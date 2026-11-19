/**
 * Lab: ground RouterOS's two TZSP senders (`/tool/sniffer` streaming and mangle
 * `action=sniff-tzsp`) on CHRs booted by quickchr (issue #5). Not a test tier:
 * run by hand, never a gate. REPORT.md says what it showed.
 *
 *   bun test/lab/tzsp-senders/lab.ts                 # x86 stable, x86 long-term, arm64 stable
 *   bun test/lab/tzsp-senders/lab.ts --only x86:stable,x86:long-term
 *
 * Safety. Each router is a machine this run creates and owns: the name is
 * `tzsp-lab-<channel>-<arch>-<random>`, checked absent, then created with
 * `quickchr add`, which refuses an existing name. Only owned machines are
 * configured or removed. They are removed when the run ends, fails, or gets
 * SIGINT or SIGTERM, and removal is verified; a machine that could not be
 * removed is named on stderr and the exit code is non-zero.
 *
 * Capture. One UDP listener per router on 127.0.0.1, port 0 (the kernel picks
 * a free port). The guest sends to the SLIRP gateway 10.0.2.2:<port>, which
 * QEMU delivers to that loopback port. Experiments run one after another;
 * each datagram is filed under the experiment running when it arrived. Only
 * datagrams that are this lab's own traffic are kept (`classify`); others
 * are counted, never stored.
 *
 * Output. Every step must succeed and every experiment's control traffic
 * must be seen (`expect`) before anything is written to evidence/:
 * <version>-<arch>.json and, for the saved-file experiment,
 * <version>-<arch>-sniffer-file.pcapng (its SHA-256 is in the JSON). A run
 * that fails writes its partial evidence to .scratch/tzsp-lab/ instead.
 * `fixtures.ts` turns evidence/ into test/fixtures/routeros/.
 */
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createSocket } from "node:dgram";
import {
	chmod,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..", "..");
const EVIDENCE = join(import.meta.dir, "evidence");
const FAILED = join(ROOT, ".scratch", "tzsp-lab");
/** Where pings go: SLIRP's DNS address, which answers ICMP echo. */
const PEER = "10.0.2.3";
/** The CHR's address on its SLIRP NIC. */
const GUEST = "10.0.2.15";
const GATEWAY = "10.0.2.2";
/** `sniff-id` used for the mangle experiments: 0x1234, easy to spot in hex. */
export const SNIFF_ID = 4660;
/** How long to wait after a step for late datagrams before the next label. */
const DRAIN_MS = 1500;
/** Datagrams kept per experiment; the rest are counted (`Experiment.summary`). */
const KEEP = 8;

/**
 * Deadlines. `quickchr start` keeps quickchr's own boot budget (its
 * BOOT_TIMEOUT), so the lab adds none. A RouterOS command answers in
 * milliseconds on KVM and seconds under TCG; its budget is a base for that
 * plus the time the command itself waits (`commandBudget`). Teardown waits
 * for quickchr, which itself waits for a `start` of the same machine still
 * in progress. A file copy of under 1 KiB gets a minute.
 */
const REST_BASE_MS = 20_000;
const TEARDOWN_MS = 180_000;
const SCP_MS = 60_000;
const QUICKCHR_MS = 30_000;

type Target = { channel: "stable" | "long-term"; arch: "x86" | "arm64" };

export interface Datagram {
	/** ms since the experiment started, host arrival time */
	t: number;
	length: number;
	hex: string;
}

interface Step {
	command: string;
	status: number;
	output: string;
}

export interface Summary {
	/** Every datagram that arrived during the experiment, lab traffic or not. */
	datagrams: number;
	/** Of those, how many began `01 00 00 01 01` (v1, received, Ethernet, end tag). */
	tzspHeaderNoTags: number;
	/** Datagrams not this lab's traffic: counted, not stored. */
	dropped: number;
	maxLength: number;
	/** TZSP-in-UDP-to-the-listener layers in the deepest datagram (`nesting`). */
	maxNesting: number;
	lengths: Record<string, number>;
	/** Lab datagrams carrying the ping directly (not nested), by ICMP type: 8 request, 0 reply. */
	icmp: Record<string, number>;
	/** Why datagrams were dropped: the innermost frame's kind (`innermost`), never its bytes. */
	droppedKinds: Record<string, number>;
}

export interface Experiment {
	name: string;
	steps: Step[];
	/** The first KEEP lab datagrams, plus the deepest one if it came later. */
	datagrams: Datagram[];
	summary: Summary;
	/** Router state read by REST during the experiment. */
	state?: Record<string, unknown>;
	notes?: string[];
}

export interface Evidence {
	target: Target;
	machine: string;
	/** ISO 8601, UTC. */
	date: string;
	accelerator: string;
	quickchr: string;
	router?: Record<string, string>;
	snifferDefaults?: Record<string, string>;
	listenerPort?: number;
	bootMs?: number;
	pcapng?: { file: string; sha256: string; bytes: number };
	experiments: Experiment[];
	/** Only in a failed run's scratch copy. */
	failure?: string;
}

/* ------------------------------------------------------------------ bytes */

const u16 = (b: Uint8Array, at: number) =>
	((b[at] ?? 0) << 8) | (b[at + 1] ?? 0);
const ip4 = (b: Uint8Array, at: number) =>
	Array.from(b.subarray(at, at + 4)).join(".");
const hexOf = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** An IPv4 packet holding ICMP between the guest and PEER. */
function isLabIcmpPacket(ip: Uint8Array): boolean {
	if (ip.length < 20 || (ip[0] ?? 0) >> 4 !== 4 || ip[9] !== 1) return false;
	const pair = [ip4(ip, 12), ip4(ip, 16)].sort().join(" ");
	return pair === [GUEST, PEER].sort().join(" ");
}

/** An Ethernet frame holding such a packet. */
function isLabIcmpFrame(eth: Uint8Array): boolean {
	return (
		eth.length >= 14 + 20 &&
		u16(eth, 12) === 0x0800 &&
		isLabIcmpPacket(eth.subarray(14))
	);
}

/**
 * TZSP layers, each inside Ethernet, IPv4 and UDP to `port`, before an
 * ordinary frame: 0 for a datagram that carries one directly.
 */
export function nesting(bytes: Uint8Array, port: number): number {
	let cur = bytes;
	let depth = 0;
	for (;;) {
		if (cur.length < 5 + 14 + 20 + 8) return depth;
		if (hexOf(cur.subarray(0, 5)) !== "0100000101") return depth;
		const eth = cur.subarray(5);
		if (u16(eth, 12) !== 0x0800) return depth;
		const ip = eth.subarray(14);
		if (ip[9] !== 17) return depth;
		const udp = ip.subarray(((ip[0] ?? 0) & 0x0f) * 4);
		if (u16(udp, 2) !== port) return depth;
		cur = udp.subarray(8);
		depth += 1;
	}
}

/**
 * Is this datagram the lab's own traffic? A TZSP datagram (v1, received,
 * Ethernet, no tags) whose innermost frame, after any TZSP-in-UDP-to-`port`
 * layers, is ICMP between the guest and PEER; or a `sniff-pc` datagram (the
 * id, 8 bytes, then that IPv4 packet). Nothing else is stored.
 */
export function classify(
	bytes: Uint8Array,
	port: number,
): "tzsp" | "sniff-pc" | "other" {
	const id = Buffer.alloc(4);
	id.writeUInt32BE(SNIFF_ID);
	if (
		hexOf(bytes.subarray(0, 4)) === id.toString("hex") &&
		isLabIcmpPacket(bytes.subarray(12))
	)
		return "sniff-pc";
	let cur = bytes;
	for (let i = nesting(bytes, port); i > 0; i--) {
		const ip = cur.subarray(5 + 14);
		cur = ip.subarray(((ip[0] ?? 0) & 0x0f) * 4 + 8);
	}
	if (hexOf(cur.subarray(0, 5)) !== "0100000101") return "other";
	return isLabIcmpFrame(cur.subarray(5)) ? "tzsp" : "other";
}

/**
 * What the innermost frame of a datagram is, after any TZSP-in-UDP-to-`port`
 * layers: "ipv4 proto 17 fragment", "ipv4 proto 1", "ethertype 86dd",
 * "not tzsp". A label only, for counting dropped datagrams.
 */
export function innermost(bytes: Uint8Array, port: number): string {
	let cur = bytes;
	for (let i = nesting(bytes, port); i > 0; i--) {
		const ip = cur.subarray(5 + 14);
		cur = ip.subarray(((ip[0] ?? 0) & 0x0f) * 4 + 8);
	}
	if (hexOf(cur.subarray(0, 5)) !== "0100000101") return "not tzsp";
	const eth = cur.subarray(5);
	if (eth.length < 14) return "short frame";
	const type = u16(eth, 12);
	if (type !== 0x0800) return `ethertype ${type.toString(16).padStart(4, "0")}`;
	const ip = eth.subarray(14);
	const fragment = (u16(ip, 6) & 0x3fff) !== 0;
	return `ipv4 proto ${ip[9]}${fragment ? " fragment" : ""}`;
}

/** ICMP type in a TZSP datagram's frame (8 request, 0 reply), or undefined if not ICMP. */
export function icmpType(bytes: Uint8Array): number | undefined {
	const ip = bytes.subarray(5 + 14);
	if (ip[9] !== 1) return undefined;
	return ip[((ip[0] ?? 0) & 0x0f) * 4];
}

export interface Pcapng {
	interfaces: {
		linkType: number;
		snapLen: number;
		name: string;
		tsresol: number;
	}[];
	packets: {
		iface: number;
		ts: bigint;
		captured: number;
		original: number;
		comment: string;
		data: Uint8Array;
	}[];
}

/** Read a little-endian pcapng file; throws on any block or option the lab does not expect. */
export function readPcapng(b: Buffer): Pcapng {
	const out: Pcapng = { interfaces: [], packets: [] };
	if (b.readUInt32LE(0) !== 0x0a0d0d0a || b.readUInt32LE(8) !== 0x1a2b3c4d)
		throw new Error("not a little-endian pcapng section");
	const options = (from: number, to: number) => {
		const found: Record<number, Buffer> = {};
		for (let p = from; p + 4 <= to; ) {
			const code = b.readUInt16LE(p);
			const len = b.readUInt16LE(p + 2);
			if (code === 0) break;
			found[code] = b.subarray(p + 4, p + 4 + len);
			p += 4 + Math.ceil(len / 4) * 4;
		}
		return found;
	};
	for (let o = 0; o + 12 <= b.length; ) {
		const type = b.readUInt32LE(o);
		const len = b.readUInt32LE(o + 4);
		if (len < 12 || o + len > b.length) throw new Error("bad block length");
		if (type === 0x0a0d0d0a) {
			if (Object.keys(options(o + 24, o + len - 4)).length > 0)
				throw new Error("section header has options");
		} else if (type === 1) {
			const opt = options(o + 16, o + len - 4);
			const codes = Object.keys(opt).sort().join(",");
			if (codes !== "2,9") throw new Error(`interface options ${codes}`);
			out.interfaces.push({
				linkType: b.readUInt16LE(o + 8),
				snapLen: b.readUInt32LE(o + 12),
				name: opt[2]?.toString("utf8") ?? "",
				tsresol: opt[9]?.[0] ?? -1,
			});
		} else if (type === 6) {
			const captured = b.readUInt32LE(o + 20);
			const opt = options(o + 28 + Math.ceil(captured / 4) * 4, o + len - 4);
			if (Object.keys(opt).join(",") !== "1")
				throw new Error("packet options other than one comment");
			out.packets.push({
				iface: b.readUInt32LE(o + 8),
				ts:
					(BigInt(b.readUInt32LE(o + 12)) << 32n) |
					BigInt(b.readUInt32LE(o + 16)),
				captured,
				original: b.readUInt32LE(o + 24),
				comment: opt[1]?.toString("utf8") ?? "",
				data: b.subarray(o + 28, o + 28 + captured),
			});
		} else {
			throw new Error(`unexpected block type ${type}`);
		}
		o += len;
	}
	return out;
}

/** The saved file holds only this lab's pings, and names only ether interfaces. */
function checkPcapng(file: Pcapng): string | undefined {
	for (const i of file.interfaces)
		if (!/^ether\d+ (rx|tx)$/.test(i.name)) return `interface ${i.name}`;
	for (const p of file.packets) {
		if (!/^cpu:\d+ fp:\d+$/.test(p.comment)) return "a packet comment";
		if (!isLabIcmpFrame(p.data)) return "a packet that is not the lab's ICMP";
	}
	return file.packets.length === 0 ? "no packets" : undefined;
}

/* ------------------------------------------------------------ processes */

/** Child processes get an allowlisted env, never a copy of process.env (tikoci-testing). */
function childEnv(extra: Record<string, string> = {}): Record<string, string> {
	const env: Record<string, string> = {};
	for (const [key, value] of Object.entries(process.env)) {
		if (value === undefined) continue;
		if (
			["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG"].includes(key) ||
			key.startsWith("XDG_") ||
			key.startsWith("QUICKCHR_")
		)
			env[key] = value;
	}
	return { ...env, QUICKCHR_NO_TIPS: "1", ...extra };
}

interface Ran {
	code: number;
	stdout: string;
	stderr: string;
	timedOut: boolean;
}

/** Run a child; past `timeoutMs` it is killed. No deadline when undefined. */
function run(
	argv: string[],
	opts: { env?: Record<string, string>; timeoutMs?: number } = {},
): Promise<Ran> {
	return new Promise((resolve) => {
		const [cmd, ...args] = argv as [string, ...string[]];
		const child = spawn(cmd, args, {
			env: opts.env ?? childEnv(),
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		const timer =
			opts.timeoutMs === undefined
				? undefined
				: setTimeout(() => {
						timedOut = true;
						child.kill("SIGKILL");
					}, opts.timeoutMs);
		child.stdout.on("data", (b: Buffer) => {
			stdout += b.toString();
		});
		child.stderr.on("data", (b: Buffer) => {
			stderr += b.toString();
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			resolve({ code: code ?? -1, stdout, stderr, timedOut });
		});
		child.on("error", (e) => {
			clearTimeout(timer);
			resolve({ code: -1, stdout, stderr: String(e), timedOut });
		});
	});
}

/* ------------------------------------------------- ownership and cleanup */

/** Machines this run created, by name. Nothing else is configured or removed. */
const owned = new Set<string>();
/** Temporary directories to remove on exit (the askpass helper's). */
const tempDirs = new Set<string>();
const removals = new Map<string, Promise<boolean>>();
/** `create` calls still running, so cleanup waits for a machine mid-`add`. */
const provisioning = new Set<Promise<unknown>>();

/** Remove one owned machine and confirm `quickchr list` no longer knows it. */
function teardown(name: string): Promise<boolean> {
	const pending = removals.get(name);
	if (pending) return pending;
	const p = (async () => {
		await run(["quickchr", "remove", name], { timeoutMs: TEARDOWN_MS });
		const left = await run(["quickchr", "list", name, "--json"], {
			timeoutMs: QUICKCHR_MS,
		});
		const gone = left.code !== 0 && /not found/.test(left.stdout + left.stderr);
		if (gone) owned.delete(name);
		return gone;
	})();
	removals.set(name, p);
	return p;
}

/** Remove every owned machine and temp dir; return the machines still present. */
async function cleanupAll(): Promise<string[]> {
	// A machine whose `add` is still running joins `owned` when it settles;
	// each `run` has a deadline, so this wait is bounded.
	await Promise.allSettled([...provisioning]);
	const names = [...owned];
	const results = await Promise.all(names.map((n) => teardown(n)));
	for (const dir of tempDirs) {
		await rm(dir, { recursive: true, force: true });
		tempDirs.delete(dir);
	}
	return names.filter((_, i) => !results[i]);
}

let interrupted = false;
function onSignal(signal: "SIGINT" | "SIGTERM"): void {
	if (interrupted) return;
	interrupted = true;
	console.error(`${signal}: removing this run's machines`);
	void cleanupAll().then((left) => {
		for (const n of left) console.error(`NOT REMOVED: ${n}`);
		process.exit(signal === "SIGINT" ? 130 : 143);
	});
}

/* ------------------------------------------------------------- listener */

interface Bucket {
	origin: number;
	kept: Datagram[];
	deepest?: Datagram & { depth: number };
	summary: Summary;
}

class Listener {
	private readonly socket = createSocket("udp4");
	private bucket: Bucket | undefined;
	port = 0;
	constructor() {
		this.socket.on("message", (msg) => this.file(msg));
	}
	private file(msg: Buffer): void {
		const b = this.bucket;
		if (!b) return;
		const s = b.summary;
		s.datagrams += 1;
		s.lengths[msg.length] = (s.lengths[msg.length] ?? 0) + 1;
		s.maxLength = Math.max(s.maxLength, msg.length);
		if (msg.subarray(0, 5).toString("hex") === "0100000101")
			s.tzspHeaderNoTags += 1;
		if (classify(msg, this.port) === "other") {
			s.dropped += 1;
			const kind = innermost(msg, this.port);
			s.droppedKinds[kind] = (s.droppedKinds[kind] ?? 0) + 1;
			return;
		}
		const depth = nesting(msg, this.port);
		const type = depth === 0 ? icmpType(msg) : undefined;
		if (type !== undefined) s.icmp[type] = (s.icmp[type] ?? 0) + 1;
		s.maxNesting = Math.max(s.maxNesting, depth);
		const d = {
			t: Date.now() - b.origin,
			length: msg.length,
			hex: msg.toString("hex"),
		};
		if (b.kept.length < KEEP) b.kept.push(d);
		else if (
			depth >
			Math.max(
				b.deepest?.depth ?? 0,
				...b.kept.map((k) => nesting(Buffer.from(k.hex, "hex"), this.port)),
			)
		)
			b.deepest = { ...d, depth };
	}
	/** Start filing datagrams under a new experiment. */
	begin(): Bucket {
		this.bucket = {
			origin: Date.now(),
			kept: [],
			summary: {
				datagrams: 0,
				tzspHeaderNoTags: 0,
				dropped: 0,
				maxLength: 0,
				maxNesting: 0,
				lengths: {},
				icmp: {},
				droppedKinds: {},
			},
		};
		return this.bucket;
	}
	/** Datagrams the current experiment has seen so far. */
	count(): number {
		return this.bucket?.summary.datagrams ?? 0;
	}
	open(): Promise<number> {
		return new Promise((resolve, reject) => {
			this.socket.once("error", reject);
			this.socket.bind(0, "127.0.0.1", () => {
				this.port = this.socket.address().port;
				resolve(this.port);
			});
		});
	}
	close(): void {
		this.bucket = undefined;
		this.socket.close();
	}
}

/* --------------------------------------------------------------- router */

/**
 * RouterOS reports a failed command in the text, with HTTP 200, ending in
 * its position: "bad parameter bogus (line 1 column 26)", "no such item
 * (/file/get; line 1)" (7.25.1 x86 CHR, by hand, 2026-11-19 UTC).
 */
const ROUTEROS_ERROR = /\((?:[^()]*; )?line \d+(?: column \d+)?\)$/;

/** How long a command may take: a base, plus what it waits for itself. */
function commandBudget(command: string): number {
	let ms = REST_BASE_MS;
	const count = /\/ping .*count=(\d+)/.exec(command)?.[1];
	if (count) ms += Number(count) * 1000;
	for (const m of command.matchAll(/:delay (\d+)s/g)) ms += Number(m[1]) * 1000;
	return ms;
}

class StepError extends Error {}

class Router {
	readonly url: string;
	private readonly auth: string;
	constructor(url: string, auth: string) {
		this.url = url;
		this.auth = auth;
	}
	private async rest(
		path: string,
		init: { method?: string; body?: unknown; timeoutMs?: number } = {},
	): Promise<{ status: number; body: unknown }> {
		try {
			const res = await fetch(`${this.url}${path}`, {
				method: init.method ?? "GET",
				headers: {
					authorization: `Basic ${btoa(this.auth)}`,
					"content-type": "application/json",
				},
				...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
				signal: AbortSignal.timeout(init.timeoutMs ?? REST_BASE_MS),
			});
			const text = await res.text();
			let body: unknown = text;
			try {
				body = JSON.parse(text);
			} catch {}
			return { status: res.status, body };
		} catch {
			return { status: 0, body: undefined };
		}
	}
	/** A GET that must succeed; returns the parsed body. */
	async read(path: string): Promise<unknown> {
		const r = await this.rest(path);
		if (r.status !== 200)
			throw new StepError(`GET ${path}: status ${r.status}`);
		return r.body;
	}
	/** Run one RouterOS CLI command; a timeout, a non-200 or a RouterOS error fails it. */
	async exec(command: string): Promise<Step> {
		const { status, body } = await this.rest("/execute", {
			method: "POST",
			body: { script: command, "as-string": true },
			timeoutMs: commandBudget(command),
		});
		const output =
			typeof body === "object" && body !== null && "ret" in body
				? String((body as { ret: unknown }).ret)
				: "";
		const step = {
			command,
			status,
			output: withoutComments(output.replaceAll("\r\n", "\n")),
		};
		if (status !== 200 || ROUTEROS_ERROR.test(step.output.trim()))
			throw Object.assign(new StepError(`step failed: ${command}`), { step });
		return step;
	}
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Drop export header comments: they carry the CHR's software id. */
const withoutComments = (s: string) =>
	s
		.split("\n")
		.filter((l) => !l.startsWith("#"))
		.join("\n");

/* ---------------------------------------------------------- experiments */

interface Ctx {
	ev: Evidence;
	router: Router;
	listener: Listener;
	machine: string;
	pcap?: Buffer;
}

type Action = string | ((exp: Experiment) => Promise<void>);

/** Run an experiment's commands and checks, drain, and record what arrived. */
async function experiment(
	c: Ctx,
	name: string,
	actions: Action[],
	drainMs = DRAIN_MS,
): Promise<Experiment> {
	const bucket = c.listener.begin();
	const exp: Experiment = {
		name,
		steps: [],
		datagrams: bucket.kept,
		summary: bucket.summary,
	};
	c.ev.experiments.push(exp);
	for (const action of actions) {
		if (typeof action !== "string") {
			await action(exp);
			continue;
		}
		try {
			exp.steps.push(await c.router.exec(action));
		} catch (e) {
			const step = (e as { step?: Step }).step;
			if (step) exp.steps.push(step);
			throw e;
		}
	}
	await sleep(drainMs);
	if (bucket.deepest) {
		const { depth: _, ...d } = bucket.deepest;
		exp.datagrams.push(d);
	}
	return exp;
}

/** Fail the run unless `ok`: the experiment's control traffic or state was not seen. */
function expect(exp: Experiment, ok: boolean, what: string): void {
	if (!ok) throw new StepError(`${exp.name}: expected ${what}`);
}

const icmpCount = (exp: Experiment, type: number) =>
	exp.summary.icmp[type] ?? 0;

const firstCounter = (exp: Experiment) =>
	(exp.state?.counters as number[] | undefined)?.[0];

/** Record the packet counter of each `tzsp-lab` mangle rule, in rule order. */
const readCounters =
	(c: Ctx): Action =>
	async (exp) => {
		const rules = (await c.router.read(
			"/ip/firewall/mangle?comment=tzsp-lab",
		)) as { packets?: string }[];
		exp.state = {
			...exp.state,
			counters: rules.map((r) => Number(r.packets ?? Number.NaN)),
		};
	};

/** Record the rule as REST stores it. */
const readRule =
	(c: Ctx): Action =>
	async (exp) => {
		exp.state = {
			...exp.state,
			restRecord: await c.router.read("/ip/firewall/mangle?comment=tzsp-lab"),
		};
	};

/** Fail unless the sniffer reports running; recorded in the experiment. */
const sniffing =
	(c: Ctx): Action =>
	async (exp) => {
		const s = (await c.router.read("/tool/sniffer")) as { running?: string };
		exp.state = { ...exp.state, snifferRunningAfterStart: s.running };
		if (s.running !== "true")
			throw new StepError(`${exp.name}: sniffer did not start`);
	};

/** The sniffer settings the ICMP streaming experiments start from. */
const snifferBase = (port: number) =>
	`/tool/sniffer/set streaming-enabled=yes streaming-server=${GATEWAY}:${port} ` +
	`filter-ip-address=${PEER}/32 filter-ip-protocol=icmp filter-operator-between-entries=and ` +
	`filter-stream=yes only-headers=no file-name=""`;

const mangleState = [
	"/ip/firewall/mangle/print stats where comment=tzsp-lab",
	"/ip/firewall/mangle/print detail where comment=tzsp-lab",
];
const mangleClean = "/ip/firewall/mangle/remove [find comment=tzsp-lab]";
/** A precaution after adding a rule over REST, so the ping meets a rule in effect. */
const settle = ":delay 2s";

async function experiments(c: Ctx, full: boolean): Promise<void> {
	const P = c.listener.port;
	const sniff = (extra = "") =>
		`action=sniff-tzsp sniff-target=${GATEWAY} sniff-target-port=${P} comment=tzsp-lab${extra ? ` ${extra}` : ""}`;

	const stream = await experiment(c, "sniffer-stream", [
		snifferBase(P),
		"/tool/sniffer/start",
		sniffing(c),
		`/ping ${PEER} count=3`,
		"/tool/sniffer/stop",
	]);
	expect(
		stream,
		icmpCount(stream, 8) === 3 && icmpCount(stream, 0) === 3,
		"3 echo requests and 3 replies",
	);
	if (!full) return;

	const headers = await experiment(c, "sniffer-only-headers", [
		snifferBase(P),
		"/tool/sniffer/set only-headers=yes",
		"/tool/sniffer/start",
		sniffing(c),
		`/ping ${PEER} count=2 size=1000`,
		"/tool/sniffer/stop",
		"/tool/sniffer/set only-headers=no",
	]);
	expect(
		headers,
		icmpCount(headers, 8) === 2 && icmpCount(headers, 0) === 2,
		"2 requests and 2 replies",
	);

	// One chain at a time. Replies from PEER for the inbound chains, requests to it for the rest.
	for (const [chain, match] of [
		["prerouting", `src-address=${PEER}`],
		["input", `src-address=${PEER}`],
		["output", `dst-address=${PEER}`],
		["postrouting", `dst-address=${PEER}`],
	] as const) {
		const exp = await experiment(c, `mangle-${chain}`, [
			`/ip/firewall/mangle/add chain=${chain} protocol=icmp ${match} ${sniff()}`,
			settle,
			`/ping ${PEER} count=2`,
			...mangleState,
			readCounters(c),
			mangleClean,
		]);
		expect(exp, firstCounter(exp) === 2, "the rule to count 2 packets");
	}

	const id = await experiment(c, "mangle-sniff-id", [
		`/ip/firewall/mangle/add chain=output protocol=icmp dst-address=${PEER} ${sniff(`sniff-id=${SNIFF_ID}`)}`,
		readRule(c),
		settle,
		`/ping ${PEER} count=2`,
		...mangleState,
		"/ip/firewall/mangle/export where comment=tzsp-lab",
		readCounters(c),
		mangleClean,
	]);
	expect(id, firstCounter(id) === 2, "the rule to count 2 packets");

	// sniff-pc is the other sniff action; it keeps sniff-id. Not TZSP (REPORT.md).
	const pc = await experiment(c, "mangle-sniff-pc", [
		`/ip/firewall/mangle/add chain=output protocol=icmp dst-address=${PEER} action=sniff-pc sniff-target=${GATEWAY} sniff-target-port=${P} sniff-id=${SNIFF_ID} comment=tzsp-lab`,
		readRule(c),
		settle,
		`/ping ${PEER} count=2`,
		...mangleState,
		readCounters(c),
		mangleClean,
	]);
	expect(pc, firstCounter(pc) === 2, "the rule to count 2 packets");

	// A second rule that matches the TZSP datagrams the first rule sends.
	for (const chain of ["output", "postrouting"]) {
		const exp = await experiment(c, `mangle-self-${chain}`, [
			`/ip/firewall/mangle/add chain=output protocol=icmp dst-address=${PEER} ${sniff()}`,
			`/ip/firewall/mangle/add chain=${chain} protocol=udp dst-address=${GATEWAY} dst-port=${P} ${sniff()}`,
			settle,
			`/ping ${PEER} count=2`,
			...mangleState,
			readCounters(c),
			mangleClean,
		]);
		expect(exp, firstCounter(exp) === 2, "the trigger rule to count 2");
		expect(exp, icmpCount(exp, 8) === 2, "the trigger's 2 echo requests");
	}

	// Does a broad mangle rule mirror the sniffer's own stream?
	const cross = await experiment(c, "mangle-mirrors-sniffer", [
		`/ip/firewall/mangle/add chain=postrouting protocol=udp dst-address=${GATEWAY} dst-port=${P} ${sniff()}`,
		settle,
		snifferBase(P),
		"/tool/sniffer/start",
		sniffing(c),
		`/ping ${PEER} count=2`,
		"/tool/sniffer/stop",
		...mangleState,
		readCounters(c),
		mangleClean,
	]);
	expect(
		cross,
		icmpCount(cross, 8) === 2 && icmpCount(cross, 0) === 2,
		"the sniffer's 2 requests and 2 replies",
	);

	const file = await experiment(c, "sniffer-file", [
		snifferBase(P),
		"/tool/sniffer/set streaming-enabled=no file-name=tzsp-lab-capture file-limit=100",
		"/tool/sniffer/start",
		sniffing(c),
		`/ping ${PEER} count=3`,
		"/tool/sniffer/stop",
		':put [/file/get [find name~"tzsp-lab"] name]',
		'/file/print proplist=name,type,size where name~"tzsp-lab"',
	]);
	const remote = file.steps[5]?.output.trim() ?? "";
	const pcap = await scpPull(c.machine, remote);
	const problem = checkPcapng(readPcapng(pcap));
	if (problem) throw new StepError(`sniffer-file: ${problem}`);
	c.pcap = pcap;
	c.ev.pcapng = {
		file: `${c.ev.router?.version}-${c.ev.target.arch}-sniffer-file.pcapng`,
		sha256: createHash("sha256").update(pcap).digest("hex"),
		bytes: pcap.length,
	};
	file.notes = [`router file "${remote}", copied over SCP`];
	file.steps.push(await c.router.exec('/file/remove [find name~"tzsp-lab"]'));
	file.steps.push(await c.router.exec('/tool/sniffer/set file-name=""'));

	// `and` between filter entries with a two-value protocol list, then the
	// same with `or` as its control.
	for (const op of ["and", "or"]) {
		const exp = await experiment(c, `sniffer-${op}-two-protocols`, [
			`/tool/sniffer/set streaming-enabled=yes streaming-server=${GATEWAY}:${P} filter-ip-address="" filter-ip-protocol=icmp,udp filter-operator-between-entries=${op} filter-stream=yes only-headers=no file-name=""`,
			"/tool/sniffer/start",
			sniffing(c),
			`/ping ${PEER} count=2`,
			"/tool/sniffer/stop",
		]);
		if (op === "or")
			expect(
				exp,
				icmpCount(exp, 8) === 2 && icmpCount(exp, 0) === 2,
				"2 requests and 2 replies",
			);
	}

	// filter-stream: yes, then no. With no, the sniffer captures its own
	// stream, so the stop is scheduled first in a background job on the
	// router (`:execute`): stopping does not depend on REST while the router
	// is busy. The host then checks the sniffer stopped and the stream ended.
	for (const fs of ["yes", "no"]) {
		const exp = await experiment(
			c,
			`sniffer-filter-stream-${fs}`,
			[
				`/tool/sniffer/set streaming-enabled=yes streaming-server=${GATEWAY}:${P} filter-ip-address="" filter-ip-protocol=icmp,udp filter-operator-between-entries=or filter-stream=${fs} only-headers=no file-name=""`,
				':execute script="{:delay 4s; /tool/sniffer/stop}"',
				"/tool/sniffer/start",
				sniffing(c),
				`/ping ${PEER} count=1`,
			],
			6000,
		);
		const s = (await c.router.read("/tool/sniffer")) as { running?: string };
		const before = c.listener.count();
		await sleep(1000);
		expect(
			exp,
			s.running === "false",
			"the background job to stop the sniffer",
		);
		expect(
			exp,
			c.listener.count() === before,
			"the stream to end after the stop",
		);
		expect(
			exp,
			icmpCount(exp, 8) === 1 && icmpCount(exp, 0) === 1,
			"the ping's request and reply",
		);
	}
}

/**
 * Copy a file off the router over SCP. The password reaches scp's askpass
 * helper only through the child's environment; the helper is a constant
 * script. `-F /dev/null` keeps the user's SSH config out.
 */
async function scpPull(machine: string, remote: string): Promise<Buffer> {
	if (!/^[\w.-]+$/.test(remote)) throw new StepError("unexpected file name");
	const inspect = await run(["quickchr", "inspect", machine, "--json"], {
		timeoutMs: QUICKCHR_MS,
	});
	const info = JSON.parse(inspect.stdout) as {
		services: Record<
			string,
			{ port?: number; auth?: { username: string; password: string } }
		>;
	};
	const ssh = info.services.ssh?.port;
	const auth = info.services["rest-api"]?.auth;
	if (!ssh || !auth)
		throw new StepError("no SSH port or login in quickchr inspect");
	const dir = await mkdtemp(join(tmpdir(), "tzsp-lab-"));
	tempDirs.add(dir);
	try {
		const askpass = join(dir, "askpass");
		await writeFile(
			askpass,
			`#!/bin/sh\nprintf '%s\\n' "$TZSP_LAB_SSH_PASSWORD"\n`,
		);
		await chmod(askpass, 0o700);
		const local = join(dir, "capture");
		const r = await run(
			[
				"scp",
				"-F",
				"/dev/null",
				"-P",
				String(ssh),
				"-o",
				"StrictHostKeyChecking=no",
				"-o",
				"UserKnownHostsFile=/dev/null",
				"-o",
				"GlobalKnownHostsFile=/dev/null",
				"-o",
				"PubkeyAuthentication=no",
				"-o",
				"PreferredAuthentications=password,keyboard-interactive",
				"-o",
				"NumberOfPasswordPrompts=1",
				"-o",
				"ConnectTimeout=10",
				`${auth.username}@127.0.0.1:${remote}`,
				local,
			],
			{
				env: childEnv({
					SSH_ASKPASS: askpass,
					SSH_ASKPASS_REQUIRE: "force",
					TZSP_LAB_SSH_PASSWORD: auth.password,
				}),
				timeoutMs: SCP_MS,
			},
		);
		if (r.code !== 0)
			throw new StepError(
				`scp ${r.timedOut ? "timed out" : `exited ${r.code}`}`,
			);
		return await readFile(local);
	} finally {
		await rm(dir, { recursive: true, force: true });
		tempDirs.delete(dir);
	}
}

/** The `-accel` QEMU was started with, read from its command line (Linux /proc). */
async function accelerator(machine: string): Promise<string> {
	const listed = await run(["quickchr", "list", machine, "--json"], {
		timeoutMs: QUICKCHR_MS,
	});
	try {
		const { pid } = JSON.parse(listed.stdout) as { pid?: number };
		const argv = (await readFile(`/proc/${pid}/cmdline`, "utf8")).split("\0");
		const i = argv.indexOf("-accel");
		return i >= 0 ? (argv[i + 1] ?? "unknown") : "unknown";
	} catch {
		return "unknown";
	}
}

/** Create a machine this run owns, or throw having touched nothing. */
function create(target: Target): Promise<string> {
	const p = provision(target);
	provisioning.add(p);
	p.finally(() => provisioning.delete(p)).catch(() => {});
	return p;
}

async function provision(target: Target): Promise<string> {
	if (interrupted) throw new Error("interrupted; not creating a machine");
	const name = `tzsp-lab-${target.channel}-${target.arch}-${randomBytes(4).toString("hex")}`;
	const exists = await run(["quickchr", "list", name, "--json"], {
		timeoutMs: QUICKCHR_MS,
	});
	if (exists.code === 0)
		throw new Error(`${name} already exists; not touching it`);
	if (interrupted) throw new Error("interrupted; not creating a machine");
	// Owned from here: the name was absent and is random, and `add` refuses
	// an existing name, so what `add` leaves behind is this run's.
	owned.add(name);
	const added = await run(
		[
			"quickchr",
			"add",
			"--name",
			name,
			"--channel",
			target.channel,
			"--arch",
			target.arch,
		],
		{ timeoutMs: QUICKCHR_MS },
	);
	if (added.code !== 0) {
		if (/MACHINE_EXISTS/.test(added.stdout + added.stderr)) owned.delete(name);
		throw new Error(`quickchr add ${name} exited ${added.code}`);
	}
	return name;
}

async function lab(target: Target): Promise<boolean> {
	const version = await run(["quickchr", "--version"], {
		timeoutMs: QUICKCHR_MS,
	});
	const ev: Evidence = {
		target,
		machine: "",
		date: new Date().toISOString(),
		accelerator: "",
		quickchr: version.stdout.split("\n")[0]?.trim() ?? "",
		experiments: [],
	};
	const listener = new Listener();
	const ctx: Partial<Ctx> = {};
	let ok = false;
	try {
		ev.machine = await create(target);
		ev.listenerPort = await listener.open();
		const t0 = Date.now();
		const started = await run(["quickchr", "start", ev.machine]);
		ev.bootMs = Date.now() - t0;
		if (started.code !== 0)
			throw new Error(`quickchr start exited ${started.code}`);
		ev.accelerator = await accelerator(ev.machine);
		const inspect = await run(["quickchr", "inspect", ev.machine, "--json"], {
			timeoutMs: QUICKCHR_MS,
		});
		const rest = (
			JSON.parse(inspect.stdout) as {
				services: Record<string, { url: string; auth: { basic: string } }>;
			}
		).services["rest-api"];
		if (!rest) throw new Error("quickchr inspect has no rest-api service");
		const router = new Router(rest.url, rest.auth.basic);
		const res = (await router.read("/system/resource")) as Record<
			string,
			string
		>;
		ev.router = {
			// "7.24.6 (long-term)": the number, then the channel the router names.
			version: (res.version ?? "").split(" ")[0] ?? "",
			versionString: res.version ?? "",
			architecture: res["architecture-name"] ?? "",
			board: res["board-name"] ?? "",
		};
		ev.snifferDefaults = (await router.read("/tool/sniffer")) as Record<
			string,
			string
		>;
		Object.assign(ctx, { ev, router, listener, machine: ev.machine });
		await experiments(ctx as Ctx, target.arch === "x86");
		ok = true;
	} catch (e) {
		ev.failure = e instanceof Error ? e.message : String(e);
	} finally {
		try {
			listener.close();
		} catch {}
		if (ev.machine && owned.has(ev.machine) && !(await teardown(ev.machine)))
			console.error(`NOT REMOVED: ${ev.machine}`);
	}
	const stem = `${ev.router?.version || target.channel}-${target.arch}`;
	const dir = ok ? EVIDENCE : FAILED;
	await mkdir(dir, { recursive: true });
	await writeFile(
		join(dir, `${stem}.json`),
		`${JSON.stringify(ev, null, "\t")}\n`,
	);
	if (ok && ctx.pcap && ev.pcapng)
		await writeFile(join(dir, ev.pcapng.file), ctx.pcap);
	console.log(
		`${ev.machine || stem}: ${ok ? "done" : `FAILED: ${ev.failure}`} -> ${join(dir, `${stem}.json`)}`,
	);
	return ok;
}

if (import.meta.main) {
	process.on("SIGINT", () => onSignal("SIGINT"));
	process.on("SIGTERM", () => onSignal("SIGTERM"));
	const only = process.argv.indexOf("--only");
	const all: Target[] = [
		{ channel: "stable", arch: "x86" },
		{ channel: "long-term", arch: "x86" },
		{ channel: "stable", arch: "arm64" },
	];
	const pick = only >= 0 ? (process.argv[only + 1] ?? "").split(",") : [];
	const targets =
		pick.length > 0
			? all.filter((t) => pick.includes(`${t.arch}:${t.channel}`))
			: all;
	if (targets.length === 0 || targets.length < pick.length) {
		console.error(
			`--only takes one or more of ${all.map((t) => `${t.arch}:${t.channel}`).join(",")}`,
		);
		process.exit(2);
	}
	// x86 machines one after another (the loop experiment loads the host);
	// the slow arm64 boot under TCG runs alongside them.
	const x86 = targets.filter((t) => t.arch === "x86");
	const arm = targets.filter((t) => t.arch === "arm64");
	const results = await Promise.allSettled([
		(async () => {
			const out: boolean[] = [];
			for (const t of x86) {
				if (interrupted) break;
				out.push(await lab(t));
			}
			return out;
		})(),
		Promise.all(arm.map((t) => lab(t))),
	]);
	const left = await cleanupAll();
	for (const n of left) console.error(`NOT REMOVED: ${n}`);
	const failed = results.some(
		(r) => r.status === "rejected" || r.value.includes(false),
	);
	process.exit(failed || left.length > 0 ? 1 : 0);
}
