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
 * quickchr's `add`, which refuses an existing name (test/chr/quickchr.ts,
 * shared with the integration tier). Only owned machines are configured or
 * removed. They are removed when the run ends, fails, or gets
 * SIGINT or SIGTERM (after the work in flight stops), and removal is
 * verified; a machine that could not be removed is named on stderr and the
 * exit code is non-zero. A second signal exits at once, naming what is left.
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
import { createHash } from "node:crypto";
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
import {
	accelerator,
	childEnv,
	cleanupAll,
	create,
	leftOver,
	owned,
	ROOT,
	run,
	services,
	start,
	stop,
	tempDirs,
	teardown,
	version,
} from "../../chr/quickchr.ts";
import {
	GATEWAY,
	GUEST,
	PEER,
	Router,
	SETTLE,
	type Step,
	StepError,
	snifferStream,
} from "../../chr/router.ts";

const EVIDENCE = join(import.meta.dir, "evidence");
const FAILED = join(ROOT, ".scratch", "tzsp-lab");
/** `sniff-id` used for the mangle experiments: 0x1234, easy to spot in hex. */
export const SNIFF_ID = 4660;
/** How long to wait after a step for late datagrams before the next label. */
const DRAIN_MS = 1500;
/** Datagrams kept per experiment; the rest are counted (`Experiment.summary`). */
const KEEP = 8;

/** A file copy of under 1 KiB gets a minute. */
const SCP_MS = 60_000;

type Target = { channel: "stable" | "long-term"; arch: "x86" | "arm64" };

export interface Datagram {
	/** ms since the experiment started, host arrival time */
	t: number;
	length: number;
	hex: string;
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
	let o = 0;
	for (; o + 12 <= b.length; ) {
		const type = b.readUInt32LE(o);
		const len = b.readUInt32LE(o + 4);
		if (len < 12 || len % 4 !== 0 || o + len > b.length)
			throw new Error("bad block length");
		if (b.readUInt32LE(o + len - 4) !== len)
			throw new Error("trailing block length differs");
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
			if (28 + Math.ceil(captured / 4) * 4 > len - 4)
				throw new Error("packet data past its block");
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
	if (o !== b.length) throw new Error("bytes after the last block");
	return out;
}

/**
 * The saved file is what the evidence claims: Ethernet interfaces named for
 * an ether port and direction, nanosecond timestamps, and only this lab's
 * pings, whole (captured = original) and in time order.
 */
export function checkPcapng(file: Pcapng): string | undefined {
	for (const i of file.interfaces) {
		if (!/^ether\d+ (rx|tx)$/.test(i.name)) return `interface ${i.name}`;
		if (i.linkType !== 1) return `link type ${i.linkType}, not Ethernet`;
		if (i.tsresol !== 9) return `if_tsresol ${i.tsresol}, not nanoseconds`;
	}
	let last = 0n;
	for (const p of file.packets) {
		const iface = file.interfaces[p.iface];
		if (!iface) return `a packet on interface ${p.iface}, which is not defined`;
		if (p.captured !== p.original || p.captured > iface.snapLen)
			return "a packet that was cut short";
		if (p.ts === 0n || p.ts < last) return "a timestamp out of order";
		last = p.ts;
		if (!/^cpu:\d+ fp:\d+$/.test(p.comment)) return "a packet comment";
		if (!isLabIcmpFrame(p.data)) return "a packet that is not the lab's ICMP";
	}
	return file.packets.length === 0 ? "no packets" : undefined;
}

/* -------------------------------------------------------------- signals */

/**
 * A signal stops work (`stop`); the main task then removes machines and
 * exits, so removal never races a step still using a machine. `experiment`
 * checks between steps. A second signal exits at once and names what is left.
 */
let interrupted: "SIGINT" | "SIGTERM" | undefined;
function onSignal(signal: "SIGINT" | "SIGTERM"): void {
	if (interrupted) {
		for (const n of owned.keys()) console.error(`NOT REMOVED: ${n}`);
		process.exit(signal === "SIGINT" ? 130 : 143);
	}
	interrupted = signal;
	console.error(`${signal}: stopping, then removing this run's machines`);
	stop();
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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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
		if (interrupted) throw new StepError(`${name}: ${interrupted}`);
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

const mangleState = [
	"/ip/firewall/mangle/print stats where comment=tzsp-lab",
	"/ip/firewall/mangle/print detail where comment=tzsp-lab",
];
const mangleClean = "/ip/firewall/mangle/remove [find comment=tzsp-lab]";

async function experiments(c: Ctx, full: boolean): Promise<void> {
	const P = c.listener.port;
	const sniff = (extra = "") =>
		`action=sniff-tzsp sniff-target=${GATEWAY} sniff-target-port=${P} comment=tzsp-lab${extra ? ` ${extra}` : ""}`;

	const stream = await experiment(c, "sniffer-stream", [
		snifferStream(P),
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
		snifferStream(P),
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
			SETTLE,
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
		SETTLE,
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
		SETTLE,
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
			SETTLE,
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
		SETTLE,
		snifferStream(P),
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
		snifferStream(P),
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
	const { sshPort: ssh, auth } = await services(machine);
	if (!ssh || !auth)
		throw new StepError("no SSH port or login in quickchr's descriptor");
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

async function lab(target: Target): Promise<boolean> {
	const ev: Evidence = {
		target,
		machine: "",
		date: new Date().toISOString(),
		accelerator: "",
		quickchr: await version(),
		experiments: [],
	};
	const listener = new Listener();
	const ctx: Partial<Ctx> = {};
	let ok = false;
	try {
		ev.machine = await create(`tzsp-lab-${target.channel}-${target.arch}`, {
			routeros: target.channel,
			arch: target.arch,
		});
		ev.listenerPort = await listener.open();
		ev.bootMs = await start(ev.machine);
		ev.accelerator = accelerator(ev.machine);
		const rest = await services(ev.machine);
		const router = new Router(rest.restUrl, rest.basic);
		ev.router = await router.identity();
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
			console.error(leftOver(ev.machine));
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
	for (const n of left) console.error(leftOver(n));
	const failed = results.some(
		(r) => r.status === "rejected" || r.value.includes(false),
	);
	if (interrupted) process.exit(interrupted === "SIGINT" ? 130 : 143);
	process.exit(failed || left.length > 0 ? 1 : 0);
}
