/**
 * Lab: ground RouterOS's two TZSP senders (`/tool/sniffer` streaming and mangle
 * `action=sniff-tzsp`) on CHRs booted by quickchr (issue #5). Not a test tier:
 * run by hand, never a gate. REPORT.md says what it showed.
 *
 *   bun test/lab/tzsp-senders/lab.ts                 # x86 stable, x86 long-term, arm64 stable
 *   bun test/lab/tzsp-senders/lab.ts --only x86:stable,x86:long-term
 *
 * Each router gets one machine named `tzsp-lab-<channel>-<arch>-<run id>` and
 * one host UDP listener on 127.0.0.1, port 0 (the kernel picks a free one).
 * The guest sends to the SLIRP gateway 10.0.2.2:<port>, which QEMU delivers to
 * that loopback port. Experiments run one after another on that port, and each
 * datagram is labelled with the experiment running when it arrived. The
 * machine is removed in `finally`; only machines this run created are touched.
 *
 * Output: evidence/<version>-<arch>.json (every command, its output and the
 * raw datagrams) and, for the saved-file experiment,
 * evidence/<version>-<arch>-sniffer-file.pcapng. `fixtures.ts` turns them into
 * test/fixtures/routeros/.
 */
import { spawn } from "node:child_process";
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

const EVIDENCE = join(import.meta.dir, "evidence");
/** Where pings go: SLIRP's DNS address. Pings to 10.0.2.2 did not reach the sniffer (REPORT.md). */
const PEER = "10.0.2.3";
const GATEWAY = "10.0.2.2";
/** `sniff-id` used for the mangle experiments: 0x1234, easy to spot in hex. */
const SNIFF_ID = 4660;
/** How long to wait after a step for late datagrams before the next label. */
const DRAIN_MS = 1500;
/** A REST call's own budget; RouterOS answers these in well under a second on KVM. */
const REST_MS = 60_000;

type Target = { channel: "stable" | "long-term"; arch: "x86" | "arm64" };

interface Datagram {
	/** ms since the run started, host arrival time */
	t: number;
	peer: string;
	length: number;
	hex: string;
}

interface Step {
	command: string;
	status: number;
	output: string;
}

interface Experiment {
	name: string;
	steps: Step[];
	datagrams: Datagram[];
	/** For the loop experiments, only the first datagrams are kept; these summarize the rest. */
	summary?: Record<string, unknown>;
	notes?: string[];
}

interface Evidence {
	target: Target;
	machine: string;
	date: string;
	host: { os: string; accelerator: string };
	quickchr: string;
	router?: Record<string, string>;
	snifferDefaults?: Record<string, string>;
	listenerPort?: number;
	bootMs?: number;
	experiments: Experiment[];
	error?: string;
}

/** Child processes get an allowlisted env, never a copy of process.env (tikoci-testing). */
function childEnv(extra: Record<string, string> = {}): Record<string, string> {
	const env: Record<string, string> = {};
	for (const [key, value] of Object.entries(process.env)) {
		if (value === undefined) continue;
		if (
			["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "TERM"].includes(
				key,
			) ||
			key.startsWith("XDG_") ||
			key.startsWith("QUICKCHR_")
		) {
			env[key] = value;
		}
	}
	return { ...env, QUICKCHR_NO_TIPS: "1", ...extra };
}

function run(
	argv: string[],
	env = childEnv(),
): Promise<{ code: number; stdout: string; stderr: string }> {
	return new Promise((resolve) => {
		const [cmd, ...args] = argv as [string, ...string[]];
		const child = spawn(cmd, args, { env, stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (b: Buffer) => {
			stdout += b.toString();
		});
		child.stderr.on("data", (b: Buffer) => {
			stderr += b.toString();
		});
		child.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
		child.on("error", (e) => resolve({ code: -1, stdout, stderr: String(e) }));
	});
}

class Listener {
	readonly datagrams: Datagram[] = [];
	private readonly socket = createSocket("udp4");
	port = 0;
	constructor(origin: number) {
		this.socket.on("message", (msg, rinfo) => {
			this.datagrams.push({
				t: Date.now() - origin,
				peer: `${rinfo.address}:${rinfo.port}`,
				length: msg.length,
				hex: msg.toString("hex"),
			});
		});
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
		this.socket.close();
	}
}

class Router {
	readonly url: string;
	private readonly auth: string;
	constructor(url: string, auth: string) {
		this.url = url;
		this.auth = auth;
	}
	async rest(
		path: string,
		init: { method?: string; body?: unknown } = {},
	): Promise<{ status: number; body: unknown }> {
		try {
			const res = await fetch(`${this.url}${path}`, {
				method: init.method ?? "GET",
				headers: {
					authorization: `Basic ${btoa(this.auth)}`,
					"content-type": "application/json",
				},
				...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
				signal: AbortSignal.timeout(REST_MS),
			});
			const text = await res.text();
			let body: unknown = text;
			try {
				body = JSON.parse(text);
			} catch {}
			return { status: res.status, body };
		} catch (e) {
			return { status: 0, body: String(e) };
		}
	}
	/** Run one RouterOS CLI command and return what it printed. */
	async exec(command: string): Promise<Step> {
		const { status, body } = await this.rest("/execute", {
			method: "POST",
			body: { script: command, "as-string": true },
		});
		const output =
			typeof body === "object" && body !== null && "ret" in body
				? String((body as { ret: unknown }).ret)
				: typeof body === "string"
					? body
					: JSON.stringify(body);
		return { command, status, output: output.replaceAll("\r\n", "\n") };
	}
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Strip an export's header comments: they carry the CHR's software id. */
const withoutComments = (s: string) =>
	s
		.split("\n")
		.filter((l) => !l.startsWith("#"))
		.join("\n");

/**
 * How many TZSP-in-UDP-in-IPv4-in-Ethernet layers deep a datagram goes, each
 * addressed to `port`: 0 for a datagram that carries an ordinary frame.
 */
export function nesting(hex: string, port: number): number {
	let bytes = Buffer.from(hex, "hex");
	let depth = 0;
	for (;;) {
		// TZSP v1, received, Ethernet, end tag; then Ethernet with IPv4.
		if (bytes.length < 5 + 14 + 20 + 8) return depth;
		if (bytes.readUInt32BE(0) !== 0x01000001 || bytes[4] !== 1) return depth;
		const eth = bytes.subarray(5);
		if (eth.readUInt16BE(12) !== 0x0800) return depth;
		const ip = eth.subarray(14);
		const ihl = ((ip[0] ?? 0) & 0x0f) * 4;
		if (ip[9] !== 17) return depth;
		const udp = ip.subarray(ihl);
		if (udp.readUInt16BE(2) !== port) return depth;
		bytes = udp.subarray(8);
		depth += 1;
	}
}

async function experiment(
	ev: Evidence,
	router: Router,
	listener: Listener,
	name: string,
	commands: string[],
	keep = Number.POSITIVE_INFINITY,
	drainMs = DRAIN_MS,
): Promise<Experiment> {
	const from = listener.datagrams.length;
	const exp: Experiment = { name, steps: [], datagrams: [] };
	ev.experiments.push(exp);
	for (const command of commands) exp.steps.push(await router.exec(command));
	await sleep(drainMs);
	const seen = listener.datagrams.slice(from);
	exp.datagrams = seen.slice(0, keep);
	if (seen.length > keep) {
		const sizes: Record<number, number> = {};
		let maxDepth = 0;
		for (const d of seen) {
			sizes[d.length] = (sizes[d.length] ?? 0) + 1;
			maxDepth = Math.max(maxDepth, nesting(d.hex, listener.port));
		}
		exp.summary = {
			datagrams: seen.length,
			keptFirst: keep,
			spanMs: (seen.at(-1)?.t ?? 0) - (seen[0]?.t ?? 0),
			maxLength: Math.max(...seen.map((d) => d.length)),
			maxNesting: maxDepth,
			lengths: sizes,
		};
	} else if (seen.length > 0) {
		exp.summary = {
			datagrams: seen.length,
			maxNesting: Math.max(...seen.map((d) => nesting(d.hex, listener.port))),
		};
	}
	return exp;
}

/** The sniffer settings every streaming experiment starts from. */
const snifferBase = (port: number) =>
	`/tool/sniffer/set streaming-enabled=yes streaming-server=${GATEWAY}:${port} ` +
	`filter-ip-address=${PEER}/32 filter-ip-protocol=icmp filter-operator-between-entries=and ` +
	`filter-stream=yes only-headers=no file-name=""`;

/** A mangle rule's stats line and the rule as REST stores it. */
const mangleState = [
	"/ip/firewall/mangle/print stats where comment=tzsp-lab",
	"/ip/firewall/mangle/print detail where comment=tzsp-lab",
];
const mangleClean = "/ip/firewall/mangle/remove [find comment=tzsp-lab]";
/** A rule added over REST took effect only after a moment: a ping right after `add` missed it (REPORT.md). */
const settle = ":delay 2s";

async function experiments(
	ev: Evidence,
	router: Router,
	listener: Listener,
	full: boolean,
	machine: string,
): Promise<void> {
	const P = listener.port;
	/** A mangle rule's sniff-tzsp action to this run's listener. */
	const sniff = (extra = "") =>
		`action=sniff-tzsp sniff-target=${GATEWAY} sniff-target-port=${P} comment=tzsp-lab${extra ? ` ${extra}` : ""}`;

	await experiment(ev, router, listener, "sniffer-stream", [
		snifferBase(P),
		"/tool/sniffer/start",
		`/ping ${PEER} count=3`,
		"/tool/sniffer/stop",
	]);
	if (!full) return;

	await experiment(ev, router, listener, "sniffer-only-headers", [
		snifferBase(P),
		"/tool/sniffer/set only-headers=yes",
		"/tool/sniffer/start",
		`/ping ${PEER} count=2 size=1000`,
		"/tool/sniffer/stop",
		"/tool/sniffer/set only-headers=no",
	]);

	// One chain at a time. Replies from PEER for the inbound chains, requests to it for the rest.
	for (const [chain, match] of [
		["prerouting", `src-address=${PEER}`],
		["input", `src-address=${PEER}`],
		["output", `dst-address=${PEER}`],
		["postrouting", `dst-address=${PEER}`],
	] as const) {
		await experiment(ev, router, listener, `mangle-${chain}`, [
			`/ip/firewall/mangle/add chain=${chain} protocol=icmp ${match} ${sniff()}`,
			settle,
			`/ping ${PEER} count=2`,
			...mangleState,
			mangleClean,
		]);
	}

	await experiment(ev, router, listener, "mangle-sniff-id", [
		`/ip/firewall/mangle/add chain=output protocol=icmp dst-address=${PEER} ${sniff(`sniff-id=${SNIFF_ID}`)}`,
		settle,
		`/ping ${PEER} count=2`,
		...mangleState,
		"/ip/firewall/mangle/export where comment=tzsp-lab",
		mangleClean,
	]);

	// sniff-pc is the other sniff action; it keeps sniff-id. Not TZSP (REPORT.md).
	await experiment(ev, router, listener, "mangle-sniff-pc", [
		`/ip/firewall/mangle/add chain=output protocol=icmp dst-address=${PEER} action=sniff-pc sniff-target=${GATEWAY} sniff-target-port=${P} sniff-id=${SNIFF_ID} comment=tzsp-lab`,
		settle,
		`/ping ${PEER} count=2`,
		...mangleState,
		mangleClean,
	]);

	// A rule broad enough to match the TZSP datagrams the first rule sends.
	for (const chain of ["output", "postrouting"]) {
		await experiment(ev, router, listener, `mangle-self-${chain}`, [
			`/ip/firewall/mangle/add chain=output protocol=icmp dst-address=${PEER} ${sniff()}`,
			`/ip/firewall/mangle/add chain=${chain} protocol=udp dst-address=${GATEWAY} dst-port=${P} ${sniff()}`,
			settle,
			`/ping ${PEER} count=2`,
			...mangleState,
			mangleClean,
		]);
	}

	// Does a broad mangle rule mirror the sniffer's own stream?
	await experiment(ev, router, listener, "mangle-mirrors-sniffer", [
		`/ip/firewall/mangle/add chain=postrouting protocol=udp dst-address=${GATEWAY} dst-port=${P} ${sniff()}`,
		settle,
		snifferBase(P),
		"/tool/sniffer/start",
		`/ping ${PEER} count=2`,
		"/tool/sniffer/stop",
		...mangleState,
		mangleClean,
	]);

	const file = await experiment(ev, router, listener, "sniffer-file", [
		`${snifferBase(P)}`,
		"/tool/sniffer/set streaming-enabled=no file-name=tzsp-lab-capture file-limit=100",
		"/tool/sniffer/start",
		`/ping ${PEER} count=3`,
		"/tool/sniffer/stop",
		':put [/file/get [find name~"tzsp-lab"] name]',
		'/file/print proplist=name,type,size where name~"tzsp-lab"',
	]);
	const fileName = file.steps[5]?.output.trim();
	if (
		fileName &&
		!fileName.includes("failure") &&
		!fileName.includes("no such")
	) {
		const local = join(
			EVIDENCE,
			`${ev.router?.version}-${ev.target.arch}-sniffer-file.pcapng`,
		);
		const got = await scpPull(machine, fileName, local);
		file.notes = [`router file "${fileName}"`, got];
	} else {
		file.notes = [`no file found: ${fileName}`];
	}
	file.steps.push(await router.exec('/file/remove [find name~"tzsp-lab"]'));
	file.steps.push(await router.exec('/tool/sniffer/set file-name=""'));

	// `filter-operator-between-entries=and` with a two-value protocol list: the
	// first two lab runs used this for the loop experiments and got nothing.
	await experiment(ev, router, listener, "sniffer-and-two-protocols", [
		`/tool/sniffer/set streaming-enabled=yes streaming-server=${GATEWAY}:${P} filter-ip-address="" filter-ip-protocol=icmp,udp filter-operator-between-entries=and filter-stream=yes only-headers=no file-name=""`,
		"/tool/sniffer/start",
		`/ping ${PEER} count=2`,
		"/tool/sniffer/stop",
	]);

	// filter-stream: yes, then no. The no case feeds the sniffer its own stream,
	// and a REST call made during that loop did not return in the exploratory
	// run (REPORT.md). So the stop is scheduled first, in a background job on
	// the router (`:execute`), and the host waits it out.
	for (const fs of ["yes", "no"]) {
		const exp = await experiment(
			ev,
			router,
			listener,
			`sniffer-filter-stream-${fs}`,
			[
				`/tool/sniffer/set streaming-enabled=yes streaming-server=${GATEWAY}:${P} filter-ip-address="" filter-ip-protocol=icmp,udp filter-operator-between-entries=or filter-stream=${fs} only-headers=no file-name=""`,
				':execute script="{:delay 4s; /tool/sniffer/stop}"',
				"/tool/sniffer/start",
				`/ping ${PEER} count=1`,
			],
			8,
			6000,
		);
		const t0 = Date.now();
		const alive = await router.rest("/system/resource");
		exp.notes = [
			`REST /system/resource after the run: status ${alive.status} in ${Date.now() - t0} ms`,
		];
		exp.steps.push(await router.exec("/tool/sniffer/print"));
		exp.steps.push(await router.exec("/tool/sniffer/stop"));
	}
}

/** Copy a file off the router over SCP, with the password from quickchr inspect via askpass. */
async function scpPull(
	machine: string,
	remote: string,
	local: string,
): Promise<string> {
	const inspect = await run(["quickchr", "inspect", machine, "--json"]);
	const info = JSON.parse(inspect.stdout) as {
		services: Record<
			string,
			{ port: number; auth?: { username: string; password: string } }
		>;
	};
	const ssh = info.services.ssh?.port;
	const auth = info.services["rest-api"]?.auth;
	if (!ssh || !auth) return "no ssh port or credentials in quickchr inspect";
	const dir = await mkdtemp(join(tmpdir(), "tzsp-lab-"));
	try {
		const askpass = join(dir, "askpass.sh");
		await writeFile(askpass, `#!/bin/sh\nprintf '%s\\n' '${auth.password}'\n`);
		await chmod(askpass, 0o700);
		const r = await run(
			[
				"scp",
				"-P",
				String(ssh),
				"-o",
				"StrictHostKeyChecking=no",
				"-o",
				"UserKnownHostsFile=/dev/null",
				"-o",
				"PubkeyAuthentication=no",
				"-o",
				"PreferredAuthentications=password,keyboard-interactive",
				`${auth.username}@127.0.0.1:${remote}`,
				local,
			],
			childEnv({ SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: "force" }),
		);
		return r.code === 0
			? `copied to evidence/${local.split("/").at(-1)}`
			: `scp failed ${r.code}: ${r.stderr.trim()}`;
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
}

/** Format a written JSON file the way the repo's Biome gate expects. */
export async function biomeFormat(file: string): Promise<void> {
	const biome = join(
		import.meta.dir,
		"..",
		"..",
		"..",
		"node_modules",
		".bin",
		"biome",
	);
	const r = await run([biome, "format", "--write", file]);
	if (r.code !== 0) throw new Error(`biome format ${file}: ${r.stderr}`);
}

/** The `-accel` QEMU was started with, read from its command line (Linux /proc). */
async function accelerator(machine: string): Promise<string> {
	const listed = await run(["quickchr", "list", machine, "--json"]);
	try {
		const { pid } = JSON.parse(listed.stdout) as { pid?: number };
		const argv = (await readFile(`/proc/${pid}/cmdline`, "utf8")).split("\0");
		const i = argv.indexOf("-accel");
		return i >= 0 ? (argv[i + 1] ?? "unknown") : "unknown (no -accel)";
	} catch (e) {
		return `unknown (${String(e)})`;
	}
}

async function lab(target: Target, runId: string): Promise<Evidence> {
	const machine = `tzsp-lab-${target.channel}-${target.arch}-${runId}`;
	const origin = Date.now();
	const version = await run(["quickchr", "--version"]);
	const ev: Evidence = {
		target,
		machine,
		date: new Date().toISOString(),
		host: { os: `${process.platform} ${process.arch}`, accelerator: "" },
		quickchr: version.stdout.split("\n")[0]?.trim() ?? "",
		experiments: [],
	};
	const listener = new Listener(origin);
	let created = false;
	try {
		ev.listenerPort = await listener.open();
		const t0 = Date.now();
		const started = await run([
			"quickchr",
			"start",
			machine,
			"--channel",
			target.channel,
			"--arch",
			target.arch,
		]);
		created = true;
		ev.bootMs = Date.now() - t0;
		ev.host.accelerator = await accelerator(machine);
		if (started.code !== 0) {
			throw new Error(
				`quickchr start exited ${started.code}: ${started.stderr.trim() || started.stdout.trim()}`,
			);
		}
		const inspect = await run(["quickchr", "inspect", machine, "--json"]);
		const rest = (
			JSON.parse(inspect.stdout) as {
				services: Record<string, { url: string; auth: { basic: string } }>;
			}
		).services["rest-api"];
		if (!rest) throw new Error("quickchr inspect has no rest-api service");
		const router = new Router(rest.url, rest.auth.basic);
		const res = (await router.rest("/system/resource")).body as Record<
			string,
			string
		>;
		ev.router = {
			// "7.24.6 (long-term)": the number, then the channel the router names.
			version: (res.version ?? "").split(" ")[0] ?? "",
			versionString: res.version ?? "",
			architecture: res["architecture-name"] ?? "",
			board: res["board-name"] ?? "",
			cpu: res.cpu ?? "",
		};
		ev.snifferDefaults = (await router.rest("/tool/sniffer")).body as Record<
			string,
			string
		>;
		await experiments(ev, router, listener, target.arch === "x86", machine);
	} catch (e) {
		ev.error = String(e);
	} finally {
		listener.close();
		if (created) {
			await run(["quickchr", "stop", machine]);
			await run(["quickchr", "remove", machine]);
		}
		await mkdir(EVIDENCE, { recursive: true });
		const file = join(
			EVIDENCE,
			`${ev.router?.version ?? target.channel}-${target.arch}.json`,
		);
		for (const exp of ev.experiments) {
			for (const s of exp.steps) s.output = withoutComments(s.output);
		}
		await writeFile(file, `${JSON.stringify(ev, null, "\t")}\n`);
		await biomeFormat(file);
		console.log(
			`${machine}: ${ev.error ? `FAILED ${ev.error}` : "done"} -> ${file}`,
		);
	}
	return ev;
}

if (import.meta.main) {
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
	if (targets.length === 0) {
		console.error(
			`--only takes one of ${all.map((t) => `${t.arch}:${t.channel}`).join(", ")}`,
		);
		process.exit(2);
	}
	const runId = Date.now().toString(36);
	// x86 machines one after another (the loop experiment loads the host);
	// the slow arm64 boot under TCG runs alongside them.
	const x86 = targets.filter((t) => t.arch === "x86");
	const arm = targets.filter((t) => t.arch === "arm64");
	const results = await Promise.all([
		(async () => {
			const out: Evidence[] = [];
			for (const t of x86) out.push(await lab(t, runId));
			return out;
		})(),
		Promise.all(arm.map((t) => lab(t, runId))),
	]);
	const failed = results.flat().filter((e) => e.error);
	process.exit(failed.length > 0 ? 1 : 0);
}
