/**
 * Shared test helpers: hex, frame builders for dissector vectors, RouterOS
 * fixtures, and loopback UDP. Sockets bind port 0 or ask the OS for a free
 * port; nothing assumes a fixed port is free (tikoci-testing, "Hermetic").
 */
import { CString, dlopen, FFIType } from "bun:ffi";
import { createSocket, type Socket } from "node:dgram";
import { closeSync, constants, openSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const bytes = (hex: string) =>
	Uint8Array.from(hex.match(/../g) ?? [], (b) => Number.parseInt(b, 16));

export const h8 = (n: number) => n.toString(16).padStart(2, "0");
export const h16 = (n: number) => n.toString(16).padStart(4, "0");
export const h32 = (n: number) => (n >>> 0).toString(16).padStart(8, "0");
const ip4 = (a: string) =>
	a
		.split(".")
		.map((p) => h8(Number(p)))
		.join("");
const mac = (m: string) => m.split(":").join("");
const half = (hex: string) => hex.length / 2;

export const MAC_A = "02:00:00:00:00:0a";
export const MAC_B = "02:00:00:00:00:0b";

/** An Ethernet frame, hex. */
export const eth = (type: number, payload: string, dst = MAC_B, src = MAC_A) =>
	mac(dst) + mac(src) + h16(type) + payload;

/** An IPv4 packet, hex; fields left out are filled in consistently. */
export function ipv4(o: {
	proto: number;
	payload: string;
	src?: string;
	dst?: string;
	ttl?: number;
	ihl?: number;
	options?: string;
	totalLength?: number;
	flagsOffset?: number;
	version?: number;
}): string {
	const options = o.options ?? "";
	const ihl = o.ihl ?? 5 + half(options) / 4;
	const total = o.totalLength ?? 20 + half(options) + half(o.payload);
	return (
		h8(((o.version ?? 4) << 4) | ihl) +
		"00" +
		h16(total) +
		"1234" +
		h16(o.flagsOffset ?? 0) +
		h8(o.ttl ?? 64) +
		h8(o.proto) +
		"0000" +
		ip4(o.src ?? "10.0.2.15") +
		ip4(o.dst ?? "10.0.2.3") +
		options +
		o.payload
	);
}

export const V6_SRC = "fe800000000000000000000000000001";
export const V6_DST = "20010db8000000000000000000000002";

/** An IPv6 packet, hex. `extensions` are already encoded and sit before `payload`. */
export function ipv6(o: {
	next: number;
	payload: string;
	extensions?: string;
	payloadLength?: number;
	version?: number;
}): string {
	const body = (o.extensions ?? "") + o.payload;
	return (
		h8((o.version ?? 6) << 4) +
		"000000" +
		h16(o.payloadLength ?? half(body)) +
		h8(o.next) +
		"40" +
		V6_SRC +
		V6_DST +
		body
	);
}

/** One 8-byte IPv6 extension header (hop-by-hop, routing, destination options). */
export const ext8 = (next: number) => `${h8(next)}00000000000000`;

export const udp = (sp: number, dp: number, payload: string, length?: number) =>
	h16(sp) + h16(dp) + h16(length ?? 8 + half(payload)) + "0000" + payload;

export function tcp(o: {
	sp: number;
	dp: number;
	flags: number;
	seq?: number;
	ack?: number;
	offset?: number;
	payload?: string;
	options?: string;
}): string {
	const options = o.options ?? "";
	const offset = o.offset ?? 5 + half(options) / 4;
	return (
		h16(o.sp) +
		h16(o.dp) +
		h32(o.seq ?? 1000) +
		h32(o.ack ?? 0) +
		h8(offset << 4) +
		h8(o.flags) +
		h16(64240) +
		"0000" +
		"0000" +
		options +
		(o.payload ?? "")
	);
}

/** An ICMP echo, hex: type, code, checksum, id, sequence, data. */
export const echo = (type: number, id: number, seq: number, data = "abcd") =>
	h8(type) + "00" + "0000" + h16(id) + h16(seq) + data;

/** The TZSP header RouterOS sends: v1, received, Ethernet, end tag alone. */
export const TZSP_HEADER = "0100000101";

const FIXTURES = join(import.meta.dir, "..", "fixtures", "routeros");

/** A RouterOS fixture's datagrams, hex, one per line. */
export const fixture = (name: string) =>
	readFileSync(join(FIXTURES, `${name}.hex`), "utf8")
		.trim()
		.split("\n");

/** Every fixture's provenance, from index.json. */
export const fixtureIndex = () =>
	JSON.parse(readFileSync(join(FIXTURES, "index.json"), "utf8")) as {
		file: string;
		listenerPort: number;
		routeros: string;
	}[];

/** Provenance of a fixture, from index.json. */
export const fixtureInfo = (name: string) => {
	const index = fixtureIndex();
	const entry = index.find((e) => e.file === `${name}.hex`);
	if (!entry) throw new Error(`no index.json entry for ${name}`);
	return entry;
};

const LLDP_FIXTURES = join(import.meta.dir, "..", "fixtures", "lldp");

/** An LLDP fixture's TZSP datagrams, hex, one per line (test/fixtures/lldp/). */
export const lldpFixture = (file: string) =>
	readFileSync(join(LLDP_FIXTURES, file), "utf8").trim().split("\n");

/** Every LLDP fixture's provenance, and what its router reported. */
export const lldpFixtureIndex = () =>
	JSON.parse(readFileSync(join(LLDP_FIXTURES, "index.json"), "utf8")) as {
		file: string;
		experiment: string;
		routeros: string;
		architecture: string;
		mac: string;
		identity: string;
	}[];

const MNDP_FIXTURES = join(import.meta.dir, "..", "fixtures", "mndp");

/** An MNDP fixture's TZSP datagrams, hex, one per line (test/lab/mndp/). */
export const mndpFixture = (file: string) =>
	readFileSync(join(MNDP_FIXTURES, file), "utf8").trim().split("\n");

/** Every MNDP fixture's provenance, and what its router reported. */
export const mndpFixtureIndex = () =>
	JSON.parse(readFileSync(join(MNDP_FIXTURES, "index.json"), "utf8")) as {
		file: string;
		experiment: string;
		routeros: string;
		architecture: string;
		mac: string;
		identity: string;
		board: string;
		versionString: string;
	}[];

const DHCP_FIXTURES = join(import.meta.dir, "..", "fixtures", "dhcp");

/** A DHCP fixture's TZSP datagrams, hex, one per line (test/lab/dhcp/). */
export const dhcpFixture = (file: string) =>
	readFileSync(join(DHCP_FIXTURES, file), "utf8").trim().split("\n");

/** Every DHCP fixture's provenance, each line's sender, and the routers' MACs. */
export const dhcpFixtureIndex = () =>
	JSON.parse(readFileSync(join(DHCP_FIXTURES, "index.json"), "utf8")) as {
		file: string;
		experiment: string;
		routeros: string;
		architecture: string;
		lines: { sender: string; message: string }[];
		serverEther1: string;
		serverEther2: string;
		clientEther2: string;
	}[];

/** An LLDP TLV, hex: the 7-bit type and 9-bit length, then the value. */
export const tlv = (type: number, value: string) =>
	h16((type << 9) | (value.length / 2)) + value;

/** A DHCP option, hex: code, length, value. */
export const opt = (code: number, value: string) =>
	h8(code) + h8(value.length / 2) + value;

/**
 * A DHCPv4 message, hex: the 236-byte header, the magic cookie and
 * `options` (already encoded, End included when wanted). Fields left out
 * are a client's DISCOVER from MAC_A.
 */
export function dhcpMessage(
	o: {
		op?: number;
		htype?: number;
		hlen?: number;
		xid?: number;
		flags?: number;
		ciaddr?: string;
		yiaddr?: string;
		siaddr?: string;
		giaddr?: string;
		chaddr?: string;
		sname?: string;
		file?: string;
		cookie?: string;
		options?: string;
	} = {},
): string {
	const pad = (hex: string, n: number) =>
		hex.padEnd(n * 2, "0").slice(0, n * 2);
	return (
		h8(o.op ?? 1) +
		h8(o.htype ?? 1) +
		h8(o.hlen ?? 6) +
		"00" +
		h32(o.xid ?? 0x12345678) +
		"0000" +
		h16(o.flags ?? 0) +
		ip4(o.ciaddr ?? "0.0.0.0") +
		ip4(o.yiaddr ?? "0.0.0.0") +
		ip4(o.siaddr ?? "0.0.0.0") +
		ip4(o.giaddr ?? "0.0.0.0") +
		pad(o.chaddr ?? mac(MAC_A), 16) +
		pad(o.sname ?? "", 64) +
		pad(o.file ?? "", 128) +
		(o.cookie ?? "63825363") +
		(o.options ?? `${opt(53, "01")}ff`)
	);
}

/** An MNDP TLV, hex: big-endian type and length, then the value. */
export const mtlv = (type: number, value: string) =>
	h16(type) + h16(value.length / 2) + value;

/** An MNDP datagram (header and TLVs, hex) in UDP 5678 to 5678 in IPv4 in Ethernet, as bytes. */
export const mndpFrame = (payload: string, sp = 5678, dp = 5678) =>
	bytes(eth(0x0800, ipv4({ proto: 17, payload: udp(sp, dp, payload) })));

/** A DHCP message in UDP 68 to 67 in IPv4 in Ethernet, as bytes. */
export const dhcpFrame = (message: string, sp = 68, dp = 67) =>
	bytes(eth(0x0800, ipv4({ proto: 17, payload: udp(sp, dp, message) })));

/** Hex of a string's UTF-8 bytes. */
export const utf8 = (s: string) => Buffer.from(s, "utf8").toString("hex");

/** Send each datagram to 127.0.0.1:port, in order, from one socket. */
export async function send(port: number, datagrams: (Uint8Array | string)[]) {
	const socket = createSocket("udp4");
	// Every socket error names its role, so a CI failure says which bind failed
	// (the Windows leg showed a bare "bind EADDRINUSE 0.0.0.0"). An error
	// event rejects the send in flight, even if its callback never comes.
	const failed = (error: Error) =>
		new Error(`sender to port ${port} failed: ${error.message}`, {
			cause: error,
		});
	let rejectInFlight: ((error: Error) => void) | undefined;
	let failure: Error | undefined;
	socket.on("error", (error) => {
		failure = failed(error);
		rejectInFlight?.(failure);
	});
	try {
		for (const d of datagrams) {
			if (failure) throw failure;
			const data = typeof d === "string" ? bytes(d) : d;
			await new Promise<void>((resolve, reject) => {
				rejectInFlight = reject;
				socket.send(data, port, "127.0.0.1", (error) =>
					error ? reject(failed(error)) : resolve(),
				);
			});
		}
	} finally {
		rejectInFlight = undefined;
		socket.close();
	}
}

/** Bind a UDP socket on 127.0.0.1 (port 0: any free one). Close it when done. */
export function holdPort(port = 0): Promise<{ socket: Socket; port: number }> {
	const socket = createSocket("udp4");
	return new Promise((resolve, reject) => {
		socket.once("error", (error) =>
			reject(
				new Error(`binding port ${port} to hold it failed: ${error.message}`, {
					cause: error,
				}),
			),
		);
		socket.bind({ port, address: "0.0.0.0" }, () =>
			resolve({ socket, port: socket.address().port }),
		);
	});
}

export const closeSocket = (socket: Socket) =>
	new Promise<void>((resolve) => socket.close(() => resolve()));

/** A port that was free a moment ago: bound, read, released. */
export async function freePort(): Promise<number> {
	const { socket, port } = await holdPort();
	await closeSocket(socket);
	// On Windows the port is free a few ms after close (see expectPortFree):
	// wait for that, so the caller's own bind does not race it.
	await expectPortFree(port);
	// expectPortFree's own probe has just closed too, so on Windows wait out
	// that release as well: 50 ms, five times the 10 ms measured there. A
	// bind cannot prove it, since each probe ends with another close.
	if (process.platform === "win32") await new Promise((r) => setTimeout(r, 50));
	return port;
}

/**
 * Proves `port` is free by binding it, then releases it again.
 *
 * Windows frees a UDP port a few milliseconds after the socket's `close`
 * event: on windows-latest with Bun 1.4.4, 3 of 3 rebinds right after
 * `closed` resolved failed with EADDRINUSE, and each succeeded at the first
 * retry 10 ms later (CI run 44521692931, the Codex review on #20). So on
 * Windows only, the bind is retried for up to 500 ms; elsewhere the port
 * must be free at once.
 */
export async function expectPortFree(port: number) {
	const deadline = Date.now() + (process.platform === "win32" ? 500 : 0);
	for (;;) {
		try {
			const { socket } = await holdPort(port);
			await closeSocket(socket);
			return;
		} catch (error) {
			if (Date.now() >= deadline) throw error;
			await new Promise((r) => setTimeout(r, 10));
		}
	}
}

/** Wait until `check()` holds, polling; fails after `timeoutMs`. */
export async function until(check: () => boolean, timeoutMs = 2000) {
	const deadline = Date.now() + timeoutMs;
	while (!check()) {
		if (Date.now() > deadline)
			throw new Error("timed out waiting for a condition");
		await new Promise((r) => setTimeout(r, 5));
	}
}

/**
 * An explicit environment for a child process, not a copy of this one
 * (tikoci-testing, "Hermetic"). Windows sockets need SystemRoot, so it is
 * kept when set.
 */
export function childEnv(): Record<string, string> {
	const env: Record<string, string> = {
		PATH: process.env.PATH ?? "",
		NO_COLOR: "1",
	};
	for (const key of ["SystemRoot", "SYSTEMROOT", "TEMP", "TMP"]) {
		const value = process.env[key];
		if (value !== undefined) env[key] = value;
	}
	return env;
}

/** 7.25.1 x86_64 /tool/sniffer, an ICMP echo request (test/fixtures/routeros/). */
const REQUEST_HEX = () => fixture("7.25.1-x86-sniffer-stream")[0] as string;

/**
 * A pseudo-terminal from libc (Linux and macOS; not Windows), for a child
 * whose terminal nobody reads: the test never reads `master`, so the
 * child's writes fill the terminal's buffer and then block, as with Ctrl-S.
 * Bun.spawn's own `terminal` option cannot do this: it always reads.
 */
export function openPty(): { master: number; slave: number } {
	const libc = dlopen(
		process.platform === "darwin" ? "/usr/lib/libSystem.B.dylib" : "libc.so.6",
		{
			posix_openpt: { args: [FFIType.i32], returns: FFIType.i32 },
			grantpt: { args: [FFIType.i32], returns: FFIType.i32 },
			unlockpt: { args: [FFIType.i32], returns: FFIType.i32 },
			ptsname: { args: [FFIType.i32], returns: FFIType.ptr },
		},
	);
	try {
		const { posix_openpt, grantpt, unlockpt, ptsname } = libc.symbols;
		const master = posix_openpt(constants.O_RDWR | constants.O_NOCTTY);
		if (master < 0) throw new Error("posix_openpt failed");
		const name = ptsname(master);
		if (grantpt(master) !== 0 || unlockpt(master) !== 0 || !name) {
			closeSync(master);
			throw new Error("grantpt, unlockpt or ptsname failed");
		}
		const path = new CString(name).toString();
		let slave: number;
		try {
			slave = openSync(path, constants.O_RDWR | constants.O_NOCTTY);
		} catch (error) {
			closeSync(master);
			throw error;
		}
		return { master, slave };
	} finally {
		libc.close();
	}
}

/**
 * Run the CLI (`command`, without flags) with stdout on a terminal nobody
 * reads, fill that terminal with full-detail packets, then send SIGINT.
 * Returns the exit code, stderr, the port, and the time from SIGINT to exit;
 * a child still running `budgetMs` after SIGINT is killed (code null).
 */
export async function stalledTerminal(command: string[], budgetMs: number) {
	const start = (slave: number) =>
		Bun.spawn(
			[
				...command,
				"--bind",
				"127.0.0.1",
				"--port",
				"0",
				"--follow",
				"--detail",
				"full",
			],
			{ env: childEnv(), stdin: "ignore", stdout: slave, stderr: "pipe" },
		);
	const pty = openPty();
	let proc: ReturnType<typeof start>;
	try {
		proc = start(pty.slave);
	} catch (error) {
		closeSync(pty.master);
		throw error;
	} finally {
		// The child has its own copy; the test never writes to the terminal.
		closeSync(pty.slave);
	}
	let stderr = "";
	const drained = (async () => {
		const decoder = new TextDecoder();
		for await (const chunk of proc.stderr)
			stderr += decoder.decode(chunk, { stream: true });
	})();
	let killer: ReturnType<typeof setTimeout> | undefined;
	try {
		await until(() => /listening on UDP [^ ]*:\d+/.test(stderr), budgetMs);
		const port = Number(/listening on UDP [^ ]*:(\d+)/.exec(stderr)?.[1]);
		// Each line is the datagram as hex, about 16 KB; 16 of them are more
		// than a terminal holds. Each datagram stays under macOS's default
		// loopback UDP limit (net.inet.udp.maxdgram, 9216 bytes): a 30 KB one
		// failed there with EMSGSIZE (CI, macos-latest).
		const big = REQUEST_HEX() + "00".repeat(8000);
		await send(port, Array(16).fill(big));
		await new Promise((r) => setTimeout(r, 500));
		const runningBeforeInterrupt = proc.exitCode === null;
		const interruptedAt = performance.now();
		proc.kill("SIGINT");
		killer = setTimeout(() => proc.kill("SIGKILL"), budgetMs);
		await proc.exited;
		const ms = performance.now() - interruptedAt;
		await drained;
		return {
			code: proc.signalCode === "SIGKILL" ? null : proc.exitCode,
			stderr,
			port,
			ms,
			runningBeforeInterrupt,
		};
	} finally {
		clearTimeout(killer);
		proc.kill("SIGKILL");
		closeSync(pty.master);
	}
}

/**
 * Run `command` (a CLI, `decode -` and its flags included) with stdin a
 * pipe that is written once and never closed, as a producer that has gone
 * quiet. Once `ready` matches stdout (or at once when it is undefined,
 * after `settleMs`), SIGINT is sent; the child must exit inside `budgetMs`
 * without stdin closing. The child is killed in `finally`.
 */
export async function interruptWithStdinOpen(
	command: string[],
	input: Uint8Array,
	o: { ready?: RegExp; settleMs?: number; budgetMs: number },
) {
	const proc = Bun.spawn(command, {
		env: childEnv(),
		stdin: "pipe",
		stdout: "pipe",
		stderr: "pipe",
	});
	const killer = setTimeout(() => proc.kill("SIGKILL"), o.budgetMs * 2);
	try {
		proc.stdin.write(input);
		await proc.stdin.flush();
		const stderr = new Response(proc.stderr).text();
		const reader = proc.stdout.getReader();
		const decoder = new TextDecoder();
		let stdout = "";
		let interruptedAt: number | undefined;
		const interrupt = () => {
			interruptedAt = performance.now();
			proc.kill("SIGINT");
		};
		if (!o.ready) setTimeout(interrupt, o.settleMs ?? 300);
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			stdout += decoder.decode(value, { stream: true });
			if (o.ready && interruptedAt === undefined && o.ready.test(stdout))
				interrupt();
		}
		const code = await proc.exited;
		return {
			code,
			stdout,
			stderr: await stderr,
			/** From SIGINT to exit; stdin was never closed. */
			ms: performance.now() - (interruptedAt ?? performance.now()),
			interrupted: interruptedAt !== undefined,
		};
	} finally {
		clearTimeout(killer);
		proc.kill("SIGKILL");
	}
}
