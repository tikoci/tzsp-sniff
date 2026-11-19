/**
 * Shared test helpers: hex, frame builders for dissector vectors, RouterOS
 * fixtures, and loopback UDP. Sockets bind port 0 or ask the OS for a free
 * port; nothing assumes a fixed port is free (tikoci-testing, "Hermetic").
 */
import { createSocket, type Socket } from "node:dgram";
import { readFileSync } from "node:fs";
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

/** Provenance of a fixture, from index.json. */
export const fixtureInfo = (name: string) => {
	const index = JSON.parse(
		readFileSync(join(FIXTURES, "index.json"), "utf8"),
	) as {
		file: string;
		listenerPort: number;
		routeros: string;
	}[];
	const entry = index.find((e) => e.file === `${name}.hex`);
	if (!entry) throw new Error(`no index.json entry for ${name}`);
	return entry;
};

/** Send each datagram to 127.0.0.1:port, in order, from one socket. */
export async function send(port: number, datagrams: (Uint8Array | string)[]) {
	const socket = createSocket("udp4");
	// Every socket error names its role, so a CI failure says which bind failed
	// (the Windows leg showed a bare "bind EADDRINUSE 0.0.0.0").
	let failure: Error | undefined;
	socket.on("error", (error) => {
		failure = new Error(`sender to port ${port} failed: ${error.message}`, {
			cause: error,
		});
	});
	try {
		for (const d of datagrams) {
			const data = typeof d === "string" ? bytes(d) : d;
			await new Promise<void>((resolve, reject) =>
				socket.send(data, port, "127.0.0.1", (error) =>
					error
						? reject(
								new Error(`sender to port ${port} failed: ${error.message}`, {
									cause: error,
								}),
							)
						: resolve(),
				),
			);
			if (failure) throw failure;
		}
	} finally {
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
	return port;
}

/**
 * Proves `port` is free now by binding it, then releases it again.
 *
 * Diagnostic (Codex review on #20): the Windows leg failed this rebind right
 * after the listener's `closed` resolved. On failure it keeps trying for up
 * to 2 s only to measure how long the port stayed held, prints that, and
 * still fails: the measurement decides the fix, the retry does not.
 */
export async function expectPortFree(port: number) {
	try {
		const { socket } = await holdPort(port);
		await closeSocket(socket);
	} catch (error) {
		const started = Date.now();
		let freedAfter: number | undefined;
		while (Date.now() - started < 2000) {
			await new Promise((r) => setTimeout(r, 10));
			const held = await holdPort(port).catch(() => undefined);
			if (held) {
				await closeSocket(held.socket);
				freedAfter = Date.now() - started;
				break;
			}
		}
		console.error(
			`expectPortFree(${port}) on ${process.platform}: not free at first; ${freedAfter === undefined ? "still held after 2000 ms" : `free after ${freedAfter} ms`}`,
		);
		throw error;
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
