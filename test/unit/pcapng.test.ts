import { afterAll, describe, expect, test } from "bun:test";
import {
	closeSync,
	existsSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readdirSync,
	readFileSync,
	readSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openCapture } from "../../src/capture.ts";
import { TzspSniffError } from "../../src/errors.ts";
import { fileSink } from "../../src/file.ts";
import type { BoundListener, Capture } from "../../src/listen.ts";
import {
	type ByteSink,
	type CaptureWriter,
	interfaceBlock,
	LINKTYPE_TZSP,
	packetBlock,
	pcapngWriter,
	peerComment,
	sectionHeaderBlock,
} from "../../src/pcapng.ts";
import type { StreamRecord, SummaryRecord } from "../../src/records.ts";
import { parseTzsp } from "../../src/tzsp.ts";
import { VERSION } from "../../src/version.ts";
import {
	bytes,
	expectPortFree,
	fixture,
	holdPort,
	send,
	until,
} from "./helpers.ts";
import { blocks, readPcapng } from "./pcapng-reader.ts";

const STREAM = fixture("7.25.1-x86-sniffer-stream");
const REQUEST = STREAM[0] as string;
const CONTROL = "01040000";
const INVALID = "0100";
const POSIX = process.platform !== "win32";

const dir = mkdtempSync(join(tmpdir(), "tzsp-sniff-pcapng-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
let n = 0;
const fresh = () => join(dir, `capture-${++n}.pcapng`);

const LISTENER_A: BoundListener = Object.freeze({
	address: "0.0.0.0",
	port: 37008,
	label: "router-a",
});
const LISTENER_B: BoundListener = Object.freeze({
	address: "::",
	port: 37009,
	label: "37009",
});

function capture(
	hex: string,
	o: { listener?: BoundListener; seq?: number; peer?: string } = {},
): Capture {
	const datagram = bytes(hex);
	const peer = o.peer ?? "10.0.2.15";
	return {
		seq: o.seq ?? 1,
		time: 1_763_600_000_123,
		listener: o.listener ?? LISTENER_A,
		peer: {
			address: peer,
			port: 41000,
			family: peer.includes(":") ? "IPv6" : "IPv4",
		},
		datagram,
		tzsp: parseTzsp(datagram),
	};
}

/** A sink that keeps every chunk, and can fail or hang on the nth write. */
function memorySink(
	o: {
		failAt?: number;
		error?: unknown;
		hangAt?: number;
		closeError?: unknown;
	} = {},
) {
	const chunks: Uint8Array[] = [];
	let writes = 0;
	const calls: string[] = [];
	const sink: ByteSink = {
		async open() {
			calls.push("open");
		},
		write(chunk) {
			writes += 1;
			calls.push("write");
			if (writes === o.hangAt) return new Promise(() => {});
			if (writes === o.failAt) return Promise.reject(o.error);
			chunks.push(chunk);
			return Promise.resolve();
		},
		async close() {
			calls.push("close");
			if (o.closeError) throw o.closeError;
		},
	};
	return { sink, chunks, calls, bytes: () => Buffer.concat(chunks) };
}

const rejection = async (p: Promise<unknown>) => {
	try {
		await p;
	} catch (error) {
		return error;
	}
	throw new Error("expected a rejection");
};

describe("pcapng blocks", () => {
	test("section header: little-endian magic, version 1.0, unknown length, the application", () => {
		const b = sectionHeaderBlock("tzsp-sniff 1.2.3");
		const view = new DataView(b.buffer);
		expect(view.getUint32(0, true)).toBe(0x0a0d0d0a);
		expect(view.getUint32(4, true)).toBe(b.length);
		expect(view.getUint32(b.length - 4, true)).toBe(b.length);
		expect(b.length % 4).toBe(0);
		const file = readPcapng(b);
		expect(file.version).toEqual([1, 0]);
		expect(file.sectionLength).toBe(-1n);
		expect(file.application).toBe("tzsp-sniff 1.2.3");
	});

	test("interface: LINKTYPE_TZSP, no snap length, the label, the port, ms timestamps", () => {
		const file = readPcapng(
			Buffer.concat([
				sectionHeaderBlock("x"),
				interfaceBlock(LISTENER_A),
				interfaceBlock(LISTENER_B),
			]),
		);
		expect(LINKTYPE_TZSP).toBe(128);
		expect(file.interfaces).toEqual([
			{
				linkType: 128,
				snapLen: 0,
				name: "router-a",
				description: "TZSP on UDP 0.0.0.0:37008",
				tsresol: 3,
			},
			{
				linkType: 128,
				snapLen: 0,
				name: "37009",
				description: "TZSP on UDP [::]:37009",
				tsresol: 3,
			},
		]);
	});

	test("packet: interface, arrival time in ms, the datagram byte for byte, the peer comment", () => {
		const c = capture(REQUEST);
		const file = readPcapng(
			Buffer.concat([
				sectionHeaderBlock("x"),
				interfaceBlock(LISTENER_A),
				interfaceBlock(LISTENER_B),
				packetBlock(1, c),
			]),
		);
		const [p] = file.packets;
		expect(p?.interfaceId).toBe(1);
		expect(p?.timestamp).toBe(1_763_600_000_123n);
		expect(p?.capturedLength).toBe(c.datagram.length);
		expect(p?.originalLength).toBe(c.datagram.length);
		expect(Buffer.from(p?.data ?? []).toString("hex")).toBe(REQUEST);
		expect(p?.comments).toEqual(["peer=10.0.2.15:41000"]);
	});

	test("a datagram of any length is padded to 32 bits; an IPv6 peer is bracketed", () => {
		for (const hex of [INVALID, CONTROL, `${REQUEST}aa`, `${REQUEST}aabb`]) {
			const b = packetBlock(0, capture(hex, { peer: "fe80::1" }));
			expect(b.length % 4).toBe(0);
			const [p] = readPcapng(
				Buffer.concat([sectionHeaderBlock("x"), interfaceBlock(LISTENER_A), b]),
			).packets;
			expect(Buffer.from(p?.data ?? []).toString("hex")).toBe(hex);
			expect(p?.comments).toEqual(["peer=[fe80::1]:41000"]);
		}
		expect(peerComment("::ffff:10.0.0.1", 5)).toBe("peer=[::ffff:10.0.0.1]:5");
	});
});

describe("pcapngWriter", () => {
	test("open: the sink first, then a section header and one interface per listener; write: one block each", async () => {
		const m = memorySink();
		const w = pcapngWriter(m.sink, { target: "mem" });
		expect(w.target).toBe("mem");
		await w.open([LISTENER_A, LISTENER_B]);
		await w.write(capture(REQUEST, { listener: LISTENER_B }));
		// A listener object equal by port, not by identity, still maps.
		await w.write(capture(CONTROL, { listener: { ...LISTENER_A } }));
		await w.close();
		expect(m.calls).toEqual([
			"open",
			"write",
			"write",
			"write",
			"write",
			"write",
			"close",
		]);
		const file = readPcapng(m.bytes());
		expect(file.application).toBe(`tzsp-sniff ${VERSION}`);
		expect(file.interfaces.map((i) => i.name)).toEqual(["router-a", "37009"]);
		expect(file.packets.map((p) => p.interfaceId)).toEqual([1, 0]);
		expect(file.trailing).toBe(0);
		expect(w.written).toEqual({ datagrams: 2, bytes: m.bytes().length });
	});

	test("used out of order: write/invalid-option", async () => {
		const w = pcapngWriter(memorySink().sink);
		const code = async (p: Promise<unknown>) =>
			((await rejection(p)) as TzspSniffError).code;
		expect(await code(w.write(capture(REQUEST)))).toBe("write/invalid-option");
		await w.open([LISTENER_A]);
		expect(await code(w.open([LISTENER_A]))).toBe("write/invalid-option");
		expect(
			await code(
				w.write(
					capture(REQUEST, {
						listener: { address: "0.0.0.0", port: 1, label: "x" },
					}),
				),
			),
		).toBe("write/invalid-option");
		await w.close();
		expect(await code(w.write(capture(REQUEST)))).toBe("write/invalid-option");
		expect(() => pcapngWriter(memorySink().sink, { stallMs: -1 })).toThrow(
			TzspSniffError,
		);
	});

	test("a sink's coded failure is the writer's from then on; close still closes the sink and reports it", async () => {
		const error = new TzspSniffError("write/failed", "disk full");
		const m = memorySink({ failAt: 3, error });
		const w = pcapngWriter(m.sink);
		await w.open([LISTENER_A]);
		expect(await rejection(w.write(capture(REQUEST)))).toBe(error);
		expect(await rejection(w.write(capture(REQUEST)))).toBe(error);
		expect(await rejection(w.close())).toBe(error);
		expect(m.calls.at(-1)).toBe("close");
		expect(m.calls.filter((c) => c === "write")).toHaveLength(3);
		expect(w.written.datagrams).toBe(0);
	});

	test("an uncoded sink error comes through unchanged", async () => {
		const error = new Error("reader went away");
		const w = pcapngWriter(memorySink({ failAt: 3, error }).sink);
		await w.open([LISTENER_A]);
		expect(await rejection(w.write(capture(REQUEST)))).toBe(error);
	});

	test("a sink that takes nothing for stallMs: write/stalled", async () => {
		const w = pcapngWriter(memorySink({ hangAt: 3 }).sink, {
			stallMs: 50,
			target: "slow",
		});
		await w.open([LISTENER_A]);
		const started = performance.now();
		const error = (await rejection(
			w.write(capture(REQUEST)),
		)) as TzspSniffError;
		expect(error.code).toBe("write/stalled");
		expect(error.message).toContain("slow");
		expect(performance.now() - started).toBeLessThan(2000);
	});

	test("a close failure is reported when nothing failed before", async () => {
		const error = new TzspSniffError("write/failed", "close");
		const m = memorySink({ closeError: error });
		const w = pcapngWriter(m.sink);
		await w.open([LISTENER_A]);
		expect(await rejection(w.close())).toBe(error);
		// Closing twice does nothing more.
		await w.close();
		expect(m.calls.filter((c) => c === "close")).toHaveLength(1);
	});
});

describe("fileSink", () => {
	test("nothing is created before open; then a new file, owner-only", async () => {
		const path = fresh();
		const sink = fileSink(path);
		expect(existsSync(path)).toBe(false);
		await sink.open();
		await sink.write(Uint8Array.of(1, 2, 3));
		await sink.close();
		expect([...readFileSync(path)]).toEqual([1, 2, 3]);
		if (POSIX) expect(statSync(path).mode & 0o777).toBe(0o600);
	});

	test("an existing file is write/exists, and is left as it was", async () => {
		const path = fresh();
		writeFileSync(path, "keep");
		const error = (await rejection(fileSink(path).open())) as TzspSniffError;
		expect(error.code).toBe("write/exists");
		expect(error.message).toContain(path);
		expect(error.fix).toContain("--overwrite");
		expect(readFileSync(path, "utf8")).toBe("keep");
	});

	test("overwrite: the old contents go, and the file is owner-only again", async () => {
		const path = fresh();
		writeFileSync(path, "old contents, longer than the new", { mode: 0o644 });
		const sink = fileSink(path, { overwrite: true });
		await sink.open();
		await sink.write(Uint8Array.of(9));
		await sink.close();
		expect([...readFileSync(path)]).toEqual([9]);
		if (POSIX) expect(statSync(path).mode & 0o777).toBe(0o600);
	});

	// Windows too: CI's runners may create symbolic links.
	test("overwrite never follows a symbolic link: write/failed, the target untouched", async () => {
		const target = fresh();
		writeFileSync(target, "target", { mode: 0o644 });
		const link = fresh();
		symlinkSync(target, link);
		const error = (await rejection(
			fileSink(link, { overwrite: true }).open(),
		)) as TzspSniffError;
		expect(error.code).toBe("write/failed");
		expect(readFileSync(target, "utf8")).toBe("target");
		if (POSIX) expect(statSync(target).mode & 0o777).toBe(0o644);
		expect(lstatSync(link).isSymbolicLink()).toBe(true);
		expect(error.message).toContain("a symbolic link");
	});

	test("a directory that is not there: write/failed naming the path", async () => {
		const path = join(dir, "missing", "x.pcapng");
		const error = (await rejection(fileSink(path).open())) as TzspSniffError;
		expect(error.code).toBe("write/failed");
		expect(error.message).toContain(path);
	});

	test("a full disk: write/failed with the cause", async () => {
		const enospc = Object.assign(new Error("ENOSPC: no space left on device"), {
			code: "ENOSPC",
		});
		let closed = 0;
		const sink = fileSink(
			fresh(),
			{},
			{
				open: (async () => ({
					write: async () => {
						throw enospc;
					},
					close: async () => {
						closed += 1;
					},
				})) as never,
			},
		);
		await sink.open();
		const error = (await rejection(
			sink.write(Uint8Array.of(1)),
		)) as TzspSniffError;
		expect(error.code).toBe("write/failed");
		expect(error.cause).toBe(enospc);
		await sink.close();
		expect(closed).toBe(1);
	});

	test("overwrite: a reader that had the old file open never sees the capture", async () => {
		const path = fresh();
		writeFileSync(path, "old", { mode: 0o644 });
		const fd = openSync(path, "r");
		try {
			const sink = fileSink(path, { overwrite: true });
			if (POSIX) {
				await sink.open();
				await sink.write(Uint8Array.of(7, 7, 7, 7, 7));
				await sink.close();
				expect([...readFileSync(path)]).toEqual([7, 7, 7, 7, 7]);
				expect(statSync(path).mode & 0o777).toBe(0o600);
			} else {
				// Windows will not rename over a file another handle holds open
				// (`EPERM` on windows-latest, Bun 1.4.4): the overwrite fails,
				// and the old file stays as it was.
				const error = (await rejection(sink.open())) as TzspSniffError;
				expect(error.code).toBe("write/failed");
				expect(readFileSync(path, "utf8")).toBe("old");
			}
			const buffer = Buffer.alloc(16);
			const n = readSync(fd, buffer, 0, 16, 0);
			expect(buffer.subarray(0, n).toString()).toBe("old");
			// No temporary file is left beside it.
			expect(readdirSync(dir).filter((f) => f.endsWith(".tzsp-sniff"))).toEqual(
				[],
			);
		} finally {
			closeSync(fd);
		}
	});

	test("overwrite refuses a directory, naming the path", async () => {
		const path = join(dir, `d-${++n}`);
		mkdirSync(path);
		const error = (await rejection(
			fileSink(path, { overwrite: true }).open(),
		)) as TzspSniffError;
		expect(error.code).toBe("write/failed");
		expect(error.message).toContain("a directory");
	});

	// mkfifo: Linux and macOS.
	test.skipIf(!POSIX)(
		"overwrite refuses a named pipe at once, without opening it",
		async () => {
			const path = fresh();
			expect(Bun.spawnSync(["mkfifo", path]).exitCode).toBe(0);
			const started = performance.now();
			const error = (await rejection(
				fileSink(path, { overwrite: true }).open(),
			)) as TzspSniffError;
			expect(error.code).toBe("write/failed");
			expect(error.message).toContain("not a regular file");
			expect(performance.now() - started).toBeLessThan(1000);
			expect(lstatSync(path).isFIFO()).toBe(true);
		},
	);
});

/** Every record of a capture, sending `datagrams` once the header is in. */
async function drain(
	stream: AsyncIterable<StreamRecord> & {
		header: { listeners: { port: number }[] };
	},
	datagrams: string[],
) {
	const seen: StreamRecord[] = [];
	for await (const r of stream) {
		seen.push(r);
		if (r.type === "header")
			await send(r.listeners[0]?.port as number, datagrams);
	}
	return seen;
}

const summaryOf = (records: StreamRecord[]) => records.at(-1) as SummaryRecord;

describe("openCapture with writers", () => {
	test("write saves every datagram, before filters; writeReported only what is reported", async () => {
		const all = memorySink();
		const reported = memorySink();
		const path = "all.pcapng";
		const stream = await openCapture({
			ports: [{ port: 0, label: "lab" }],
			bind: "127.0.0.1",
			idleMs: 300,
			filter: { proto: ["tcp"] },
			write: pcapngWriter(all.sink, { target: path }),
			writeReported: pcapngWriter(reported.sink),
		});
		expect(stream.header.write).toBe(path);
		const records = await drain(stream, [REQUEST, CONTROL, INVALID]);
		const summary = summaryOf(records);
		expect(summary.status).toBe("complete");
		expect(summary.counters).toMatchObject({
			datagrams: 3,
			packets: 0,
			filtered: 1,
			control: 1,
			invalid: 1,
		});
		const file = readPcapng(all.bytes());
		expect(file.interfaces.map((i) => i.name)).toEqual(["lab"]);
		expect(
			file.packets.map((p) => Buffer.from(p.data).toString("hex")),
		).toEqual([REQUEST, CONTROL, INVALID]);
		expect(file.packets[0]?.comments[0]).toMatch(/^peer=127\.0\.0\.1:\d+$/);
		expect(summary.written).toEqual({
			datagrams: 3,
			bytes: all.bytes().length,
		});
		// The filtered ICMP frame is not reported; the records are.
		expect(
			readPcapng(reported.bytes()).packets.map((p) =>
				Buffer.from(p.data).toString("hex"),
			),
		).toEqual([CONTROL, INVALID]);
		expect(all.calls.at(-1)).toBe("close");
		expect(reported.calls.at(-1)).toBe("close");
	});

	test("no writer: no write in the header, no written in the summary", async () => {
		const stream = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			idleMs: 100,
		});
		expect("write" in stream.header).toBe(false);
		const records = await drain(stream, []);
		expect("written" in summaryOf(records)).toBe(false);
	});

	test("a file that cannot be made: openCapture rejects with its code, and the port is freed", async () => {
		const path = fresh();
		writeFileSync(path, "x");
		let port = 0;
		const listeners: BoundListener[] = [];
		const w = pcapngWriter(fileSink(path), { target: path });
		const spy: CaptureWriter = {
			target: w.target,
			written: w.written,
			open: (l) => {
				listeners.push(...l);
				port = l[0]?.port as number;
				return w.open(l);
			},
			write: (c) => w.write(c),
			close: () => w.close(),
		};
		const error = (await rejection(
			openCapture({ ports: [{ port: 0 }], bind: "127.0.0.1", write: spy }),
		)) as TzspSniffError;
		expect(error.code).toBe("write/exists");
		expect(listeners).toHaveLength(1);
		await expectPortFree(port);
		expect(readFileSync(path, "utf8")).toBe("x");
	});

	test("a port that fails to bind leaves no file", async () => {
		const held = await holdPort();
		const path = fresh();
		try {
			const error = (await rejection(
				openCapture({
					ports: [{ port: held.port }],
					write: pcapngWriter(fileSink(path)),
				}),
			)) as TzspSniffError;
			expect(error.code).toBe("listen/bind-failed");
			expect(existsSync(path)).toBe(false);
		} finally {
			held.socket.close();
		}
	});

	test("a write that fails mid-capture ends it with that error; the counters still add up", async () => {
		const error = new TzspSniffError(
			"write/failed",
			"Writing x failed: ENOSPC",
		);
		// Section header, interface, then the first packet block succeed.
		const m = memorySink({ failAt: 4, error });
		const stream = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			durationMs: 3000,
			write: pcapngWriter(m.sink),
		});
		const records = await drain(stream, [REQUEST, REQUEST, REQUEST]);
		const summary = summaryOf(records);
		expect(summary.status).toBe("error");
		expect(summary.stoppedBy).toBe("error");
		expect(summary.error?.code).toBe("write/failed");
		// The first packet was saved and printed; the second's save failed,
		// so it is counted as unsaved and not handed over.
		expect(records.filter((r) => r.type === "packet")).toHaveLength(1);
		expect(summary.counters.packets).toBe(1);
		expect(summary.counters.unsaved).toBe(1);
		const c = summary.counters;
		expect(
			c.packets +
				c.control +
				c.unsupported +
				c.invalid +
				c.filtered +
				c.dropped +
				c.unread +
				c.unsaved,
		).toBe(c.datagrams);
		expect(summary.written?.datagrams).toBe(1);
		expect(m.calls.at(-1)).toBe("close");
		await expectPortFree(stream.header.listeners[0]?.port as number);
	});

	test("a close that fails makes the summary an error", async () => {
		const error = new TzspSniffError("write/failed", "Closing x failed");
		const stream = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			count: 1,
			write: pcapngWriter(memorySink({ closeError: error }).sink),
		});
		const summary = summaryOf(await drain(stream, [REQUEST]));
		expect(summary.status).toBe("error");
		expect(summary.stoppedBy).toBe("count");
		expect(summary.error?.code).toBe("write/failed");
	});

	test("stopped early by the caller: the writers are closed, and a close failure rejects return()", async () => {
		const ok = memorySink();
		const stream = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			durationMs: 3000,
			write: pcapngWriter(ok.sink),
		});
		for await (const r of stream) {
			if (r.type === "header") break;
		}
		expect(ok.calls.at(-1)).toBe("close");

		const error = new TzspSniffError("write/failed", "Closing x failed");
		const bad = memorySink({ closeError: error });
		const unread = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			durationMs: 3000,
			write: pcapngWriter(bad.sink),
		});
		// Never read: return() alone still closes the writer.
		const iterator = unread[Symbol.asyncIterator]();
		expect(await rejection(iterator.return?.() ?? Promise.resolve())).toBe(
			error,
		);
		expect(bad.calls.at(-1)).toBe("close");
	});

	test("one writer given as both is refused, and nothing stays bound", async () => {
		const w = pcapngWriter(memorySink().sink);
		const error = (await rejection(
			openCapture({ ports: [{ port: 0 }], write: w, writeReported: w }),
		)) as TzspSniffError;
		expect(error.code).toBe("listen/invalid-option");
	});

	test("a real file: every block whole, owner-only", async () => {
		const path = fresh();
		const stream = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			count: 2,
			write: pcapngWriter(fileSink(path), { target: path }),
		});
		const summary = summaryOf(await drain(stream, [REQUEST, REQUEST]));
		const file = readFileSync(path);
		expect(blocks(file).trailing).toBe(0);
		expect(readPcapng(file).packets).toHaveLength(2);
		expect(summary.written?.bytes).toBe(file.length);
		if (POSIX) expect(statSync(path).mode & 0o777).toBe(0o600);
	});
});

test("a capture nobody reads closes its writer when its limit closes the sockets", async () => {
	const m = memorySink();
	const stream = await openCapture({
		ports: [{ port: 0 }],
		bind: "127.0.0.1",
		durationMs: 50,
		write: pcapngWriter(m.sink),
	});
	await stream.listener.closed;
	await until(() => m.calls.at(-1) === "close");
	// Read later, it still ends with a summary.
	const records: StreamRecord[] = [];
	for await (const r of stream) records.push(r);
	expect(summaryOf(records).stoppedBy).toBe("duration");
	expect(m.calls.filter((c) => c === "close")).toHaveLength(1);
});

/** A promise and the function that resolves it. */
function deferred() {
	let resolve: () => void = () => {};
	const promise = new Promise<void>((r) => {
		resolve = r;
	});
	return { promise, resolve };
}

describe("writer limits and late calls", () => {
	test("an option too long for pcapng is refused before the sink is touched", async () => {
		const m = memorySink();
		const w = pcapngWriter(m.sink);
		const error = (await rejection(
			w.open([{ address: "0.0.0.0", port: 1, label: "é".repeat(32_768) }]),
		)) as TzspSniffError;
		expect(error.code).toBe("write/invalid-option");
		expect(m.calls).toEqual([]);
	});

	test("stallMs above the timer maximum is refused", () => {
		const code = (stallMs: number) => {
			try {
				pcapngWriter(memorySink().sink, { stallMs });
			} catch (error) {
				return (error as TzspSniffError).code;
			}
			return undefined;
		};
		expect(code(2_147_483_648)).toBe("write/invalid-option");
		expect(code(2_147_483_647)).toBeUndefined();
	});

	test("an open that times out and finishes late is still closed", async () => {
		const late = deferred();
		const calls: string[] = [];
		let held = false;
		const w = pcapngWriter(
			{
				async open() {
					await late.promise;
					held = true;
					calls.push("open");
				},
				async write() {},
				async close() {
					calls.push(`close held=${held}`);
					held = false;
				},
			},
			{ stallMs: 30 },
		);
		const error = (await rejection(w.open([LISTENER_A]))) as TzspSniffError;
		expect(error.code).toBe("write/stalled");
		const closing = w.close().catch(() => {});
		setTimeout(late.resolve, 5);
		await closing;
		expect(calls).toEqual(["open", "close held=true"]);
		expect(held).toBe(false);
	});

	test("a write that times out and finishes late does not change what was written", async () => {
		const late = deferred();
		let writes = 0;
		const w = pcapngWriter(
			{
				async write() {
					writes += 1;
					if (writes === 3) await late.promise;
				},
			},
			{ stallMs: 30 },
		);
		await w.open([LISTENER_A]);
		const before = { ...w.written };
		expect(
			((await rejection(w.write(capture(REQUEST)))) as TzspSniffError).code,
		).toBe("write/stalled");
		late.resolve();
		await new Promise((r) => setTimeout(r, 10));
		expect(w.written).toEqual(before);
	});
});

describe("capture shutdown with writers", () => {
	test("the limits run from the bind, while a writer is still opening", async () => {
		const slow = deferred();
		setTimeout(slow.resolve, 150);
		const stream = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			durationMs: 20,
			write: pcapngWriter({
				open: () => slow.promise,
				async write() {},
			}),
		});
		const summary = summaryOf(await drain(stream, []));
		expect(summary.stoppedBy).toBe("duration");
		expect(summary.durationMs).toBeLessThan(120);
	});

	test("a reader paused at the header: the writer closes when the limit ends intake", async () => {
		const m = memorySink();
		const stream = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			durationMs: 30,
			write: pcapngWriter(m.sink),
		});
		const iterator = stream[Symbol.asyncIterator]();
		expect((await iterator.next()).value?.type).toBe("header");
		await stream.listener.closed;
		await until(() => m.calls.at(-1) === "close");
		// Read on later: the summary still comes.
		let last: StreamRecord | undefined;
		for (;;) {
			const r = await iterator.next();
			if (r.done) break;
			last = r.value;
		}
		expect(last?.type).toBe("summary");
		expect(m.calls.filter((c) => c === "close")).toHaveLength(1);
	});

	test("throw() while a write is pending: the writer closes after it", async () => {
		// A bare CaptureWriter, not pcapngWriter (which waits for its own last
		// call), so this checks the capture's own ordering.
		const held = deferred();
		const order: string[] = [];
		let writing = false;
		const writer: CaptureWriter = {
			target: "bare",
			written: { datagrams: 0, bytes: 0 },
			async open() {},
			async write() {
				writing = true;
				await held.promise;
				order.push("write finished");
			},
			async close() {
				order.push("close");
			},
		};
		const stream = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			durationMs: 3000,
			write: writer,
		});
		const iterator = stream[Symbol.asyncIterator]();
		const header = (await iterator.next()).value as {
			listeners: { port: number }[];
		};
		const pending = iterator.next();
		await send(header.listeners[0]?.port as number, [REQUEST]);
		await until(() => writing);
		const thrown = iterator.throw?.(new Error("stop"));
		setTimeout(held.resolve, 20);
		await pending;
		await thrown?.catch(() => {});
		expect(order).toEqual(["write finished", "close"]);
	});

	test("a write failure after the duration ended intake keeps duration as the reason", async () => {
		let writes = 0;
		const stream = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			durationMs: 60,
			write: pcapngWriter(
				{
					write: async () => {
						writes += 1;
						if (writes === 3) await new Promise(() => {});
					},
				},
				{ stallMs: 150 },
			),
		});
		const summary = summaryOf(await drain(stream, [REQUEST]));
		expect(summary.stoppedBy).toBe("duration");
		expect(summary.status).toBe("error");
		expect(summary.error?.code).toBe("write/stalled");
	});

	test("a writer another capture holds is refused, and that capture keeps it", async () => {
		const m = memorySink();
		const w = pcapngWriter(m.sink);
		const first = await openCapture({
			ports: [{ port: 0 }],
			bind: "127.0.0.1",
			count: 1,
			durationMs: 3000,
			write: w,
		});
		const error = (await rejection(
			openCapture({ ports: [{ port: 0 }], bind: "127.0.0.1", write: w }),
		)) as TzspSniffError;
		expect(error.code).toBe("write/invalid-option");
		expect(m.calls).not.toContain("close");
		const summary = summaryOf(await drain(first, [REQUEST]));
		expect(summary.status).toBe("complete");
		expect(summary.written?.datagrams).toBe(1);
	});
});

describe("writer edge cases from CodeRabbit", () => {
	test("a sink that throws instead of rejecting: the failure sticks, and the sink is not called again", async () => {
		const error = new TzspSniffError("write/failed", "sync");
		let writes = 0;
		const w = pcapngWriter({
			write: ((_chunk: Uint8Array) => {
				writes += 1;
				if (writes === 3) throw error;
				return Promise.resolve();
			}) as ByteSink["write"],
		});
		await w.open([LISTENER_A]);
		expect(await rejection(w.write(capture(REQUEST)))).toBe(error);
		expect(await rejection(w.write(capture(REQUEST)))).toBe(error);
		expect(writes).toBe(3);
	});

	test("an open that settles after close has stopped waiting is still closed", async () => {
		const late = deferred();
		let held = false;
		let closes = 0;
		const w = pcapngWriter(
			{
				async open() {
					await late.promise;
					held = true;
				},
				async write() {},
				async close() {
					closes += 1;
					held = false;
				},
			},
			{ stallMs: 20 },
		);
		expect(
			((await rejection(w.open([LISTENER_A]))) as TzspSniffError).code,
		).toBe("write/stalled");
		await w.close().catch(() => {});
		// Close has given up waiting; the open finishes only now.
		expect(held).toBe(false);
		late.resolve();
		await until(() => closes === 2);
		expect(held).toBe(false);
	});
});
