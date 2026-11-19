import { describe, expect, test } from "bun:test";
import { createSocket, type Socket, type SocketOptions } from "node:dgram";
import { join } from "node:path";
import {
	type CaptureOptions,
	type CaptureStream,
	openCapture,
} from "../../src/capture.ts";
import { TzspSniffError } from "../../src/errors.ts";
import type {
	Counters,
	PacketRecord,
	StreamRecord,
	SummaryRecord,
	WarningRecord,
} from "../../src/records.ts";
import {
	childEnv,
	closeSocket,
	eth,
	expectPortFree,
	fixture,
	holdPort,
	ipv4,
	send,
	TZSP_HEADER,
	tcp,
	until,
} from "./helpers.ts";

/**
 * The capture core (DESIGN.md, "Counters and --expect", "Stream
 * termination"): every stream starts with a header and, read to the end,
 * ends with exactly one summary whose counters add up.
 */
const STREAM = fixture("7.25.1-x86-sniffer-stream");
const REQUEST = STREAM[0] as string;
const KEEPALIVE = "01040000";
const INVALID = "02000001";

/** A TCP SYN to port 22, as RouterOS would stream it. */
const SSH =
	TZSP_HEADER +
	eth(
		0x0800,
		ipv4({
			proto: 6,
			src: "10.0.2.15",
			dst: "192.0.2.7",
			payload: tcp({ sp: 50000, dp: 22, flags: 0x02 }),
		}),
	);

const portOf = (s: CaptureStream) => s.header.listeners[0]?.port as number;

/** Read the stream to its end, running `during` once the header has arrived. */
async function readAll(
	options: CaptureOptions,
	during: (stream: CaptureStream) => Promise<void> = async () => {},
) {
	const stream = await openCapture({ ports: [{ port: 0 }], ...options });
	const records: StreamRecord[] = [];
	for await (const record of stream) {
		records.push(record);
		if (record.type === "header") await during(stream);
	}
	await stream.listener.closed;
	return { stream, records, summary: records.at(-1) as SummaryRecord };
}

const sumOf = (c: Counters) =>
	c.packets +
	c.control +
	c.unsupported +
	c.invalid +
	c.filtered +
	c.dropped +
	c.unread;

const ofType = <T extends StreamRecord["type"]>(
	records: StreamRecord[],
	type: T,
) =>
	records.filter(
		(r): r is Extract<StreamRecord, { type: T }> => r.type === type,
	);

describe("openCapture", () => {
	test("header first, summary last, records between; --count stops it", async () => {
		const { stream, records, summary } = await readAll(
			{ count: 2, durationMs: 5000 },
			(s) =>
				send(portOf(s), [
					KEEPALIVE,
					REQUEST,
					INVALID,
					STREAM[1] as string,
					REQUEST,
				]),
		);
		expect(records[0]?.type).toBe("header");
		expect(ofType(records, "summary")).toHaveLength(1);
		expect(summary.type).toBe("summary");
		expect(summary).toMatchObject({ status: "complete", stoppedBy: "count" });
		expect(ofType(records, "packet").map((p) => p.seq)).toEqual([2, 4]);
		expect(ofType(records, "record").map((r) => r.kind)).toEqual([
			"control",
			"invalid",
		]);
		expect(summary.counters).toMatchObject({
			packets: 2,
			control: 1,
			invalid: 1,
		});
		expect(sumOf(summary.counters)).toBe(summary.counters.datagrams);
		expect(summary.protocols).toEqual({ ethernet: 2, ipv4: 2, icmp: 2 });
		expect(summary.conversations.top).toEqual([
			{
				protocol: "icmp",
				a: "10.0.2.15",
				b: "10.0.2.3",
				packets: 2,
				bytes: 140,
			},
		]);
		expect(summary.senders.top[0]?.listener).toBe(String(portOf(stream)));
		await expectPortFree(portOf(stream));
	});

	test("the header says what runs: listeners, limits, queue, detail", async () => {
		const stream = await openCapture({
			ports: [{ port: 0, label: "r1" }],
			count: 5,
			idleMs: 1000,
			expect: 2,
			detail: "layers",
			queue: { datagrams: 7 },
		});
		stream.listener.close();
		expect(stream.header).toMatchObject({
			type: "header",
			schemaVersion: 1,
			tool: "tzsp-sniff",
			bind: "0.0.0.0",
			listeners: [{ port: portOf(stream), label: "r1" }],
			limits: { count: 5, idleMs: 1000, expect: 2 },
			queue: { datagrams: 7, bytes: 16 * 1024 * 1024 },
			detail: "layers",
			stats: false,
		});
		await stream.listener.closed;
	});

	test("nothing arrived: capture/no-datagrams before a complete summary", async () => {
		const { records, summary } = await readAll({ durationMs: 50 });
		expect(summary).toMatchObject({
			status: "complete",
			stoppedBy: "duration",
		});
		const warnings = ofType(records, "warning");
		expect(warnings.map((w) => w.code)).toEqual(["capture/no-datagrams"]);
		expect(warnings[0]?.fix).toContain(
			"/tool/sniffer/set streaming-enabled=yes",
		);
		expect(records.at(-2)).toBe(warnings[0] as WarningRecord);
	});

	test("only control and invalid records: capture/no-frames", async () => {
		const { records } = await readAll({ idleMs: 150 }, (s) =>
			send(portOf(s), [KEEPALIVE, INVALID]),
		);
		expect(ofType(records, "warning").map((w) => w.code)).toEqual([
			"capture/no-frames",
		]);
	});

	test("--idle counts from the last datagram, not from the bind", async () => {
		let sending: Promise<void> = Promise.resolve();
		const { stream, summary } = await readAll({ idleMs: 150 }, async (s) => {
			// Sent while the next read is pending, 100 ms after the bind: idle
			// must move to 150 ms after this arrival, not stop at 150 ms.
			sending = new Promise((resolve, reject) =>
				setTimeout(() => send(portOf(s), [REQUEST]).then(resolve, reject), 100),
			);
		});
		await sending;
		expect(summary).toMatchObject({ status: "complete", stoppedBy: "idle" });
		expect(summary.counters.packets).toBe(1);
		// Measured from the arrival the listener saw, not from when the test sent.
		const arrival = stream.listener.lastArrival as number;
		const stoppedAt = stream.listener.endedAt as number;
		expect(arrival - stream.listener.boundAt).toBeGreaterThanOrEqual(90);
		expect(stoppedAt - arrival).toBeGreaterThanOrEqual(140);
	});

	test("a wall-clock step back changes neither the idle stop nor the duration", async () => {
		const realNow = Date.now;
		const started = performance.now();
		try {
			const { summary } = await readAll({ idleMs: 30 }, async () => {
				// As if NTP stepped the clock 2 s back just after the bind.
				Date.now = () => realNow() - 2000;
			});
			expect(summary.stoppedBy).toBe("idle");
			// It stopped about 30 ms after the bind, not 2 s later.
			expect(performance.now() - started).toBeLessThan(1000);
			expect(summary.durationMs).toBeGreaterThanOrEqual(25);
			expect(summary.durationMs).toBeLessThan(1000);
		} finally {
			Date.now = realNow;
		}
	});

	test("--expect unmet: status error, the code, and the empty case", async () => {
		const { summary } = await readAll({ durationMs: 50, expect: 1 });
		expect(summary.status).toBe("error");
		expect(summary.error).toMatchObject({
			code: "capture/expect-unmet",
			case: "capture/no-datagrams",
		});
		expect(summary.error?.fix).toContain("/tool/sniffer/start");
	});

	test("--expect met: complete", async () => {
		const { summary } = await readAll({ count: 1, expect: 1 }, (s) =>
			send(portOf(s), [REQUEST]),
		);
		expect(summary.status).toBe("complete");
		expect(summary.error).toBeUndefined();
	});

	test("an abort ends it as interrupted, with the summary", async () => {
		const controller = new AbortController();
		const { summary } = await readAll(
			{ signal: controller.signal },
			async () => {
				setTimeout(() => controller.abort(), 30);
			},
		);
		expect(summary).toMatchObject({
			status: "interrupted",
			stoppedBy: "interrupt",
		});
	});

	test("an abort with --expect unmet is still an error", async () => {
		const controller = new AbortController();
		const { summary } = await readAll(
			{ signal: controller.signal, expect: 3 },
			async () => {
				setTimeout(() => controller.abort(), 30);
			},
		);
		expect(summary).toMatchObject({ status: "error", stoppedBy: "interrupt" });
	});

	test("drops: a capture/dropped warning and an incomplete summary", async () => {
		const stream = await openCapture({
			ports: [{ port: 0 }],
			queue: { datagrams: 1 },
			idleMs: 100,
		});
		const records: StreamRecord[] = [];
		for await (const record of stream) {
			records.push(record);
			if (record.type === "header") {
				// Not reading while they arrive: one fits, four are dropped.
				await send(portOf(stream), [
					REQUEST,
					REQUEST,
					REQUEST,
					REQUEST,
					REQUEST,
				]);
				await until(() => stream.listener.counters.received === 5);
			}
		}
		const summary = records.at(-1) as SummaryRecord;
		expect(summary.status).toBe("incomplete");
		expect(summary.counters).toMatchObject({
			datagrams: 5,
			packets: 1,
			dropped: 4,
		});
		expect(sumOf(summary.counters)).toBe(5);
		expect(ofType(records, "warning").map((w) => w.code)).toEqual([
			"capture/dropped",
		]);
	});

	test("filters: removed frames are counted as filtered, and the header lists the filters", async () => {
		const { stream, records, summary } = await readAll(
			{ idleMs: 150, filter: { proto: ["TCP"], not: { host: ["10.9.9.9"] } } },
			(s) => send(portOf(s), [REQUEST, SSH, KEEPALIVE, STREAM[1] as string]),
		);
		expect(stream.header.filters).toEqual({
			proto: ["tcp"],
			not: { host: ["10.9.9.9"] },
		});
		// Only the TCP frame is reported; the keepalive is not a frame, and
		// filters do not apply to it.
		expect(ofType(records, "packet").map((p) => p.seq)).toEqual([2]);
		expect(ofType(records, "record").map((r) => r.seq)).toEqual([3]);
		expect(summary.counters).toMatchObject({
			datagrams: 4,
			packets: 1,
			control: 1,
			filtered: 2,
		});
		expect(sumOf(summary.counters)).toBe(4);
		// The tables count what was reported; senders count every datagram.
		expect(summary.protocols).toEqual({ ethernet: 1, ipv4: 1, tcp: 1 });
		expect(summary.conversations.top.map((c) => c.protocol)).toEqual(["tcp"]);
		expect(summary.senders.top[0]?.datagrams).toBe(4);
		expect(ofType(records, "warning")).toEqual([]);
	});

	test("no filters: the header says so with an empty spec", async () => {
		const stream = await openCapture({ ports: [{ port: 0 }] });
		stream.listener.close();
		expect(stream.header.filters).toEqual({});
		await stream.listener.closed;
	});

	test("--count counts after filters", async () => {
		const { records, summary } = await readAll(
			{ count: 2, durationMs: 5000, filter: { portMatch: [22] } },
			(s) => send(portOf(s), [REQUEST, SSH, REQUEST, REQUEST, SSH, SSH]),
		);
		expect(summary).toMatchObject({ status: "complete", stoppedBy: "count" });
		expect(ofType(records, "packet").map((p) => p.seq)).toEqual([2, 5]);
		expect(summary.counters).toMatchObject({ packets: 2, filtered: 3 });
	});

	test("filters removed every frame: capture/all-filtered names them, and --expect carries the case", async () => {
		const { records, summary } = await readAll(
			{
				idleMs: 150,
				expect: 1,
				filter: { portMatch: [443], not: { proto: ["arp"] } },
			},
			(s) => send(portOf(s), [REQUEST, KEEPALIVE, SSH]),
		);
		const warnings = ofType(records, "warning");
		expect(warnings.map((w) => w.code)).toEqual(["capture/all-filtered"]);
		expect(warnings[0]?.message).toContain("2 frames");
		expect(warnings[0]?.message).toContain("--port-match 443 --not-proto arp");
		expect(warnings[0]?.fix).toContain("--port-match 443 --not-proto arp");
		expect(summary.counters).toMatchObject({
			packets: 0,
			filtered: 2,
			control: 1,
		});
		expect(summary.status).toBe("error");
		expect(summary.error).toMatchObject({
			code: "capture/expect-unmet",
			case: "capture/all-filtered",
			fix: warnings[0]?.fix,
		});
	});

	test("a filter it cannot read is refused before any socket opens", async () => {
		// The port is taken: a bind first would fail with listen/bind-failed.
		const held = await holdPort();
		try {
			const error = await openCapture({
				ports: [{ port: held.port }],
				filter: { host: ["nope"] },
			}).catch((e: unknown) => e);
			expect(error).toMatchObject({ code: "filter/invalid-value" });
		} finally {
			await closeSocket(held.socket);
		}
	});

	test("stats: no packet records, the same summary", async () => {
		const { records, summary } = await readAll({ count: 2, stats: true }, (s) =>
			send(portOf(s), [REQUEST, KEEPALIVE, REQUEST]),
		);
		expect(records.map((r) => r.type)).toEqual(["header", "summary"]);
		expect(summary.counters).toMatchObject({ packets: 2, control: 1 });
	});

	test("detail levels add fields in order: line < summary < layers < full", async () => {
		const shapes: Record<string, string[]> = {};
		for (const detail of ["line", "summary", "layers", "full"] as const) {
			const { records } = await readAll({ count: 1, detail }, (s) =>
				send(portOf(s), [REQUEST]),
			);
			const packet = ofType(records, "packet")[0] as PacketRecord;
			shapes[detail] = Object.keys(packet);
			if (detail === "full") expect(packet.datagram).toBe(REQUEST);
			if (detail === "layers") {
				// Offsets index the datagram: the TZSP header is 5 bytes.
				// The TZSP layer spans the whole datagram, so the frame's layers
				// lie inside it.
				expect(
					packet.layers?.map((l) => [l.protocol, l.offset, l.length]),
				).toEqual([
					["tzsp", 0, 75],
					["ethernet", 5, 70],
					["ipv4", 19, 56],
					["icmp", 39, 36],
				]);
				expect(packet.layers?.[0]?.fields).toMatchObject({ headerLength: 5 });
			}
		}
		expect(shapes.line).toEqual(["type", "seq", "time", "listener", "line"]);
		expect(shapes.summary).toEqual([
			...(shapes.line ?? []),
			"peer",
			"length",
			"protocols",
			"src",
			"dst",
		]);
		expect(shapes.layers).toEqual([...(shapes.summary ?? []), "layers"]);
		expect(shapes.full).toEqual([...(shapes.layers ?? []), "datagram"]);
	});

	test("a consumer that stops early gets no summary, and the port is freed", async () => {
		const stream = await openCapture({ ports: [{ port: 0 }] });
		for await (const record of stream) {
			expect(record.type).toBe("header");
			break;
		}
		await stream.listener.closed;
		await expectPortFree(portOf(stream));
	});

	test("invalid limits are refused", async () => {
		for (const options of [
			{ count: 0 },
			{ durationMs: -1 },
			{ idleMs: 1.5 },
			{ expect: 0 },
		]) {
			const error = await openCapture(options).catch((e: unknown) => e);
			expect(error).toBeInstanceOf(TzspSniffError);
			expect((error as TzspSniffError).code).toBe("listen/invalid-option");
		}
	});

	test("return() while a read is pending ends it and frees the port; so does return() before the first read", async () => {
		const pendingStream = await openCapture({ ports: [{ port: 0 }] });
		const it = pendingStream[Symbol.asyncIterator]();
		expect((await it.next()).value?.type).toBe("header");
		const pending = it.next();
		const returned = it.return?.();
		// The pending read gets the end of the stream; nothing is left waiting.
		await pending;
		await returned;
		await pendingStream.listener.closed;
		await expectPortFree(portOf(pendingStream));

		const unread = await openCapture({ ports: [{ port: 0 }] });
		await unread[Symbol.asyncIterator]().return?.();
		await unread.listener.closed;
		await expectPortFree(portOf(unread));
	});

	test("a capture is read once: a second iterator is refused", async () => {
		const stream = await openCapture({ ports: [{ port: 0 }] });
		stream[Symbol.asyncIterator]();
		expect(() => stream[Symbol.asyncIterator]()).toThrow(
			expect.objectContaining({ code: "capture/reused" }),
		);
		stream.listener.close();
		await stream.listener.closed;
	});

	test("a met count stops intake before the entry is handed over, and an abort after it does not change why", async () => {
		const controller = new AbortController();
		const stream = await openCapture({
			ports: [{ port: 0 }],
			count: 1,
			signal: controller.signal,
		});
		const it = stream[Symbol.asyncIterator]();
		await it.next(); // header
		await send(portOf(stream), [REQUEST]);
		expect((await it.next()).value?.type).toBe("packet");
		// Holding the entry: the listener is already closed.
		expect(stream.listener.ended).toBe("closed");
		await send(portOf(stream), [REQUEST]).catch(() => {});
		controller.abort();
		const rest: StreamRecord[] = [];
		for (let r = await it.next(); !r.done; r = await it.next())
			rest.push(r.value);
		const summary = rest.at(-1) as SummaryRecord;
		expect(summary).toMatchObject({ status: "complete", stoppedBy: "count" });
		expect(summary.counters.datagrams).toBe(1);
	});

	test("limits run from the bind: an unread stream still stops on time", async () => {
		const stream = await openCapture({ ports: [{ port: 0 }], durationMs: 25 });
		await stream.listener.closed;
		expect(stream.listener.ended).toBe("closed");
		await expectPortFree(portOf(stream));
		const records: StreamRecord[] = [];
		for await (const r of stream) records.push(r);
		expect(records.at(-1)).toMatchObject({
			type: "summary",
			stoppedBy: "duration",
		});
	});

	test("durations past the timer ceiling are refused", async () => {
		for (const options of [{ durationMs: 2 ** 31 }, { idleMs: 2 ** 31 }]) {
			const error = await openCapture(options).catch((e: unknown) => e);
			expect((error as TzspSniffError).code).toBe("listen/invalid-option");
		}
	});

	test("only dropped datagrams: --expect names capture/dropped as the case", async () => {
		const { records, summary } = await readAll(
			{ queue: { bytes: 1 }, idleMs: 80, expect: 1 },
			(s) => send(portOf(s), [REQUEST]),
		);
		expect(ofType(records, "warning").map((w) => w.code)).toEqual([
			"capture/dropped",
		]);
		expect(summary.error).toMatchObject({
			code: "capture/expect-unmet",
			case: "capture/dropped",
		});
	});

	test("datagrams that arrived but were never read: capture/unread", async () => {
		const stream = await openCapture({ ports: [{ port: 0 }], durationMs: 60 });
		const it = stream[Symbol.asyncIterator]();
		await it.next(); // header, then hold the stream while the limit passes
		await send(portOf(stream), [REQUEST]);
		await stream.listener.closed;
		const rest: StreamRecord[] = [];
		for (let r = await it.next(); !r.done; r = await it.next())
			rest.push(r.value);
		expect(ofType(rest, "warning").map((w) => w.code)).toEqual([
			"capture/unread",
		]);
		expect((rest.at(-1) as SummaryRecord).counters).toMatchObject({
			datagrams: 1,
			unread: 1,
		});
	});

	test("the stream's listener cannot be read past the capture", async () => {
		const stream = await openCapture({
			ports: [{ port: 0 }],
			durationMs: 5000,
		});
		try {
			expect(Symbol.asyncIterator in stream.listener).toBe(false);
			// @ts-expect-error: the type has no iterator either.
			stream.listener[Symbol.asyncIterator];
		} finally {
			stream.listener.close();
			await stream.listener.closed;
		}
	});

	test("an aborted capture nobody reads leaves no timer behind", async () => {
		// Bun's process.getActiveResourcesInfo() lists no timers, so watch the
		// effect instead: a leaked 60 s timer keeps the process alive.
		const script = `
			import { openCapture } from ${JSON.stringify(join(import.meta.dir, "../../src/capture.ts"))};
			const controller = new AbortController();
			const stream = await openCapture({
				ports: [{ port: 0 }],
				durationMs: 60_000,
				idleMs: 60_000,
				signal: controller.signal,
			});
			controller.abort();
			await stream.listener.closed;
		`;
		const child = Bun.spawn([process.execPath, "--no-env-file", "-e", script], {
			env: childEnv(),
			stdout: "ignore",
			stderr: "pipe",
		});
		const timer = setTimeout(() => child.kill(), 5000);
		try {
			expect(await child.exited).toBe(0);
			expect(child.signalCode).toBeNull();
		} finally {
			clearTimeout(timer);
		}
	});

	test("an abort ends intake for good: a duration that fires later does not become the reason", async () => {
		const controller = new AbortController();
		const stream = await openCapture({
			ports: [{ port: 0 }],
			durationMs: 40,
			signal: controller.signal,
		});
		controller.abort();
		await new Promise((r) => setTimeout(r, 80));
		const records: StreamRecord[] = [];
		for await (const r of stream) records.push(r);
		const summary = records.at(-1) as SummaryRecord;
		expect(summary).toMatchObject({
			status: "interrupted",
			stoppedBy: "interrupt",
		});
		// The duration runs to the end of intake, not to when the summary was read.
		expect(summary.durationMs).toBeLessThan(40);
	});

	test("a socket error nobody read yet is the reason, even after the duration passes", async () => {
		const sockets: Socket[] = [];
		const stream = await openCapture(
			{ ports: [{ port: 0 }], durationMs: 40 },
			{
				createSocket: ((options: SocketOptions) => {
					const socket = createSocket(options);
					sockets.push(socket);
					return socket;
				}) as typeof createSocket,
			},
		);
		sockets[0]?.emit("error", new Error("injected"));
		await new Promise((r) => setTimeout(r, 80));
		const records: StreamRecord[] = [];
		for await (const r of stream) records.push(r);
		expect(records.at(-1)).toMatchObject({
			status: "error",
			stoppedBy: "error",
			error: { code: "listen/socket-error" },
		});
	});

	test("control records plus dropped datagrams: no capture/no-frames, and the case is capture/dropped", async () => {
		const stream = await openCapture({
			ports: [{ port: 0 }],
			queue: { datagrams: 1 },
			idleMs: 80,
			expect: 1,
		});
		const records: StreamRecord[] = [];
		for await (const record of stream) {
			records.push(record);
			if (record.type === "header") {
				// One keepalive fits; the frames after it are dropped unread.
				await send(portOf(stream), [KEEPALIVE, REQUEST, REQUEST]);
				await until(() => stream.listener.counters.received === 3);
			}
		}
		expect(ofType(records, "warning").map((w) => w.code)).toEqual([
			"capture/dropped",
		]);
		expect((records.at(-1) as SummaryRecord).error).toMatchObject({
			code: "capture/expect-unmet",
			case: "capture/dropped",
		});
	});
});
