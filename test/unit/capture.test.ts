import { describe, expect, test } from "bun:test";
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
import { expectPortFree, fixture, send, until } from "./helpers.ts";

/**
 * The capture core (DESIGN.md, "Counters and --expect", "Stream
 * termination"): every stream starts with a header and, read to the end,
 * ends with exactly one summary whose counters add up.
 */
const STREAM = fixture("7.25.1-x86-sniffer-stream");
const REQUEST = STREAM[0] as string;
const KEEPALIVE = "01040000";
const INVALID = "02000001";

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
		let sentAt = 0;
		const { stream, summary } = await readAll({ idleMs: 150 }, async (s) => {
			// Sent while the next read is pending, 100 ms after the bind: idle
			// must move to 150 ms after this arrival, not stop at 150 ms.
			setTimeout(() => {
				sentAt = Date.now();
				send(portOf(s), [REQUEST]);
			}, 100);
		});
		expect(summary).toMatchObject({ status: "complete", stoppedBy: "idle" });
		expect(summary.counters.packets).toBe(1);
		const stoppedAt = stream.listener.boundAt + summary.durationMs;
		expect(stoppedAt - sentAt).toBeGreaterThanOrEqual(140);
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

	test("recordLimit stops at that many entries of any kind, as incomplete", async () => {
		const { records, summary } = await readAll(
			{ recordLimit: 2, durationMs: 5000 },
			(s) => send(portOf(s), [KEEPALIVE, KEEPALIVE, KEEPALIVE]),
		);
		expect(ofType(records, "record")).toHaveLength(2);
		expect(ofType(records, "warning").map((w) => w.code)).toContain(
			"capture/record-limit",
		);
		expect(summary).toMatchObject({
			status: "incomplete",
			stoppedBy: "record-limit",
		});
		expect(sumOf(summary.counters)).toBe(summary.counters.datagrams);
	});
});
