/**
 * A capture: the listener, dissection, limits, counters and the summary,
 * as one stream of records (DESIGN.md, "Counters and --expect", "Stream
 * termination"). The CLI prints this stream; any other surface is an
 * adapter over it, not a second implementation.
 */
import { dissect } from "./dissect.ts";
import { TzspSniffError } from "./errors.ts";
import { type Listener, type ListenOptions, listen } from "./listen.ts";
import {
	type Counters,
	type DatagramRecord,
	type Detail,
	datagramRecord,
	type HeaderRecord,
	isoTime,
	type PacketRecord,
	packetRecord,
	SCHEMA_VERSION,
	type StopReason,
	type StreamRecord,
	type SummaryRecord,
	type SummaryStatus,
	viewPacket,
	type WarningRecord,
} from "./records.ts";
import { summarize } from "./summary.ts";
import { VERSION } from "./version.ts";

export interface CaptureOptions extends ListenOptions {
	/** Stop after this many packets are reported. */
	count?: number;
	/** Stop this long after the sockets are bound. */
	durationMs?: number;
	/** Stop when nothing has arrived for this long, counted from the bind. */
	idleMs?: number;
	/** Fewer packets reported than this makes the summary an error. */
	expect?: number;
	/** How much each packet record carries (default `summary`). */
	detail?: Detail;
	/** Report only the summary: no packet or record entries. */
	stats?: boolean;
}

export interface CaptureStream extends AsyncIterable<StreamRecord> {
	readonly header: HeaderRecord;
	readonly listener: Listener;
}

const positive = (name: string, value: number | undefined) => {
	if (value !== undefined && (!Number.isInteger(value) || value < 1)) {
		throw new TzspSniffError(
			"listen/invalid-option",
			`${name} must be a positive integer, not ${value}.`,
			`Leave ${name} unset, or give a whole number above 0.`,
		);
	}
};

const seconds = (ms: number) => `${(ms / 1000).toFixed(1)}s`;

/**
 * Bind the listeners and return the capture's record stream. Iterating it
 * yields the `header` first and, unless the caller stops early, exactly one
 * `summary` last. Bind failures and invalid options reject here, before any
 * record.
 */
export async function openCapture(
	options: CaptureOptions = {},
): Promise<CaptureStream> {
	const { count, durationMs, idleMs, expect } = options;
	positive("count", count);
	positive("durationMs", durationMs);
	positive("idleMs", idleMs);
	positive("expect", expect);
	const detail = options.detail ?? "summary";
	const statsOnly = options.stats ?? false;
	const listener = await listen(options);

	const limits: HeaderRecord["limits"] = {};
	if (count !== undefined) limits.count = count;
	if (durationMs !== undefined) limits.durationMs = durationMs;
	if (idleMs !== undefined) limits.idleMs = idleMs;
	if (expect !== undefined) limits.expect = expect;
	const header: HeaderRecord = {
		type: "header",
		schemaVersion: SCHEMA_VERSION,
		tool: "tzsp-sniff",
		version: VERSION,
		time: isoTime(listener.boundAt),
		bind: listener.bind,
		listeners: listener.listeners.map(({ port, label }) => ({ port, label })),
		limits,
		queue: { ...listener.queue },
		detail,
		stats: statsOnly,
	};

	async function* run(): AsyncGenerator<StreamRecord> {
		const counters: Counters = {
			datagrams: 0,
			packets: 0,
			control: 0,
			unsupported: 0,
			invalid: 0,
			filtered: 0,
			dropped: 0,
			unread: 0,
		};
		const stats = summarize();
		const timers: ReturnType<typeof setTimeout>[] = [];
		let stoppedBy: StopReason | undefined;
		let failure: TzspSniffError | undefined;
		let dropWarned = false;
		const stop = (why: StopReason) => {
			stoppedBy ??= why;
			listener.close();
		};
		const dropWarning = (): WarningRecord => ({
			type: "warning",
			code: "capture/dropped",
			message: `The queue (${listener.queue.datagrams} datagrams, ${listener.queue.bytes} bytes) filled, and datagrams are being dropped; the summary counts them.`,
			fix: "Print less per packet (--stats or --detail line), or read the output faster.",
		});

		try {
			yield header;
			if (durationMs !== undefined) {
				timers.push(setTimeout(() => stop("duration"), durationMs));
			}
			if (idleMs !== undefined) {
				const check = () => {
					const last = listener.lastArrival ?? listener.boundAt;
					const left = last + idleMs - Date.now();
					if (left <= 0) stop("idle");
					else timers.push(setTimeout(check, left));
				};
				timers.push(setTimeout(check, idleMs));
			}
			try {
				for await (const capture of listener) {
					stats.addDatagram(capture);
					let record: PacketRecord | DatagramRecord | undefined;
					if (capture.tzsp.kind === "packet") {
						const d = dissect(capture.tzsp.payload);
						const view = viewPacket(d);
						counters.packets += 1;
						stats.addPacket(d, view);
						if (!statsOnly)
							record = packetRecord(capture, d, detail, undefined, view);
					} else {
						counters[capture.tzsp.kind] += 1;
						if (!statsOnly) record = datagramRecord(capture, detail);
					}
					if (record) yield record;
					if (!dropWarned && listener.counters.dropped > 0) {
						dropWarned = true;
						yield dropWarning();
					}
					if (count !== undefined && counters.packets >= count) {
						stop("count");
						break;
					}
				}
			} catch (error) {
				if (!(error instanceof TzspSniffError)) throw error;
				failure = error;
				stoppedBy = "error";
			}
		} finally {
			for (const timer of timers) clearTimeout(timer);
			listener.close();
		}

		// The listener ended through its signal, or someone closed it.
		stoppedBy ??= "interrupt";
		counters.datagrams = listener.counters.received;
		counters.dropped = listener.counters.dropped;
		counters.unread = listener.counters.queued;
		if (!dropWarned && counters.dropped > 0) yield dropWarning();

		let emptyCase: WarningRecord | undefined;
		if (!failure && counters.packets === 0) {
			const where = listener.listeners
				.map((l) => `${listener.bind}:${l.port}`)
				.join(", ");
			const elapsed = seconds(Date.now() - listener.boundAt);
			if (counters.datagrams === 0) {
				const port = listener.listeners[0]?.port;
				emptyCase = {
					type: "warning",
					code: "capture/no-datagrams",
					message: `No datagrams arrived on ${where} in ${elapsed}.`,
					fix: `Point the router here and start it: /tool/sniffer/set streaming-enabled=yes streaming-server=<this host>:${port}, then /tool/sniffer/start (a quickchr CHR reaches the host at 10.0.2.2).`,
				};
			} else if (
				counters.control + counters.unsupported + counters.invalid >
				0
			) {
				emptyCase = {
					type: "warning",
					code: "capture/no-frames",
					message: `${counters.datagrams} datagrams arrived on ${where}, but none was a TZSP Ethernet frame.`,
					fix: "Run again with --detail full to see each record's bytes.",
				};
			}
			if (emptyCase) yield emptyCase;
		}
		if (!failure && expect !== undefined && counters.packets < expect) {
			failure = new TzspSniffError(
				"capture/expect-unmet",
				`Expected at least ${expect} packets; ${counters.packets} were reported.`,
				emptyCase?.fix ??
					"Check the router's sender and the limits, then run again.",
			);
		}

		let status: SummaryStatus = "complete";
		if (failure) status = "error";
		else if (counters.dropped > 0) status = "incomplete";
		else if (stoppedBy === "interrupt") status = "interrupted";
		const summary: SummaryRecord = {
			type: "summary",
			status,
			stoppedBy,
			durationMs: Date.now() - listener.boundAt,
			counters,
			...stats.tables(),
		};
		if (failure) {
			summary.error = { code: failure.code, message: failure.message };
			if (failure.fix) summary.error.fix = failure.fix;
			if (emptyCase && failure.code === "capture/expect-unmet") {
				summary.error.case = emptyCase.code;
			}
		}
		yield summary;
	}

	return {
		header,
		listener,
		[Symbol.asyncIterator]: run,
	};
}
