/**
 * A capture: the listener, dissection, limits, counters and the summary,
 * as one stream of records (DESIGN.md, "Counters and --expect", "Stream
 * termination"). The CLI prints this stream; any other surface is an
 * adapter over it, not a second implementation.
 */
import { dissect } from "./dissect.ts";
import { type Code, TzspSniffError } from "./errors.ts";
import { createFilter, type FilterSpec } from "./filter.ts";
import {
	type ListenInternals,
	type Listener,
	type ListenOptions,
	listen,
} from "./listen.ts";
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
import { type CaptureWriter, wasAlreadyOpened } from "./pcapng.ts";
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
	/**
	 * Keep only the frames this spec matches; the rest are counted in
	 * `filtered`. Control, unsupported and invalid records are not frames,
	 * and filters do not apply to them.
	 */
	filter?: FilterSpec;
	/**
	 * Saves every datagram the capture reads, as it was received and before
	 * filters, whatever the stream reports (`--write`). Its target is in the
	 * header and its counts in the summary.
	 */
	write?: CaptureWriter;
	/**
	 * Saves each datagram the stream reports: the frames the filters keep,
	 * and every control, unsupported and invalid record (`--format pcapng`).
	 */
	writeReported?: CaptureWriter;
}

/**
 * A bound capture. Read it once: a second iterator is refused with
 * `capture/reused`. Its limits run from the bind, whether or not it is
 * being read; stopping early (`break`, `return()`) closes the sockets even
 * while a read is pending or before the first one.
 */
/**
 * The capture's listener without its datagram iterator: only the capture
 * reads the queue, so every datagram is counted in its summary.
 */
export type CaptureListener = Omit<Listener, typeof Symbol.asyncIterator>;

export interface CaptureStream extends AsyncIterable<StreamRecord> {
	readonly header: HeaderRecord;
	readonly listener: CaptureListener;
}

/** The longest delay timers take on Node and Bun (2^31 - 1 ms, about 24.8 days). */
export const MAX_TIMER_MS = 2_147_483_647;

const positive = (
	name: string,
	value: number | undefined,
	max = Number.MAX_SAFE_INTEGER,
) => {
	if (
		value !== undefined &&
		(!Number.isInteger(value) || value < 1 || value > max)
	) {
		throw new TzspSniffError(
			"listen/invalid-option",
			`${name} must be a whole number from 1 to ${max}, not ${value}.`,
			`Leave ${name} unset, or give a whole number in that range.`,
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
	/** For tests only; see {@link ListenInternals}. */
	internals: ListenInternals = {},
): Promise<CaptureStream> {
	const { count, durationMs, idleMs, expect } = options;
	positive("count", count);
	positive("durationMs", durationMs, MAX_TIMER_MS);
	positive("idleMs", idleMs, MAX_TIMER_MS);
	positive("expect", expect);
	const detail = options.detail ?? "summary";
	const statsOnly = options.stats ?? false;
	// Checked before the bind, so a bad spec opens no socket.
	const filter = createFilter(options.filter);
	const listener = await listen(options, internals);
	const writers = [options.write, options.writeReported].filter(
		(w): w is CaptureWriter => w !== undefined,
	);
	if (writers.length === 2 && writers[0] === writers[1]) {
		listener.close();
		await listener.closed;
		throw new TzspSniffError(
			"listen/invalid-option",
			"write and writeReported are the same writer.",
			"Give each its own writer, or leave one out.",
		);
	}

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
		time: isoTime(Date.now()),
		bind: listener.bind,
		listeners: listener.listeners.map(({ port, label }) => ({ port, label })),
		limits,
		filters: filter.spec,
		queue: { ...listener.queue },
		detail,
		stats: statsOnly,
	};
	if (options.write) header.write = options.write.target;

	// The limits run from the bind, not from the first read, so a caller that
	// is slow to start reading still gets its sockets closed on time.
	let stoppedBy: StopReason | undefined;
	let durationTimer: ReturnType<typeof setTimeout> | undefined;
	let idleTimer: ReturnType<typeof setTimeout> | undefined;
	const clearTimers = () => {
		clearTimeout(durationTimer);
		clearTimeout(idleTimer);
	};
	/** End intake for `why`, unless something else already ended it. */
	const stop = (why: StopReason) => {
		if (listener.ended) return;
		stoppedBy = why;
		clearTimers();
		listener.close();
	};
	// However the listener ends (an abort, a socket error, close()), its
	// timers go with it, whether or not anyone is reading the stream.
	void listener.closed.then(clearTimers);
	if (durationMs !== undefined) {
		durationTimer = setTimeout(
			() => stop("duration"),
			Math.max(0, listener.boundAt + durationMs - performance.now()),
		);
	}
	if (idleMs !== undefined) {
		// One timer, moved forward to the last arrival each time it fires early.
		const check = () => {
			const last = listener.lastArrival ?? listener.boundAt;
			const left = last + idleMs - performance.now();
			if (left <= 0) stop("idle");
			else idleTimer = setTimeout(check, left);
		};
		idleTimer = setTimeout(
			check,
			Math.max(0, listener.boundAt + idleMs - performance.now()),
		);
	}

	// After the bind, so a port that fails leaves no file; before the header,
	// so a file that cannot be made opens no capture. The limits are already
	// running. Only a writer this capture opened, or began to, is closed on
	// failure: one refused because another capture holds it stays as it was.
	const acquired: CaptureWriter[] = [];
	try {
		for (const w of writers) {
			try {
				await w.open(listener.listeners);
				acquired.push(w);
			} catch (error) {
				if (!wasAlreadyOpened(error)) acquired.push(w);
				throw error;
			}
		}
	} catch (error) {
		listener.close();
		// As at the end of a capture: a writer that failed to close outranks
		// the reason opening stopped (a closed stdout must not hide it).
		let closeFailure: unknown;
		// A close that throws instead of rejecting must not skip the others.
		await Promise.all(
			acquired.map((w) =>
				(async () => w.close())().catch((closeError: unknown) => {
					if (closeError instanceof TzspSniffError) closeFailure ??= closeError;
				}),
			),
		);
		await listener.closed;
		if (closeFailure instanceof TzspSniffError) throw closeFailure;
		throw error;
	}

	/**
	 * Close every writer, each once; the first failure is returned, not
	 * thrown, so one writer's failure does not skip closing another.
	 */
	/** The writes of the datagram being saved, settled or not. */
	let inWrite: Promise<void> | undefined;
	let writersClosed: Promise<unknown> | undefined;
	const closeWriters = () => {
		writersClosed ??= (async () => {
			let first: unknown;
			for (const w of writers) {
				try {
					await w.close();
				} catch (error) {
					first ??= error;
				}
			}
			return first;
		})();
		return writersClosed;
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
			unsaved: 0,
		};
		const stats = summarize();
		let failure: TzspSniffError | undefined;
		/** How intake had ended when a save failed, if it had. */
		let endedBeforeFailure: CaptureListener["ended"];
		let escaping: { error: unknown } | undefined;
		let dropWarned = false;
		const dropWarning = (): WarningRecord => ({
			type: "warning",
			code: "capture/dropped",
			message: `The queue (${listener.queue.datagrams} datagrams, ${listener.queue.bytes} bytes) filled, and datagrams are being dropped; the summary counts them.`,
			fix: "Print less per packet (--stats or --detail line), or read the output faster.",
		});

		try {
			yield header;
			try {
				for await (const capture of listener) {
					const d =
						capture.tzsp.kind === "packet"
							? dissect(capture.tzsp.payload)
							: undefined;
					const kept = d === undefined || filter(capture, d);
					// Saved before it is counted or handed over: a record the caller
					// sees is already in the file, and a datagram whose save failed
					// is counted once, as unsaved.
					if (writers.length) {
						const saving = (async () => {
							await options.write?.write(capture);
							if (kept) await options.writeReported?.write(capture);
						})();
						inWrite = saving.then(
							() => {},
							() => {},
						);
						try {
							await saving;
						} catch (error) {
							counters.unsaved += 1;
							// Read now: leaving the loop closes the listener itself.
							endedBeforeFailure = listener.ended;
							throw error;
						} finally {
							inWrite = undefined;
						}
					}
					stats.addDatagram(capture);
					let record: PacketRecord | DatagramRecord | undefined;
					if (d) {
						if (kept) {
							const view = viewPacket(d);
							counters.packets += 1;
							stats.addPacket(d, view);
							if (!statsOnly)
								record = packetRecord(capture, d, detail, undefined, view);
						} else {
							counters.filtered += 1;
						}
					} else {
						const kind = capture.tzsp.kind as Exclude<
							typeof capture.tzsp.kind,
							"packet"
						>;
						counters[kind] += 1;
						if (!statsOnly) record = datagramRecord(capture, detail);
					}
					// A limit met by this entry stops intake now, before the entry
					// is handed over: nothing more is received while the caller
					// holds it, and a later abort cannot change why it stopped.
					if (count !== undefined && counters.packets >= count) stop("count");
					if (record) yield record;
					if (!dropWarned && listener.counters.dropped > 0) {
						dropWarned = true;
						yield dropWarning();
					}
				}
			} catch (error) {
				if (!(error instanceof TzspSniffError)) throw error;
				failure = error;
				// A limit or signal that stopped intake first stays the reason:
				// a signal sets no stop reason of its own, so a save that failed
				// after one ended intake leaves it an interrupt.
				stoppedBy ??=
					endedBeforeFailure === "aborted" || endedBeforeFailure === "closed"
						? "interrupt"
						: "error";
			}
		} catch (error) {
			// Not a capture outcome (a consumer's own error, or a sink error with no
			// code, such as a closed stdout): it leaves without a summary.
			escaping = { error };
		} finally {
			clearTimers();
			listener.close();
			// Every way out closes the writers. A caller that stops early gets
			// a close failure from return(), since no summary follows.
			await closeWriters();
		}
		const closeFailure = await closeWriters();
		if (escaping) {
			// A file that failed to close outranks the reason the stream ended:
			// a closed stdout must not hide a capture file that is not whole.
			if (closeFailure instanceof TzspSniffError) throw closeFailure;
			throw escaping.error;
		}
		if (closeFailure !== undefined) {
			if (!(closeFailure instanceof TzspSniffError)) throw closeFailure;
			failure ??= closeFailure;
		}

		// Nothing here stopped it: its signal, a socket error the caller did not
		// read, or the caller closing it.
		stoppedBy ??= listener.ended === "error" ? "error" : "interrupt";
		// The capture's duration ends when intake stopped, not when the caller
		// gets around to the summary.
		const endedAt = listener.endedAt ?? performance.now();
		counters.datagrams = listener.counters.received;
		counters.dropped = listener.counters.dropped;
		counters.unread = listener.counters.queued;
		if (!dropWarned && counters.dropped > 0) yield dropWarning();
		let emptyCase: WarningRecord | undefined;
		let caseCode: Code | undefined;
		if (!failure && counters.packets === 0) {
			const where = listener.listeners
				.map((l) => `${listener.bind}:${l.port}`)
				.join(", ");
			const elapsed = seconds(endedAt - listener.boundAt);
			if (counters.datagrams === 0) {
				const port = listener.listeners[0]?.port;
				emptyCase = {
					type: "warning",
					code: "capture/no-datagrams",
					message: `No datagrams arrived on ${where} in ${elapsed}.`,
					fix: `Point the router here and start it: /tool/sniffer/set streaming-enabled=yes streaming-server=<this host>:${port}, then /tool/sniffer/start (a quickchr CHR reaches the host at 10.0.2.2).`,
				};
			} else if (
				counters.control + counters.unsupported + counters.invalid ===
				counters.datagrams
			) {
				// Every datagram was read, and none was a frame.
				emptyCase = {
					type: "warning",
					code: "capture/no-frames",
					message: `${counters.datagrams} datagrams arrived on ${where}, but none was a TZSP Ethernet frame.`,
					fix: "Run again with --format text or jsonl and --detail full to see each record's bytes.",
				};
			} else if (
				counters.filtered > 0 &&
				counters.dropped === 0 &&
				counters.unread === 0
			) {
				// Every frame was read, and the filters kept none of them. With
				// datagrams dropped or unread, one of those might have matched, so
				// the loss is the diagnosis, not the filters.
				const flags = filter.flags.join(" ");
				emptyCase = {
					type: "warning",
					code: "capture/all-filtered",
					message: `${counters.filtered} frames arrived on ${where} in ${elapsed}, and the filters removed all of them: ${flags}.`,
					fix: `Loosen or drop the filters (${flags}); --stats without them shows what arrived.`,
				};
			} else if (counters.dropped === 0 && counters.unread > 0) {
				const filtered = counters.filtered
					? ` The filters removed the ${counters.filtered} frames that were read.`
					: "";
				emptyCase = {
					type: "warning",
					code: "capture/unread",
					message: `${counters.unread} of the ${counters.datagrams} datagrams that arrived on ${where} were still unread when the capture stopped.${filtered}`,
					fix: "Use a longer limit, or read the output faster.",
				};
			}
			// Datagrams were dropped: the capture/dropped warning above says so.
			caseCode =
				emptyCase?.code ??
				(counters.dropped > 0 ? "capture/dropped" : undefined);
			if (emptyCase) yield emptyCase;
		}
		if (!failure && expect !== undefined && counters.packets < expect) {
			failure = new TzspSniffError(
				"capture/expect-unmet",
				`Expected at least ${expect} packets; ${counters.packets} were reported.`,
				emptyCase?.fix ??
					(caseCode === "capture/dropped"
						? "Print less per packet (--stats or --detail line), or read the output faster."
						: "Check the router's sender and the limits, then run again."),
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
			durationMs: endedAt - listener.boundAt,
			counters,
			...stats.tables(),
		};
		if (options.write) summary.written = { ...options.write.written };
		if (failure) {
			summary.error = { code: failure.code, message: failure.message };
			if (failure.fix) summary.error.fix = failure.fix;
			if (caseCode && failure.code === "capture/expect-unmet") {
				summary.error.case = caseCode;
			}
		}
		yield summary;
	}

	const view: CaptureListener = {
		get bind() {
			return listener.bind;
		},
		get listeners() {
			return listener.listeners;
		},
		get queue() {
			return listener.queue;
		},
		get counters() {
			return listener.counters;
		},
		get boundAt() {
			return listener.boundAt;
		},
		get lastArrival() {
			return listener.lastArrival;
		},
		get ended() {
			return listener.ended;
		},
		get endedAt() {
			return listener.endedAt;
		},
		closed: listener.closed,
		close: () => listener.close(),
	};

	let used = false;
	// Once intake has ended (a limit, a signal, a socket error) and the
	// datagram being saved is saved, nothing more is written: the writers
	// close then, even while nobody reads the stream or the reader is paused
	// at a record. Whoever reads later gets the close's outcome in the
	// summary, or from return().
	void listener.closed.then(async () => {
		await inWrite;
		void closeWriters();
	});
	return {
		header,
		listener: view,
		[Symbol.asyncIterator](): AsyncIterator<StreamRecord> {
			if (used) {
				throw new TzspSniffError(
					"capture/reused",
					"This capture has already been read; a capture is read once.",
					"Call openCapture() again for a new capture.",
				);
			}
			used = true;
			const generator = run();
			// An async generator queues return() behind a pending next(), and
			// never runs its finally when it has not started. Closing the
			// listener first ends a pending read and frees the sockets either way.
			const close = () => {
				clearTimers();
				listener.close();
			};

			// The writers close here too: a generator that never started never
			// runs its finally, and a close failure on an early stop has no
			// summary to go in, so return() rejects with it.
			return {
				next: () => generator.next(),
				return: async (value?: unknown) => {
					close();
					const result = await generator.return(value);
					const failure = await closeWriters();
					if (failure !== undefined) throw failure;
					return result;
				},
				// As return(): queued behind a pending next(), so a write in flight
				// finishes before its writer closes.
				throw: async (error?: unknown) => {
					close();
					try {
						return await generator.throw(error);
					} finally {
						await closeWriters();
					}
				},
			};
		},
	};
}
