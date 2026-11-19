/**
 * Output sinks over process streams. One write is in flight at a time and
 * resolves when the stream has taken it, so a slow reader slows the capture
 * loop and the capture's bounded queue absorbs the burst (drops are counted).
 *
 * A reader can stop reading without closing the pipe; then a write never
 * completes. A write that has not completed within `stallMs` (shorter once
 * `signal` fires) fails with `output/stalled`, so the CLI ends with an
 * error instead of hanging (DESIGN.md, "Limits": a sink that stalls past a
 * timeout ends the capture with a coded error).
 */
import { write } from "node:fs";
import { Writable } from "node:stream";
import { TzspSniffError } from "../errors.ts";
import { OutputClosedError, type Sink } from "./main.ts";

export interface StreamSinkOptions {
	/** stdout: failures reject. stderr: failures are skipped, since losing notices must not end a capture. */
	required: boolean;
	/** How long one write may take before it fails as stalled. */
	stallMs: number;
	/** The same, once `signal` has fired: an interrupted capture does not wait long for a stuck reader. */
	graceMs: number;
	signal?: AbortSignal;
	/** Called once, on the first failure of any kind. */
	onFailed?: () => void;
}

export interface StreamSink extends Sink {
	/** The stream failed, closed or stalled: it may never drain. */
	readonly failed: boolean;
}

/** A reader that went away: the quiet case. Anything else is a real write failure. */
const isClosed = (error: Error) => {
	const code = (error as { code?: unknown }).code;
	return code === "EPIPE" || code === "ERR_STREAM_DESTROYED";
};

/**
 * The stream to write a terminal through, so that a terminal that stops
 * reading (Ctrl-S, an unread pane) cannot block the event loop. Node and Bun
 * both write to a TTY with blocking `write()` calls on the main thread, so
 * once the terminal's buffer is full no stall timer, limit or SIGINT
 * handler can run, and the UDP port stays bound (Node 26.12.1, Bun 1.4.4
 * and 1.4.5 on Linux x86_64, an unread PTY; PR #20 review).
 *
 * - Node: the stream's handle has `setBlocking`; with it off, a full
 *   terminal leaves the write pending and `output/stalled` fires as it does
 *   for a pipe. (`fs.write` would not do on Node: its `process.exit()` then
 *   waits for the thread-pool thread stuck in `write()`.)
 * - Bun: 1.4.5 has no handle on a TTY stream, so the writes go through
 *   `fs.write`, which runs on the thread pool; the main thread stays free
 *   and Bun's `process.exit()` does not wait for that thread. Bun
 *   1.4.6-canary.1 has the handle, and there takes Node's route.
 *
 * Not a terminal, or Windows: the stream as it is. Windows is not measured;
 * Node writes a Windows stdout pipe synchronously (BACKLOG.md).
 */
export function terminalStream(
	stream: Writable & { isTTY?: boolean },
	fd: number,
	platform: string = process.platform,
): Writable {
	if (!stream.isTTY || platform === "win32") return stream;
	const handle = (
		stream as { _handle?: { setBlocking?: (blocking: boolean) => unknown } }
	)._handle;
	if (typeof handle?.setBlocking === "function") {
		handle.setBlocking(false);
		return stream;
	}
	return fdStream(fd);
}

/** A Writable over a file descriptor, each chunk written in full with `fs.write`. */
export function fdStream(fd: number): Writable {
	return new Writable({
		write(chunk: Buffer, _encoding, callback) {
			const from = (offset: number) =>
				write(fd, chunk, offset, chunk.length - offset, null, (error, n) => {
					if (error) callback(error);
					else if (offset + n < chunk.length) from(offset + n);
					else callback();
				});
			from(0);
		},
	});
}

export function streamSink(
	stream: Writable,
	options: StreamSinkOptions,
): StreamSink {
	let failure: Error | undefined;
	const fail = (error: Error): Error => {
		if (!failure) {
			failure =
				error instanceof OutputClosedError || error instanceof TzspSniffError
					? error
					: isClosed(error)
						? new OutputClosedError({ cause: error })
						: new TzspSniffError(
								"output/failed",
								`Writing to stdout failed: ${error.message}`,
								"Check where stdout goes (a full disk, a closed file), then run again.",
								{ cause: error },
							);
			options.onFailed?.();
		}
		return failure;
	};
	stream.on("error", (error) => fail(error));
	const settle = () =>
		options.required && failure ? Promise.reject(failure) : Promise.resolve();

	return {
		get failed() {
			return failure !== undefined;
		},
		write(text) {
			if (failure) return settle();
			return new Promise<void>((resolve, reject) => {
				let done = false;
				let timer: ReturnType<typeof setTimeout> | undefined;
				const finish = (error?: Error) => {
					if (done) return;
					done = true;
					clearTimeout(timer);
					options.signal?.removeEventListener("abort", onAbort);
					if (error) fail(error);
					settle().then(resolve, reject);
				};
				const arm = (ms: number) => {
					clearTimeout(timer);
					timer = setTimeout(
						() =>
							finish(
								new TzspSniffError(
									"output/stalled",
									`stdout accepted nothing for ${ms / 1000}s: its reader stopped reading.`,
									"Read the output as it comes (a pipe to a program that reads), or write it to a file.",
								),
							),
						ms,
					);
				};
				const onAbort = () => arm(options.graceMs);
				arm(options.signal?.aborted ? options.graceMs : options.stallMs);
				options.signal?.addEventListener("abort", onAbort, { once: true });
				stream.write(text, (error) => finish(error ?? undefined));
			});
		},
	};
}
