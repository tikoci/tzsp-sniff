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
import type { Writable } from "node:stream";
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
									`stdout took no output for ${ms / 1000}s: its reader stopped reading.`,
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
