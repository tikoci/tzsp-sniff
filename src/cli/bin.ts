#!/usr/bin/env node
/**
 * The `tzsp-sniff` executable: wires the process's streams and signals to
 * `main()`. It reads no environment variables yet, so a working directory's
 * `.env`, which Bun loads, changes nothing (DESIGN.md, "Decided: Node and
 * npx").
 */
import { type Io, main, OutputClosedError, type Sink } from "./main.ts";

/**
 * A sink over a process stream: one write in flight, resolved when the stream
 * has taken it, so a slow reader slows the loop and the capture's queue
 * absorbs the burst. Once the stream fails, `onClosed` runs and writes reject
 * (stdout) or are skipped (stderr: losing notices must not end the capture).
 */
function streamSink(
	stream: NodeJS.WriteStream,
	onClosed: () => void,
	required: boolean,
): Sink {
	let failed: Error | undefined;
	stream.on("error", (error) => {
		failed ??= error;
		onClosed();
	});
	const fail = (error: Error) =>
		required
			? Promise.reject(new OutputClosedError({ cause: error }))
			: Promise.resolve();
	return {
		write(text) {
			if (failed) return fail(failed);
			return new Promise<void>((resolve) => {
				stream.write(text, (error) => {
					if (error) {
						failed ??= error;
						resolve(fail(error));
					} else resolve();
				});
			});
		},
	};
}

const interrupt = new AbortController();
let interrupts = 0;
const onSignal = () => {
	interrupts += 1;
	// A second Ctrl-C does not wait for the summary.
	if (interrupts > 1) process.exit(130);
	interrupt.abort();
};
process.on("SIGINT", onSignal);
process.on("SIGTERM", onSignal);

const io: Io = {
	stdout: streamSink(process.stdout, () => interrupt.abort(), true),
	stderr: streamSink(process.stderr, () => undefined, false),
	signal: interrupt.signal,
};

try {
	process.exitCode = await main(process.argv.slice(2), io);
} finally {
	process.off("SIGINT", onSignal);
	process.off("SIGTERM", onSignal);
}
