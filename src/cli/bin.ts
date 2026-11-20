#!/usr/bin/env node
/**
 * The `tzsp-sniff` executable: wires the process's streams and signals to
 * `main()`. It reads no environment variables yet, so a working directory's
 * `.env`, which Bun loads, changes nothing (DESIGN.md, "Decided: Node and
 * npx").
 */
import { fstatSync } from "node:fs";
import { type Io, main } from "./main.ts";
import { streamSink, terminalStream } from "./sink.ts";

/** One write may take this long before stdout counts as stalled. */
const STALL_MS = 30_000;
/** The same after Ctrl-C: the summary gets this long to be read. */
const GRACE_MS = 2_000;

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

// A terminal that stops reading must not block the event loop that times
// the write out (see terminalStream).
const stdout = streamSink(terminalStream(process.stdout, 1), {
	required: true,
	stallMs: STALL_MS,
	graceMs: GRACE_MS,
	signal: interrupt.signal,
	// Stop the capture: there is nowhere left to put its result.
	onFailed: () => interrupt.abort(),
});
const stderr = streamSink(terminalStream(process.stderr, 2), {
	required: false,
	stallMs: STALL_MS,
	graceMs: GRACE_MS,
	signal: interrupt.signal,
});
const io: Io = {
	stdout,
	stderr,
	signal: interrupt.signal,
	stdoutTerminal: process.stdout.isTTY === true,
	outputFiles: [1, 2].flatMap((fd) => {
		try {
			// Every kind of target, not only a regular file: a FIFO or a device
			// named by --write is the same destination too (Copilot review of
			// cdcd610). An inode of 0 (Windows consoles and pipes) names nothing.
			const s = fstatSync(fd, { bigint: true });
			return s.ino === 0n ? [] : [{ dev: s.dev, ino: s.ino }];
		} catch {
			return [];
		}
	}),
};

let code = 1;
try {
	code = await main(process.argv.slice(2), io);
} finally {
	process.off("SIGINT", onSignal);
	process.off("SIGTERM", onSignal);
}
// A failed or stalled stream may never drain, and waiting on it would keep
// the process alive; otherwise let pending output flush and exit naturally.
if (stdout.failed || stderr.failed) process.exit(code);
process.exitCode = code;
