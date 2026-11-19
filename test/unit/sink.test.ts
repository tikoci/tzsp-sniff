import { describe, expect, test } from "bun:test";
import { closeSync, mkdtempSync, openSync, readSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { OutputClosedError } from "../../src/cli/main.ts";
import { fdStream, streamSink, terminalStream } from "../../src/cli/sink.ts";
import { TzspSniffError } from "../../src/errors.ts";

/** A stream whose writes never complete: a reader that stopped reading. */
const stuck = () => new Writable({ write() {} });
/** A stream whose writes fail with `code`. */
const failing = (code: string) =>
	new Writable({
		write(_chunk, _encoding, callback) {
			callback(Object.assign(new Error(code), { code }));
		},
	});
const options = { required: true, stallMs: 50, graceMs: 10 };

describe("streamSink", () => {
	test("a write that never completes fails as output/stalled", async () => {
		let failed = 0;
		const sink = streamSink(stuck(), { ...options, onFailed: () => failed++ });
		const started = Date.now();
		const error = await sink.write("x").catch((e: unknown) => e);
		expect((error as TzspSniffError).code).toBe("output/stalled");
		expect(Date.now() - started).toBeGreaterThanOrEqual(45);
		expect(sink.failed).toBe(true);
		expect(failed).toBe(1);
		// Later writes fail at once with the same error.
		expect(await sink.write("y").catch((e: unknown) => e)).toBe(error);
	});

	test("after an interrupt, a stuck write waits only the grace period", async () => {
		const controller = new AbortController();
		const sink = streamSink(stuck(), {
			...options,
			stallMs: 60_000,
			signal: controller.signal,
		});
		const pending = sink.write("x").catch((e: unknown) => e);
		const started = Date.now();
		controller.abort();
		expect(((await pending) as TzspSniffError).code).toBe("output/stalled");
		expect(Date.now() - started).toBeLessThan(1000);
	});

	test("a departed reader (EPIPE) is the quiet case", async () => {
		const sink = streamSink(failing("EPIPE"), options);
		expect(await sink.write("x").catch((e: unknown) => e)).toBeInstanceOf(
			OutputClosedError,
		);
	});

	test("any other failure (ENOSPC) is output/failed", async () => {
		const sink = streamSink(failing("ENOSPC"), options);
		const error = await sink.write("x").catch((e: unknown) => e);
		expect(error).toBeInstanceOf(TzspSniffError);
		expect((error as TzspSniffError).code).toBe("output/failed");
	});

	test("a stream that is not required (stderr) never rejects", async () => {
		const sink = streamSink(failing("ENOSPC"), { ...options, required: false });
		await sink.write("x");
		await sink.write("y");
		expect(sink.failed).toBe(true);
	});
});

describe("terminalStream", () => {
	const fake = (isTTY: boolean, withHandle = true) => {
		const calls: boolean[] = [];
		const stream = Object.assign(
			new Writable({ write: (_c, _e, cb) => cb() }),
			{
				isTTY,
				_handle: withHandle
					? {
							setBlocking(b: boolean) {
								calls.push(b);
							},
						}
					: undefined,
			},
		);
		return { stream, calls };
	};

	test("a terminal with a handle (Node): the same stream, made non-blocking", () => {
		const { stream, calls } = fake(true);
		expect(terminalStream(stream, 1, "linux")).toBe(stream);
		expect(calls).toEqual([false]);
	});

	test("a terminal without a handle (Bun): a stream over the descriptor", () => {
		const { stream } = fake(true, false);
		const out = terminalStream(stream, 1, "darwin");
		expect(out).not.toBe(stream);
		expect(out).toBeInstanceOf(Writable);
	});

	test("not a terminal, or Windows: the stream as it is", () => {
		for (const [tty, platform] of [
			[false, "linux"],
			[true, "win32"],
		] as const) {
			const { stream, calls } = fake(tty);
			expect(terminalStream(stream, 1, platform)).toBe(stream);
			expect(calls).toEqual([]);
		}
	});

	test("fdStream writes every byte, in order, through the descriptor", async () => {
		const dir = mkdtempSync(join(tmpdir(), "tzsp-sniff-"));
		const path = join(dir, "out.txt");
		// Written and read back through the one descriptor, never by path again.
		const fd = openSync(path, "w+");
		try {
			const out = fdStream(fd);
			const big = "x".repeat(300_000);
			for (const text of ["one\n", big, "two\n"]) {
				await new Promise<void>((resolve, reject) =>
					out.write(text, (e) => (e ? reject(e) : resolve())),
				);
			}
			const expected = `one\n${big}two\n`;
			const back = Buffer.alloc(expected.length + 1);
			const n = readSync(fd, back, 0, back.length, 0);
			expect(back.subarray(0, n).toString("utf8")).toBe(expected);
		} finally {
			closeSync(fd);
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
