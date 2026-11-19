import { describe, expect, test } from "bun:test";
import { Writable } from "node:stream";
import { OutputClosedError } from "../../src/cli/main.ts";
import { streamSink } from "../../src/cli/sink.ts";
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
