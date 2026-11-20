/**
 * Type-level checks, compiled by `bun run lint:types` (strict, with
 * exactOptionalPropertyTypes): a consumer of a live capture keeps the
 * fields a capture always has, while a decode's may be absent.
 */
import { expect, test } from "bun:test";
import type { CaptureStream } from "../../src/capture.ts";
import type { DecodeStream } from "../../src/decode.ts";

/** Compiles only while a capture's records keep `time`, `listener` and sender rows whole. */
export async function captureConsumer(stream: CaptureStream) {
	const out: string[] = [];
	for await (const r of stream) {
		if (r.type === "header") out.push(String(r.listeners[0]?.port));
		if (r.type === "packet" || r.type === "record")
			out.push(r.time.slice(11, 23), r.listener.toUpperCase());
		if (r.type === "summary")
			for (const s of r.senders.top)
				out.push(s.listener.toUpperCase(), s.peer.toUpperCase());
	}
	return out;
}

/** A decode's records may lack them: reading one without a check does not compile. */
export async function decodeConsumer(stream: DecodeStream) {
	const out: string[] = [];
	for await (const r of stream) {
		if (r.type === "header") out.push(r.input.format);
		if (r.type === "packet") {
			// @ts-expect-error: a file need not record a time
			out.push(r.time.slice(11, 23));
			out.push(r.time?.slice(11, 23) ?? "", r.interface ?? "");
		}
	}
	return out;
}

test("the consumers above compile (checked by tsc, not at run time)", () => {
	expect(typeof captureConsumer).toBe("function");
	expect(typeof decodeConsumer).toBe("function");
});
