import { describe, expect, test } from "bun:test";
import type { Capture } from "../../src/listen.ts";
import { summarize } from "../../src/summary.ts";
import { parseTzsp } from "../../src/tzsp.ts";

const capture = (peerPort: number): Capture => {
	const datagram = Uint8Array.from([1, 4, 0, 0]);
	return {
		seq: 1,
		time: 0,
		listener: { address: "0.0.0.0", port: 37008, label: "r1" },
		peer: { address: "127.0.0.1", port: peerPort, family: "IPv4" },
		datagram,
		tzsp: parseTzsp(datagram),
	};
};

describe("summarize: bounded tables", () => {
	test("folded entries are counted once each; past the cap the count is flagged as a lower bound", () => {
		// Track one sender, fold up to one more distinct one, then only flag.
		const stats = summarize({ top: 1, track: 1 });
		for (const port of [1, 2, 3, 3, 3]) stats.addDatagram(capture(port));
		const { senders } = stats.tables();
		expect(senders.top).toEqual([
			{ listener: "r1", peer: "127.0.0.1:1", datagrams: 1 },
		]);
		expect(senders.otherCount).toBe(4);
		expect(senders.otherEntries).toBe(1);
		expect(senders.otherEntriesCapped).toBe(true);
	});

	test("under the cap, distinct entries are exact and not flagged", () => {
		const stats = summarize({ top: 1, track: 10 });
		for (const port of [1, 2, 3, 3, 3]) stats.addDatagram(capture(port));
		const { senders } = stats.tables();
		expect(senders.top).toEqual([
			{ listener: "r1", peer: "127.0.0.1:3", datagrams: 3 },
		]);
		expect(senders).toMatchObject({
			otherEntries: 2,
			otherCount: 2,
			otherEntriesCapped: false,
		});
	});

	test("rows are copies: changing one does not change the tables", () => {
		const stats = summarize();
		stats.addDatagram(capture(1));
		const first = stats.tables();
		(first.senders.top[0] as { datagrams: number }).datagrams = 99;
		expect(stats.tables().senders.top[0]?.datagrams).toBe(1);
	});

	test("top and track must be whole numbers of 0 or more; track 0 folds everything", () => {
		for (const options of [
			{ top: -1 },
			{ track: 1.5 },
			{ track: Number.POSITIVE_INFINITY },
			{ top: Number.NaN },
		]) {
			expect(() => summarize(options)).toThrow(
				expect.objectContaining({ code: "summary/invalid-option" }),
			);
		}
		const all = summarize({ track: 0 });
		all.addDatagram(capture(1));
		expect(all.tables().senders).toMatchObject({ top: [], otherCount: 1 });
	});
});
