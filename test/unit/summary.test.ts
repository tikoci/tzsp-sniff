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
});
