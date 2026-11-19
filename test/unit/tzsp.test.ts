import { describe, expect, test } from "bun:test";
import { parseTzsp, type TzspDatagram, toHex } from "../../src/tzsp.ts";

/**
 * Datagrams captured from RouterOS 7.26beta5 x86 CHR `/tool/sniffer` streaming,
 * 2026-11-14, copied from tikoci/quickchr test/unit/examples-cmr-tzsp.test.ts
 * (examples/cmr/FINDINGS.md, "Wire"). Real bytes, so a parser change shows here.
 */
// The client's first SYN to the controller's CMR service.
const CMR_SYN =
	"010000010102fcb1face5f026401f40b5808004500003c3b13400040067ba5c0000202c00002018c50d431a771961b00000000a002faf00c960000020405b40402080a0deb107c0000000001030306";

const bytes = (hex: string) =>
	Uint8Array.from(hex.match(/../g) ?? [], (b) => Number.parseInt(b, 16));

/** The result's `datagram` is the input itself: same memory, same bytes. */
const expectDatagramKept = (d: TzspDatagram, input: Uint8Array) => {
	expect(d.datagram).toBe(input);
	expect(d.datagram.buffer).toBe(input.buffer);
	expect(toHex(d.datagram)).toBe(toHex(input));
};

describe("parseTzsp", () => {
	test("reads the RouterOS header: v1, received, Ethernet, end tag only", () => {
		const input = bytes(CMR_SYN);
		const d = parseTzsp(input);
		expect(d).toMatchObject({
			kind: "packet",
			version: 1,
			type: 0,
			typeName: "received",
			encapsulation: 1,
			encapsulationName: "ethernet",
			tags: [],
		});
		expect(d.problem).toBeUndefined();
		expect(d.reason).toBeUndefined();
		// The Ethernet destination MAC is the first payload bytes.
		expect(toHex(d.payload.subarray(0, 6))).toBe("02fcb1face5f");
		expect(d.payload.length).toBe(input.length - 5);
		// The payload is a view into the datagram, not a copy.
		expect(d.payload.buffer).toBe(input.buffer);
		expectDatagramKept(d, input);
	});

	test("keeps the datagram as a view when the input is itself a view", () => {
		const backing = bytes(`ffff${CMR_SYN}ffff`);
		const input = backing.subarray(2, backing.length - 2);
		const d = parseTzsp(input);
		expect(d.kind).toBe("packet");
		expect(d.datagram.byteOffset).toBe(2);
		expectDatagramKept(d, input);
	});

	test("skips pad tags and keeps other tags with their bytes", () => {
		// pad, original-length = 0x05dc, an unnamed tag 99 with one byte, end, payload aa.
		const d = parseTzsp(bytes("010000010029" + "0205dc" + "630177" + "01aa"));
		expect(d.kind).toBe("packet");
		expect(d.tags).toEqual([
			{ tag: 41, name: "original-length", hex: "05dc" },
			{ tag: 99, name: "tag-99", hex: "77" },
		]);
		expect(toHex(d.payload)).toBe("aa");
	});

	test.each([
		["keepalive", "01040000"],
		["port-opener", "01050000"],
	])(
		"reads a %s as a control record: no tags, no payload, no problem",
		(typeName, hex) => {
			const input = bytes(hex);
			const d = parseTzsp(input);
			expect(d).toMatchObject({ kind: "control", typeName, tags: [] });
			expect(d.problem).toBeUndefined();
			expect(d.reason).toBeUndefined();
			expect(d.payload.length).toBe(0);
			expectDatagramKept(d, input);
		},
	);

	test("a control record ignores bytes after its header, and keeps them", () => {
		// packet-tzsp.c reads no tags for type 4 or 5; trailing bytes stay in `datagram`.
		const input = bytes("0104000101aa");
		const d = parseTzsp(input);
		expect(d.kind).toBe("control");
		expect(d.problem).toBeUndefined();
		expect(d.payload.length).toBe(0);
		expectDatagramKept(d, input);
	});

	test("keeps another record type as unsupported, with no payload to dissect", () => {
		// Transmit (1) and an unknown type 9, each with a well-formed end tag and a byte after.
		for (const [hex, typeName] of [
			["0101000101aa", "transmit"],
			["0109beef01aa", "type-9"],
		] as const) {
			const input = bytes(hex);
			const d = parseTzsp(input);
			expect(d).toMatchObject({
				kind: "unsupported",
				typeName,
				problem: "unsupported",
				reason: "record-type",
			});
			expect(d.payload.length).toBe(0);
			expectDatagramKept(d, input);
		}
	});

	test("keeps a received record with another encapsulation as unsupported", () => {
		// Received, 802.11 radiotap, end tag, two frame bytes.
		const input = bytes("0100007e01aabb");
		const d = parseTzsp(input);
		expect(d).toMatchObject({
			kind: "unsupported",
			encapsulationName: "ieee-802.11-radiotap",
			problem: "unsupported",
			reason: "encapsulation",
		});
		// The inner frame is still found, so a later dissector can read it.
		expect(toHex(d.payload)).toBe("aabb");
		expectDatagramKept(d, input);
	});

	test("names unknown encapsulations instead of failing", () => {
		const d = parseTzsp(bytes("0100beef01"));
		expect(d.encapsulationName).toBe("encap-48879");
		expect(d.problem).toBe("unsupported");
	});

	test.each([
		["empty", "truncated", "too-short", ""],
		["fewer than 4 header bytes", "truncated", "too-short", "010000"],
		["version 2", "malformed", "bad-version", "0200000101"],
		["version 0", "malformed", "bad-version", "0000000101"],
		["no end tag", "truncated", "no-end-tag", "01000001"],
		["only pad tags", "truncated", "no-end-tag", "010000010000"],
		[
			"a tag value past the end",
			"truncated",
			"truncated-tag",
			"0100000129" + "05aa",
		],
		["a tag with no length byte", "truncated", "truncated-tag", "010000012a"],
	])(
		"%s: problem %s (%s), bytes kept, never throws",
		(_, problem, reason, hex) => {
			const input = bytes(hex);
			const d = parseTzsp(input);
			expect(d).toMatchObject({ kind: "invalid", problem, reason });
			expect(d.payload.length).toBe(0);
			expectDatagramKept(d, input);
		},
	);

	test("keeps the tags read before a truncated one", () => {
		const d = parseTzsp(bytes("01000001" + "290205dc" + "2a"));
		expect(d.reason).toBe("truncated-tag");
		expect(d.tags).toEqual([{ tag: 41, name: "original-length", hex: "05dc" }]);
	});
});
