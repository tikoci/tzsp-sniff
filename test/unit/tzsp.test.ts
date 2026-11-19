import { describe, expect, test } from "bun:test";
import {
	parseTzsp,
	TZSP_MAX_TAGS,
	type TzspDatagram,
	type TzspInvalidReason,
	type TzspUnsupportedReason,
	toHex,
} from "../../src/tzsp.ts";

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

/**
 * The result's `datagram` is the input itself (same object, same memory), and
 * its bytes still equal the fixture hex taken before parsing, so a parser that
 * wrote into its input would fail here.
 */
const expectDatagramKept = (
	d: TzspDatagram,
	input: Uint8Array,
	fixtureHex: string,
) => {
	expect(d.datagram).toBe(input);
	expect(d.datagram.buffer).toBe(input.buffer);
	expect(toHex(d.datagram)).toBe(fixtureHex);
};

/** `payload` is a view into the input's memory at `offset` bytes into it. */
const expectPayloadView = (
	d: TzspDatagram,
	input: Uint8Array,
	offset: number,
) => {
	expect(d.payload.buffer).toBe(input.buffer);
	expect(d.payload.byteOffset).toBe(input.byteOffset + offset);
};

/** `count` zero-length tags (tag 99), as hex. */
const emptyTags = (count: number) => "6300".repeat(count);

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
		expectPayloadView(d, input, 5);
		expectDatagramKept(d, input, CMR_SYN);
	});

	test("keeps the datagram as a view when the input is itself a view", () => {
		const backing = bytes(`ffff${CMR_SYN}ffff`);
		const input = backing.subarray(2, backing.length - 2);
		const d = parseTzsp(input);
		expect(d.kind).toBe("packet");
		expect(d.datagram.byteOffset).toBe(2);
		expectPayloadView(d, input, 5);
		expect(d.payload.length).toBe(input.length - 5);
		expectDatagramKept(d, input, CMR_SYN);
	});

	test("an end tag as the last byte gives an empty payload view", () => {
		const input = bytes("0100000101");
		const d = parseTzsp(input);
		expect(d.kind).toBe("packet");
		expect(d.payload.length).toBe(0);
		expectPayloadView(d, input, 5);
	});

	test("accepts a Uint8Array subclass whose constructor rejects a buffer", () => {
		// subarray() calls the subclass constructor with an ArrayBuffer, which
		// this one cannot take; the parser must not depend on it.
		class CaptureBytes extends Uint8Array {
			constructor(values: number[]) {
				super(values.map((b) => b));
			}
		}
		const input = new CaptureBytes([1, 0, 0, 1, 0x29, 1, 0x05, 1, 0xaa]);
		const d = parseTzsp(input);
		expect(d.kind).toBe("packet");
		expect(d.tags).toEqual([{ tag: 41, name: "original-length", hex: "05" }]);
		expect(toHex(d.payload)).toBe("aa");
		expectDatagramKept(d, input, "0100000129010501aa");
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
			expectDatagramKept(d, input, hex);
		},
	);

	test.each([
		["keepalive", "0104"],
		["port-opener", "0105"],
	])(
		"a %s reads no tags or frame after its header, and keeps those bytes",
		(typeName, head) => {
			// packet-tzsp.c (e0929ac4, dissect_tzsp) reads options and the frame
			// only for types other than 4 and 5. A real TLV, then an end tag and a
			// frame byte: none of it may be parsed.
			const hex = `${head}0001` + "290205dc" + "01aa";
			const input = bytes(hex);
			const d = parseTzsp(input);
			expect(d).toMatchObject({ kind: "control", typeName, tags: [] });
			expect(d.problem).toBeUndefined();
			expect(d.reason).toBeUndefined();
			expect(d.payload.length).toBe(0);
			expectDatagramKept(d, input, hex);
		},
	);

	test("reads another record type's tags and frame, and keeps it as unsupported", () => {
		// Transmit (1) and an unknown type 9: original-length, end tag, one frame byte.
		for (const [hex, typeName] of [
			["0101000129" + "0205dc" + "01aa", "transmit"],
			["0109beef29" + "0205dc" + "01aa", "type-9"],
		] as const) {
			const input = bytes(hex);
			const d = parseTzsp(input);
			expect(d).toMatchObject({
				kind: "unsupported",
				typeName,
				problem: "unsupported",
				reason: "record-type",
				tags: [{ tag: 41, name: "original-length", hex: "05dc" }],
			});
			expect(toHex(d.payload)).toBe("aa");
			expectPayloadView(d, input, input.length - 1);
			expectDatagramKept(d, input, hex);
		}
	});

	test("another record type with a broken tag list is invalid, not unsupported", () => {
		// Transmit has the tag list too (packet-tzsp.c e0929ac4), so its
		// structure is checked before its type is judged.
		const hex = "01010001";
		const input = bytes(hex);
		const d = parseTzsp(input);
		expect(d).toMatchObject({
			kind: "invalid",
			typeName: "transmit",
			problem: "truncated",
			reason: "no-end-tag",
		});
		expect(d.payload.length).toBe(0);
		expectDatagramKept(d, input, hex);
	});

	test("keeps a received record with another encapsulation as unsupported", () => {
		// Received, 802.11 radiotap, end tag, two frame bytes, inside a larger buffer.
		const hex = "0100007e01aabb";
		const backing = bytes(`ffff${hex}ff`);
		const input = backing.subarray(2, backing.length - 1);
		const d = parseTzsp(input);
		expect(d).toMatchObject({
			kind: "unsupported",
			encapsulationName: "ieee-802.11-radiotap",
			problem: "unsupported",
			reason: "encapsulation",
		});
		// The inner frame is still found, as a view, so a later dissector can read it.
		expect(toHex(d.payload)).toBe("aabb");
		expectPayloadView(d, input, 5);
		expectDatagramKept(d, input, hex);
	});

	test("names unknown encapsulations instead of failing", () => {
		const d = parseTzsp(bytes("0100beef01"));
		expect(d.encapsulationName).toBe("encap-48879");
		expect(d.problem).toBe("unsupported");
	});

	test(`reads up to ${TZSP_MAX_TAGS} tags`, () => {
		const hex = `01000001${emptyTags(TZSP_MAX_TAGS)}01aa`;
		const input = bytes(hex);
		const d = parseTzsp(input);
		expect(d.kind).toBe("packet");
		expect(d.tags.length).toBe(TZSP_MAX_TAGS);
		expect(toHex(d.payload)).toBe("aa");
	});

	test(`stops at tag ${TZSP_MAX_TAGS + 1} as unsupported, bytes kept`, () => {
		const hex = `01000001${emptyTags(TZSP_MAX_TAGS + 1)}01aa`;
		const input = bytes(hex);
		const d = parseTzsp(input);
		expect(d).toMatchObject({
			kind: "unsupported",
			problem: "unsupported",
			reason: "tag-limit",
		});
		expect(d.tags.length).toBe(TZSP_MAX_TAGS);
		expect(d.payload.length).toBe(0);
		expectDatagramKept(d, input, hex);
	});

	test("a UDP-sized run of pad tags is not a tag and ends as no-end-tag", () => {
		const hex = `01000001${"00".repeat(65_503)}`;
		const d = parseTzsp(bytes(hex));
		expect(d).toMatchObject({
			kind: "invalid",
			reason: "no-end-tag",
			tags: [],
		});
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
		[
			"a tag length of 255 past the end",
			"truncated",
			"truncated-tag",
			"0100000129ff00",
		],
	])(
		"%s: problem %s (%s), bytes kept, never throws",
		(_, problem, reason, hex) => {
			const input = bytes(hex);
			const d = parseTzsp(input);
			expect(d).toMatchObject({ kind: "invalid", problem, reason });
			expect(d.payload.length).toBe(0);
			expectDatagramKept(d, input, hex);
		},
	);

	test("keeps the tags read before a truncated one", () => {
		const d = parseTzsp(bytes("01000001" + "290205dc" + "2a"));
		expect(d.reason).toBe("truncated-tag");
		expect(d.tags).toEqual([{ tag: 41, name: "original-length", hex: "05dc" }]);
	});

	test("never throws, and keeps the input, on seeded random datagrams", () => {
		// A small linear congruential generator, so a failure reproduces.
		let seed = 0x5eed;
		const next = () => {
			seed = (Math.imul(seed, 1_103_515_245) + 12_345) >>> 0;
			return seed >>> 16;
		};
		for (let i = 0; i < 5_000; i++) {
			// Bias toward a valid header so the tag loop is exercised.
			const length = next() % 48;
			const input = Uint8Array.from({ length }, (_, at) =>
				at === 0 && next() % 4 ? 1 : next() % 4 ? next() % 8 : next() & 0xff,
			);
			const before = toHex(input);
			const d = parseTzsp(input);
			expect(d.datagram).toBe(input);
			expect(toHex(input)).toBe(before);
			expect(d.problem === undefined).toBe(
				d.kind === "packet" || d.kind === "control",
			);
		}
	});

	test("the result type ties problem and reason to kind", () => {
		// Compile-time: tsc (bun run lint:types) rejects this function if the
		// exported union stops narrowing. Runtime: one value of each branch.
		const reasonOf = (
			d: TzspDatagram,
		): TzspInvalidReason | TzspUnsupportedReason | "none" => {
			switch (d.kind) {
				case "packet":
				case "control":
					return "none";
				case "unsupported":
					return d.reason;
				case "invalid": {
					if (d.problem === "malformed") {
						const malformed: "bad-version" = d.reason;
						return malformed;
					}
					return d.reason;
				}
			}
		};
		expect(reasonOf(parseTzsp(bytes(CMR_SYN)))).toBe("none");
		expect(reasonOf(parseTzsp(bytes("01040000")))).toBe("none");
		expect(reasonOf(parseTzsp(bytes("0100007e01")))).toBe("encapsulation");
		expect(reasonOf(parseTzsp(bytes("02000001")))).toBe("bad-version");
	});
});
