import { describe, expect, test } from "bun:test";
import { parseTzsp, toHex } from "../../src/tzsp.ts";

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

describe("parseTzsp", () => {
	test("reads the RouterOS header: v1, received, Ethernet, end tag only", () => {
		const d = parseTzsp(bytes(CMR_SYN));
		expect(d).toMatchObject({
			version: 1,
			type: 0,
			typeName: "received",
			encapsulation: 1,
			encapsulationName: "ethernet",
			tags: [],
		});
		expect(d.problem).toBeUndefined();
		// The Ethernet destination MAC is the first payload bytes.
		expect(toHex(d.payload.subarray(0, 6))).toBe("02fcb1face5f");
		expect(d.payload.length).toBe(bytes(CMR_SYN).length - 5);
	});

	test("skips pad tags and keeps other tags with their bytes", () => {
		// pad, original-length = 0x05dc, an unnamed tag 99 with one byte, end, payload aa.
		const d = parseTzsp(bytes("010000010029" + "0205dc" + "630177" + "01aa"));
		expect(d.tags).toEqual([
			{ tag: 41, name: "original-length", hex: "05dc" },
			{ tag: 99, name: "tag-99", hex: "77" },
		]);
		expect(toHex(d.payload)).toBe("aa");
	});

	test("names unknown types and encapsulations instead of failing", () => {
		const d = parseTzsp(bytes("0109beef01"));
		expect(d).toMatchObject({
			typeName: "type-9",
			encapsulationName: "encap-48879",
		});
		expect(d.problem).toBeUndefined();
	});

	test("reports each malformed shape as a problem, never throws", () => {
		expect(parseTzsp(bytes("0100")).problem).toBe("too-short");
		expect(parseTzsp(bytes("0200000101")).problem).toBe("bad-version");
		expect(parseTzsp(bytes("01000001")).problem).toBe("no-end-tag");
		expect(parseTzsp(bytes("0100000129" + "05aa")).problem).toBe(
			"truncated-tag",
		);
		expect(parseTzsp(bytes("010000012a")).problem).toBe("truncated-tag");
		expect(parseTzsp(new Uint8Array(0)).payload.length).toBe(0);
	});
});
