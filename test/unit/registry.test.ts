/**
 * The dissector registry (#25): what `dissectors()` lists is what dispatch
 * does. Each declared match, given a minimal frame, reaches the dissector
 * that declares it; nothing else is reached; `--proto`'s list comes from it.
 * dissect.test.ts holds the fields records carry to the declarations.
 */
import { describe, expect, test } from "bun:test";
import {
	type DissectorInfo,
	dissect,
	dissectors,
	type FieldInfo,
} from "../../src/dissect.ts";
import {
	fieldInfo,
	type FieldDecls,
	type Registration,
} from "../../src/dissect/core.ts";
import { buildDispatch, REGISTRATIONS } from "../../src/dissect/registry.ts";
import { FILTER_PROTOCOLS } from "../../src/filter.ts";
import { bytes, eth, h16, ipv4, ipv6 } from "./helpers.ts";

const list = dissectors();
const byMatch = (d: DissectorInfo, by: string) =>
	d.matches.filter((m) => m.by === by).map((m) => m.value);

describe("dissectors()", () => {
	test("lists the order 1 protocols, outermost first", () => {
		expect(list.map((d) => d.protocol)).toEqual([
			"ethernet",
			"vlan",
			"arp",
			"ipv4",
			"ipv6",
			"icmp",
			"icmpv6",
			"udp",
			"tcp",
		]);
		for (const d of list) {
			expect(d.name).toMatch(/\S/);
			expect(d.reference).toMatch(/^(RFC|IEEE) /);
			expect(d.matches.length).toBeGreaterThan(0);
			expect(d.fields.length).toBeGreaterThan(0);
			for (const f of d.fields) expect(f.description).toMatch(/\S/);
		}
	});

	test("says how each is reached", () => {
		const of = (p: string) => list.find((d) => d.protocol === p);
		expect(of("ethernet")?.matches).toEqual([
			{ by: "link", value: "ethernet" },
		]);
		expect(of("vlan")?.matches).toEqual([
			{ by: "etherType", value: "0x8100" },
			{ by: "etherType", value: "0x88a8" },
		]);
		expect(of("tcp")?.matches).toEqual([{ by: "ipProtocol", value: 6 }]);
		expect(of("icmpv6")?.matches).toEqual([{ by: "ipProtocol", value: 58 }]);
	});

	test("returns a new copy each call", () => {
		const before = structuredClone(dissectors());
		const a = dissectors();
		const first = a[0] as DissectorInfo;
		first.protocol = "changed";
		(first.fields[0] as FieldInfo).name = "changed";
		first.matches.length = 0;
		const ipv6Fields = a.find((d) => d.protocol === "ipv6")?.fields;
		const ext = ipv6Fields?.find((f) => f.name === "extensions");
		if (ext?.items?.[0]) ext.items[0].name = "changed";
		expect(dissectors()).toEqual(before);
	});

	test("an object[] field lists its items", () => {
		const ipv6Fields = list.find((d) => d.protocol === "ipv6")?.fields;
		expect(ipv6Fields?.find((f) => f.name === "extensions")).toMatchObject({
			type: "object[]",
			optional: false,
			items: [
				{ name: "header", type: "number" },
				{ name: "name", type: "string" },
				{ name: "length", type: "number" },
			],
		});
	});

	test("--proto takes every protocol listed", () => {
		for (const d of list) expect(FILTER_PROTOCOLS).toContain(d.protocol);
	});
});

describe("dispatch follows the registry", () => {
	test("no match is claimed twice", () => {
		expect(buildDispatch(REGISTRATIONS).duplicates).toEqual([]);
		// The guard itself: a second claim on an EtherType is named.
		const again: Registration = {
			...(REGISTRATIONS[2] as Registration),
			protocol: "again",
		};
		expect(buildDispatch([...REGISTRATIONS, again]).duplicates).toEqual([
			"etherType 0x0806",
		]);
	});

	test("the link match is the first layer of a frame", () => {
		expect(dissect(bytes(eth(0x88b5, ""))).protocols[0]).toBe("ethernet");
	});

	test("each declared EtherType reaches its dissector, under Ethernet and a VLAN tag", () => {
		let seen = 0;
		for (const d of list) {
			for (const type of byMatch(d, "etherType")) {
				const n = Number(type);
				expect(dissect(bytes(eth(n, ""))).protocols[1]).toBe(d.protocol);
				const tagged = dissect(bytes(eth(0x8100, `000a${h16(n)}`)));
				expect(tagged.protocols[2]).toBe(d.protocol);
				seen++;
			}
		}
		expect(seen).toBe(5);
	});

	test("each declared IP protocol reaches its dissector, in IPv4 and IPv6", () => {
		let seen = 0;
		for (const d of list) {
			for (const proto of byMatch(d, "ipProtocol")) {
				const n = Number(proto);
				const v4 = dissect(bytes(eth(0x0800, ipv4({ proto: n, payload: "" }))));
				expect(v4.protocols[2]).toBe(d.protocol);
				const v6 = dissect(bytes(eth(0x86dd, ipv6({ next: n, payload: "" }))));
				expect(v6.protocols[2]).toBe(d.protocol);
				seen++;
			}
		}
		expect(seen).toBe(4);
	});

	test("an EtherType or IP protocol no dissector declares is data", () => {
		const declaredTypes = new Set(list.flatMap((d) => byMatch(d, "etherType")));
		const declaredProtos = new Set(
			list.flatMap((d) => byMatch(d, "ipProtocol")),
		);
		for (let n = 0x0600; n <= 0xffff; n++) {
			if (declaredTypes.has(`0x${h16(n)}`)) continue;
			expect(dissect(bytes(eth(n, "00"))).protocols).toEqual([
				"ethernet",
				"data",
			]);
		}
		for (let n = 0; n < 256; n++) {
			if (declaredProtos.has(n)) continue;
			const v4 = dissect(bytes(eth(0x0800, ipv4({ proto: n, payload: "00" }))));
			expect(v4.protocols).toEqual(["ethernet", "ipv4", "data"]);
		}
	});
});

describe("field declarations", () => {
	test("list each field in order, with nested items", () => {
		interface Sample {
			a: number;
			b?: string;
			c: { d: boolean }[];
			e: string[];
		}
		const decls: FieldDecls<Sample> = {
			a: { type: "number", description: "A." },
			b: { type: "string", optional: true, description: "B." },
			c: {
				type: "object[]",
				description: "C.",
				items: { d: { type: "boolean", description: "D." } },
			},
			e: { type: "string[]", description: "E." },
		};
		expect(fieldInfo(decls)).toEqual([
			{ name: "a", type: "number", optional: false, description: "A." },
			{ name: "b", type: "string", optional: true, description: "B." },
			{
				name: "c",
				type: "object[]",
				optional: false,
				description: "C.",
				items: [
					{ name: "d", type: "boolean", optional: false, description: "D." },
				],
			},
			{ name: "e", type: "string[]", optional: false, description: "E." },
		]);
	});

	// Checked by tsc (`bun run lint:types`): each @ts-expect-error fails the
	// build if the line under it compiles.
	test("do not compile when they drift from the fields type", () => {
		interface Sample {
			a: number;
			b?: string;
		}
		// @ts-expect-error: b is missing
		const missing: FieldDecls<Sample> = {
			a: { type: "number", description: "" },
		};
		const extra: FieldDecls<Sample> = {
			a: { type: "number", description: "" },
			b: { type: "string", optional: true, description: "" },
			// @ts-expect-error: c is not a field
			c: { type: "number", description: "" },
		};
		const wrongType: FieldDecls<Sample> = {
			// @ts-expect-error: a is a number
			a: { type: "string", description: "" },
			b: { type: "string", optional: true, description: "" },
		};
		const notOptional: FieldDecls<Sample> = {
			a: { type: "number", description: "" },
			// @ts-expect-error: b may be absent, so it is optional
			b: { type: "string", description: "" },
		};
		interface Nested {
			list: { a: number }[];
			numbers: number[];
		}
		const nestedMissing: FieldDecls<Nested> = {
			// @ts-expect-error: the item's a is missing
			list: { type: "object[]", description: "", items: {} },
			// @ts-expect-error: a list of numbers has no declaration
			numbers: { type: "object[]", description: "", items: 1 },
		};
		const nestedWrong: FieldDecls<Nested> = {
			list: {
				type: "object[]",
				description: "",
				// @ts-expect-error: the item's a is a number
				items: { a: { type: "string", description: "" } },
			},
			// @ts-expect-error: a list of numbers has no declaration
			numbers: { type: "string[]", description: "" },
		};
		interface Mixed {
			list: ({ n: number } | number[])[];
		}
		const mixed: FieldDecls<Mixed> = {
			// @ts-expect-error: a list whose items may be lists has no declaration
			list: {
				type: "object[]",
				description: "",
				items: { n: { type: "number", description: "" } },
			},
		};
		interface Nullable {
			label: string | null;
			note?: string | null;
		}
		const nullable: FieldDecls<Nullable> = {
			// @ts-expect-error: null has no field type
			label: { type: "string", description: "" },
			// @ts-expect-error: null has no field type, optional or not
			note: { type: "string", optional: true, description: "" },
		};
		expect([
			missing,
			extra,
			wrongType,
			notOptional,
			nestedMissing,
			nestedWrong,
			nullable,
			mixed,
		]).toHaveLength(8);
	});
});
