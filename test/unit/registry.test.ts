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
	m2irFacts,
} from "../../src/dissect.ts";
import {
	type Dispatch,
	Frame,
	fieldInfo,
	type FieldDecls,
	type PortDissect,
	type Registration,
} from "../../src/dissect/core.ts";
import { buildDispatch, REGISTRATIONS } from "../../src/dissect/registry.ts";
import { FILTER_PROTOCOLS } from "../../src/filter.ts";
import { bytes, eth, h16, ipv4, ipv6, tcp, udp } from "./helpers.ts";

const list = dissectors();
const byMatch = (d: DissectorInfo, by: string) =>
	d.matches.filter((m) => m.by === by).map((m) => m.value);

describe("dissectors()", () => {
	test("lists the order 1 protocols, outermost first", () => {
		expect(list.map((d) => d.protocol)).toEqual([
			"ethernet",
			"vlan",
			"arp",
			"lldp",
			"ipv4",
			"ipv6",
			"icmp",
			"icmpv6",
			"udp",
			"tcp",
			"dhcp",
			"mndp",
		]);
		for (const d of list) {
			expect(d.name).toMatch(/\S/);
			expect(d.reference).toMatch(/^(RFC|IEEE|m2ir) /);
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
		expect(of("dhcp")?.matches).toEqual([
			{ by: "udpPort", value: 67 },
			{ by: "udpPort", value: 68 },
		]);
		expect(of("mndp")?.matches).toEqual([{ by: "udpPort", value: 5678 }]);
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
		const ttl = a
			.find((d) => d.protocol === "mndp")
			?.fields.find((f) => f.name === "ttl");
		if (ttl) ttl.confidence = "documented";
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

	test("a field from the m2ir table carries m2ir's confidence and nothing more; a field from a standard none", () => {
		const fields = (p: string) =>
			list.find((d) => d.protocol === p)?.fields ?? [];
		const mndp = new Map(fields("mndp").map((f) => [f.name, f]));
		expect(mndp.get("macAddress")).toMatchObject({ confidence: "documented" });
		expect(mndp.get("ttl")).toMatchObject({ confidence: "observed-only" });
		expect(mndp.get("ttlName")).toMatchObject({ confidence: "observed-only" });
		// Version scope is in m2irFacts(), not in what every caller reads.
		for (const f of fields("mndp"))
			expect(Object.keys(f).sort()).toEqual(
				f.name === "otherTlvs"
					? ["description", "items", "name", "optional", "type"]
					: ["confidence", "description", "name", "optional", "type"],
			);
		// TLV 9's byte order is known for x86_64 senders only: kept as hex.
		expect(mndp.get("aggregatedSizeHex")?.description).toContain(
			"u32le from x86_64 senders",
		);
		// TLV 14's guessed meaning on 7.21 to 7.25 is labelled, not stated.
		expect(mndp.get("ipv6Enabled")?.description).toContain(
			"disable-ipv6 on 7.21 to 7.25.1 (guessed)",
		);
		for (const d of list) {
			if (d.protocol === "mndp") continue;
			for (const f of d.fields) expect(f.confidence).toBeUndefined();
		}
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
		// A port clashes only on the same transport: UDP 67 twice does, TCP 67 does not.
		const dhcp = REGISTRATIONS.find((r) => r.protocol === "dhcp");
		const tcp67 = probe("tcp67", { tcpPort: 67 });
		const twice = buildDispatch([
			...REGISTRATIONS,
			{ ...(dhcp as Registration), protocol: "dhcp2" },
			tcp67,
		]);
		expect(twice.duplicates).toEqual(["udpPort 67", "udpPort 68"]);
		expect(twice.dispatch.tcpPort.has(67)).toBe(true);
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
		expect(seen).toBe(6);
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

	test("each declared UDP port reaches its dissector, as source or destination, in IPv4 and IPv6", () => {
		let seen = 0;
		for (const d of list) {
			for (const port of byMatch(d, "udpPort")) {
				const n = Number(port);
				for (const [sp, dp] of [
					[50000, n],
					[n, 50000],
				] as const) {
					const v4 = dissect(
						bytes(eth(0x0800, ipv4({ proto: 17, payload: udp(sp, dp, "00") }))),
					);
					expect(v4.protocols[3]).toBe(d.protocol);
					const v6 = dissect(
						bytes(eth(0x86dd, ipv6({ next: 17, payload: udp(sp, dp, "00") }))),
					);
					expect(v6.protocols[3]).toBe(d.protocol);
				}
				seen++;
			}
		}
		expect(seen).toBe(3);
		// No dissector here is reached by TCP port yet (the tests below use their own).
		expect(list.flatMap((d) => byMatch(d, "tcpPort"))).toEqual([]);
	});

	test("a UDP port no dissector declares is data, from either side", () => {
		const declared = new Set(list.flatMap((d) => byMatch(d, "udpPort")));
		for (let n = 0; n <= 0xffff; n++) {
			if (declared.has(n)) continue;
			const d = dissect(
				bytes(eth(0x0800, ipv4({ proto: 17, payload: udp(n, n, "00") }))),
			);
			expect(d.protocols).toEqual(["ethernet", "ipv4", "udp", "data"]);
		}
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

/** A registration that only says it was reached, for the port rules below. */
function probe(
	protocol: string,
	...matches: ({ udpPort: number } | { tcpPort: number })[]
): Registration {
	const dissect: PortDissect = (f, start, end) => {
		f.layers.push({
			protocol: protocol as "data",
			offset: start,
			length: end - start,
		});
	};
	return {
		protocol,
		name: protocol,
		reference: "RFC 0",
		matches: matches.map((m) => ({ ...m, dissect })),
		fields: [],
	};
}

/** Dissect an Ethernet frame through `registrations`, not the package's own. */
function dissectWith(registrations: Registration[], frame: Uint8Array) {
	const { dispatch } = buildDispatch([...REGISTRATIONS, ...registrations]);
	const f = new Frame(frame, dispatch as Dispatch);
	dispatch.link.get("ethernet")?.(f, 0, frame.length);
	return f.layers.map((l) => l.protocol as string);
}

const udp4 = (sp: number, dp: number, payload = "00", o = {}) =>
	bytes(eth(0x0800, ipv4({ proto: 17, payload: udp(sp, dp, payload), ...o })));
const tcp4 = (sp: number, dp: number, payload = "00", o = {}) =>
	bytes(
		eth(
			0x0800,
			ipv4({ proto: 6, payload: tcp({ sp, dp, flags: 0x18, payload }), ...o }),
		),
	);

describe('port matches (DESIGN.md, "Decided: port matches")', () => {
	const low = probe("low", { udpPort: 1000 }, { tcpPort: 1000 });
	const high = probe("high", { udpPort: 2000 }, { tcpPort: 2000 });

	test("the lower port is tried first, whichever side it is on", () => {
		for (const [build, transport] of [
			[udp4, "udp"],
			[tcp4, "tcp"],
		] as const) {
			expect(dissectWith([low, high], build(2000, 1000))).toEqual([
				"ethernet",
				"ipv4",
				transport,
				"low",
			]);
			expect(dissectWith([low, high], build(1000, 2000)).at(-1)).toBe("low");
			// With only the higher port's, it is reached from either side.
			expect(dissectWith([high], build(1000, 2000)).at(-1)).toBe("high");
			expect(dissectWith([high], build(2000, 1000)).at(-1)).toBe("high");
			// Equal ports: one dissector, tried once.
			expect(dissectWith([high], build(2000, 2000))).toEqual([
				"ethernet",
				"ipv4",
				transport,
				"high",
			]);
		}
	});

	test("a UDP port match is not a TCP one, nor the reverse", () => {
		const udpOnly = probe("udp-only", { udpPort: 3000 });
		const tcpOnly = probe("tcp-only", { tcpPort: 4000 });
		expect(dissectWith([udpOnly, tcpOnly], tcp4(50000, 3000)).at(-1)).toBe(
			"data",
		);
		expect(dissectWith([udpOnly, tcpOnly], udp4(50000, 4000)).at(-1)).toBe(
			"data",
		);
		expect(dissectWith([udpOnly, tcpOnly], tcp4(50000, 4000)).at(-1)).toBe(
			"tcp-only",
		);
	});

	test("a first IP fragment's payload stays data; a later fragment has no transport layer", () => {
		// More fragments set, offset 0: the UDP length counts bytes still to come.
		const first = bytes(
			eth(
				0x0800,
				ipv4({
					proto: 17,
					payload: udp(68, 67, "0102", 300),
					flagsOffset: 0x2000,
				}),
			),
		);
		expect(dissect(first).protocols).toEqual([
			"ethernet",
			"ipv4",
			"udp",
			"data",
		]);
		expect(
			dissectWith([low], tcp4(50000, 1000, "00", { flagsOffset: 0x2000 })),
		).toEqual(["ethernet", "ipv4", "tcp", "data"]);
		const later = bytes(
			eth(
				0x0800,
				ipv4({ proto: 17, payload: udp(68, 67, "00"), flagsOffset: 0x0010 }),
			),
		);
		expect(dissect(later).protocols).toEqual(["ethernet", "ipv4", "data"]);
	});

	test("an empty payload is not dispatched", () => {
		expect(dissect(udp4(68, 67, "")).protocols).toEqual([
			"ethernet",
			"ipv4",
			"udp",
		]);
		expect(dissectWith([low], tcp4(50000, 1000, ""))).toEqual([
			"ethernet",
			"ipv4",
			"tcp",
		]);
	});

	test("a UDP datagram cut short, or longer than its IP packet, is still dispatched, over the bytes there are", () => {
		// 300 bytes declared for UDP, 2 bytes of payload. An IPv4 total length
		// of 328 says the capture ended early (truncated); one of 30 says
		// the UDP length contradicts the packet (malformed).
		for (const [total, problem] of [
			[328, "truncated"],
			[30, "malformed"],
		] as const) {
			const d = dissect(
				bytes(
					eth(
						0x0800,
						ipv4({
							proto: 17,
							payload: udp(68, 67, "0102", 300),
							totalLength: total,
						}),
					),
				),
			);
			expect(d.protocols).toEqual(["ethernet", "ipv4", "udp", "dhcp"]);
			const u = d.layers[2];
			expect({ problem: u?.problem, reason: u?.reason }).toEqual({
				problem,
				reason: "length",
			});
			expect(d.layers[3]).toMatchObject({ offset: 14 + 20 + 8, length: 2 });
		}
	});

	test("equal ports are looked up once", () => {
		const { dispatch } = buildDispatch(REGISTRATIONS);
		const asked: number[] = [];
		const udpPort = new Map(dispatch.udpPort);
		const get = udpPort.get.bind(udpPort);
		udpPort.get = (k: number) => {
			asked.push(k);
			return get(k);
		};
		const frame = udp4(40000, 40000);
		const f = new Frame(frame, { ...dispatch, udpPort });
		dispatch.link.get("ethernet")?.(f, 0, frame.length);
		expect(asked).toEqual([40000]);
		expect(f.layers.at(-1)?.protocol).toBe("data");
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

describe("m2irFacts()", () => {
	const facts = m2irFacts();
	const mndp = facts.find((p) => p.protocol === "mndp");
	const of = (field: string) => mndp?.fields.find((f) => f.field === field);

	test("names the m2ir commit and files each protocol is generated from", () => {
		expect(facts.map((p) => p.protocol)).toEqual(["mndp"]);
		expect(mndp).toMatchObject({
			repository: "tikoci/m2ir",
			files: ["physical/mndp.yaml", "profiles/mndp/profile.yaml"],
			unnamed: [],
		});
		expect(mndp?.commit).toMatch(/^[0-9a-f]{40}$/);
		expect(list.find((d) => d.protocol === "mndp")?.reference).toContain(
			mndp?.commit.slice(0, 7) ?? "none",
		);
		expect(mndp?.versionsObserved).toHaveLength(19);
	});

	test("each field's versions and since; each value's and bit's own", () => {
		// m2ir profile.yaml at 677ece8: TLV 1 documented on every version
		// observed; TLV 19 observed-only from 7.24.5, its value 0 on 7.26beta5.
		expect(of("macAddress")?.versionsSeen).toEqual(mndp?.versionsObserved);
		expect(of("ttl")).toEqual({
			field: "ttl",
			tlv: 19,
			name: "ttl",
			confidence: "observed-only",
			versionsSeen: [
				"7.24.5",
				"7.24.6",
				"7.25beta5",
				"7.25",
				"7.25.1",
				"7.26beta5",
			],
			versionsSeenOf: "sender",
			since: "7.24.5",
			introduced: "7.24",
			values: [
				{
					value: 0,
					name: "dying-gasp",
					confidence: "observed-only",
					versionsSeen: ["7.26beta5"],
				},
			],
		});
		expect(of("running")?.bits?.map((b) => [b.value, b.name])).toEqual([
			[1, "capsman"],
			[2, "cmr"],
		]);
		// TLV 6's versions are the routers that answered a request.
		expect(of("requestHex")?.versionsSeenOf).toBe("receiver");
		expect(of("request")?.versionsSeenOf).toBe("receiver");
		expect(of("header")?.versionsSeenOf).toBe("sender");
		// m2ir's name for the header, not the record's.
		expect(of("header")?.name).toBe("announcement-counter");
	});

	test("every field it lists is one dissectors() lists for the protocol", () => {
		const names = new Set(
			list.find((d) => d.protocol === "mndp")?.fields.map((f) => f.name),
		);
		for (const f of mndp?.fields ?? []) expect(names).toContain(f.field);
		// Every TLV field the table names is there.
		expect(mndp?.fields.filter((f) => f.tlv !== undefined)).toHaveLength(18);
	});

	test("returns a new copy each call", () => {
		const before = structuredClone(m2irFacts());
		const a = m2irFacts();
		const p = a[0];
		if (p) {
			p.versionsObserved.push("changed");
			p.files.push("changed");
			p.unnamed.push("changed");
			p.fields[0]?.versionsSeen.push("changed");
			const ttl = p.fields.find((f) => f.field === "ttl");
			ttl?.values?.[0]?.versionsSeen.push("changed");
			if (ttl?.values?.[0]) ttl.values[0].name = "changed";
		}
		expect(m2irFacts()).toEqual(before);
	});
});
