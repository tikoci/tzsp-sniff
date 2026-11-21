import { afterAll, describe, expect, test } from "bun:test";
import {
	type Dissection,
	dissect as dissectFrame,
	dissectors,
	type FieldInfo,
	formatIpv6,
	type Layer,
	MAX_DHCP_OPTIONS,
	MAX_IPV6_EXTENSIONS,
	MAX_LLDP_TLVS,
	MAX_VLAN_TAGS,
} from "../../src/dissect.ts";
import { packetLine, viewPacket } from "../../src/records.ts";
import { parseTzsp } from "../../src/tzsp.ts";
import {
	bytes,
	dhcpFixture,
	dhcpFixtureIndex,
	dhcpFrame,
	dhcpMessage,
	echo,
	eth,
	ext8,
	fixture,
	fixtureIndex,
	fixtureInfo,
	h8,
	h16,
	ipv4,
	ipv6,
	lldpFixture,
	lldpFixtureIndex,
	MAC_A,
	MAC_B,
	opt,
	tcp,
	tlv,
	udp,
	utf8,
} from "./helpers.ts";

/** Declared fields, as `name` or `name[].item`, with their type and whether they may be absent. */
function declared(fields: readonly FieldInfo[], prefix = "") {
	const out = new Map<string, { type: string; optional: boolean }>();
	for (const f of fields) {
		out.set(`${prefix}${f.name}`, { type: f.type, optional: f.optional });
		for (const [k, v] of declared(f.items ?? [], `${prefix}${f.name}[].`))
			out.set(k, v);
	}
	return out;
}
const DECLARED = new Map(
	dissectors().map((d) => [d.protocol, declared(d.fields)]),
);

/**
 * Every field the vectors in this file produce, by protocol, as `name` or
 * `name[].item` with the JSON type it had. The last test checks them
 * against `dissectors()`, so a field the declarations miss, or one no vector
 * here exercises, fails (#25).
 */
const produced = new Map<string, Map<string, Set<string>>>();
/** Each layer or list item that lacks a field declared required. */
const missing: string[] = [];
const isItem = (i: unknown) =>
	typeof i === "object" && i !== null && !Array.isArray(i);
const jsonType = (v: unknown): string => {
	if (!Array.isArray(v)) return v === null ? "null" : typeof v;
	// An empty list says nothing of its items' type: either kind of list.
	if (v.length === 0) return "[]";
	if (v.every((i) => typeof i === "string")) return "string[]";
	return v.every(isItem) ? "object[]" : "mixed[]";
};
function note(protocol: string, fields: object, prefix = "") {
	const byName = produced.get(protocol) ?? new Map<string, Set<string>>();
	produced.set(protocol, byName);
	for (const [key, { optional }] of DECLARED.get(protocol) ?? []) {
		// The fields at this level: `name` at the top, `prefix` + `item` within a list.
		const rest = key.startsWith(prefix) ? key.slice(prefix.length) : undefined;
		if (optional || rest === undefined || rest.includes("[]")) continue;
		if (!(rest in fields)) missing.push(`${protocol} ${key}`);
	}
	for (const [name, value] of Object.entries(fields)) {
		const key = `${prefix}${name}`;
		byName.set(key, (byName.get(key) ?? new Set()).add(jsonType(value)));
		if (Array.isArray(value))
			for (const item of value)
				if (isItem(item)) note(protocol, item, `${key}[].`);
	}
}
/** `dissect`, noting every field each layer carries. */
const dissect = (frame: Uint8Array): Dissection => {
	const d = dissectFrame(frame);
	for (const l of d.layers)
		if (l.fields && l.protocol !== "data") note(l.protocol, l.fields);
	return d;
};

const frameOf = (datagramHex: string) => parseTzsp(bytes(datagramHex)).payload;
/** The layer type that can carry `P` (ICMP and ICMPv6 share one). */
type LayerOf<P> = Layer extends infer L
	? L extends Layer
		? P extends L["protocol"]
			? L
			: never
		: never
	: never;
const layer = <P extends Layer["protocol"]>(d: Dissection, protocol: P) =>
	d.layers.find((l) => l.protocol === protocol) as LayerOf<P>;

/** Every layer lies inside the one that carries it, and so inside the frame. */
function expectSpansInside(d: Dissection) {
	// Layers form one chain, each carried by the one before: a layer starts at
	// or after its parent and ends no later than it.
	let parentStart = 0;
	let parentEnd = d.frame.length;
	for (const l of d.layers) {
		expect(l.offset).toBeGreaterThanOrEqual(parentStart);
		expect(l.length).toBeGreaterThanOrEqual(0);
		expect(l.offset + l.length).toBeLessThanOrEqual(parentEnd);
		parentStart = l.offset;
		parentEnd = l.offset + l.length;
	}
}

describe("dissect: RouterOS captures", () => {
	// 7.25.1 x86_64 CHR, /tool/sniffer streaming an ICMP echo between 10.0.2.15
	// and 10.0.2.3, 2026-11-19 (#5; test/fixtures/README.md).
	test("sniffer stream: Ethernet, IPv4, ICMP echo request and reply", () => {
		const [request, reply] = fixture("7.25.1-x86-sniffer-stream");
		const d = dissect(frameOf(request as string));
		expect(d.protocols).toEqual(["ethernet", "ipv4", "icmp"]);
		expect(d.problem).toBeUndefined();
		expect(layer(d, "ethernet").fields).toEqual({
			dst: "52:55:0a:00:02:03",
			src: "02:82:57:4d:9a:01",
			etherType: "0x0800",
		});
		expect(layer(d, "ipv4")).toMatchObject({
			offset: 14,
			length: 56,
			fields: {
				totalLength: 56,
				ttl: 255,
				protocol: 1,
				protocolName: "icmp",
				src: "10.0.2.15",
				dst: "10.0.2.3",
				dontFragment: false,
			},
		});
		// On the wire, successive requests carry sequence bytes 00 00, 01 00,
		// 02 00: RouterOS's ping writes its counter little-endian. The field
		// is read in network byte order, as RFC 792 defines it, so it reads 0,
		// 256, 512.
		expect(layer(d, "icmp")).toMatchObject({
			offset: 34,
			length: 36,
			fields: { type: 8, typeName: "echo-request", id: 0xb200, sequence: 0 },
		});
		const back = dissect(frameOf(reply as string));
		expect(layer(back, "icmp").fields?.typeName).toBe("echo-reply");
		expect(layer(back, "ipv4").fields?.src).toBe("10.0.2.3");
	});

	test("every TZSP datagram of every RouterOS fixture dissects without a problem, except only-headers", () => {
		// The inventory comes from the fixture index, so a new capture is
		// covered without editing this list. Not TZSP, so not here: the saved
		// pcapng files (decode, #14) and sniff-pc's own format.
		const names = fixtureIndex()
			.map((e) => e.file)
			.filter(
				(f) =>
					f.endsWith(".hex") &&
					!f.includes("sniff-pc") &&
					!f.includes("only-headers"),
			)
			.map((f) => f.replace(/\.hex$/, ""));
		expect(names).toContain("7.25.1-arm64-sniffer-stream");
		expect(names.length).toBeGreaterThan(20);
		for (const name of names) {
			for (const hex of fixture(name)) {
				const d = dissect(frameOf(hex));
				expect({ name, problem: d.problem }).toEqual({
					name,
					problem: undefined,
				});
				expect(d.protocols[0]).toBe("ethernet");
				expectSpansInside(d);
			}
		}
	});

	test("only-headers: a 60-byte cut of a 1000-byte ping is a truncated IPv4 total length, ICMP still read", () => {
		for (const version of ["7.24.6", "7.25.1"]) {
			const d = dissect(
				frameOf(fixture(`${version}-x86-sniffer-only-headers`)[0] as string),
			);
			expect(d.frame.length).toBe(60);
			expect(layer(d, "ipv4")).toMatchObject({
				length: 46,
				problem: "truncated",
				reason: "total-length",
				fields: { totalLength: 1000 },
			});
			expect(d.problem).toEqual({
				protocol: "ipv4",
				problem: "truncated",
				reason: "total-length",
			});
			expect(layer(d, "icmp").fields).toMatchObject({
				typeName: "echo-request",
				length: 26,
			});
		}
	});

	test("mangle output: the router's own packets come with all-zero MACs", () => {
		const d = dissect(
			frameOf(fixture("7.25.1-x86-mangle-output")[0] as string),
		);
		expect(layer(d, "ethernet").fields).toMatchObject({
			dst: "00:00:00:00:00:00",
			src: "00:00:00:00:00:00",
		});
	});

	test("filter-stream=no: the sniffer's own stream is UDP to the listener port, its TZSP left as data", () => {
		const name = "7.25.1-x86-sniffer-filter-stream-no";
		const { listenerPort } = fixtureInfo(name);
		const d = dissect(frameOf(fixture(name)[1] as string));
		expect(d.protocols).toEqual(["ethernet", "ipv4", "udp", "data"]);
		expect(layer(d, "udp").fields).toMatchObject({ dstPort: listenerPort });
		// The data is the inner TZSP datagram, starting with RouterOS's header.
		const data = layer(d, "data");
		expect(Array.from(d.frame.subarray(data.offset, data.offset + 5))).toEqual([
			1, 0, 0, 1, 1,
		]);
	});

	// RouterOS 7.26beta5 x86 CHR /tool/sniffer streaming, 2026-11-14, from
	// tikoci/quickchr's CMR lab (examples/cmr/FINDINGS.md, "Wire"); the same
	// bytes as CMR_SYN in tzsp.test.ts.
	test("a TCP SYN with options (7.26beta5 x86, 2026-11-14, quickchr CMR lab)", () => {
		const d = dissect(
			frameOf(
				"010000010102fcb1face5f026401f40b5808004500003c3b13400040067ba5c0000202c00002018c50d431a771961b00000000a002faf00c960000020405b40402080a0deb107c0000000001030306",
			),
		);
		expect(d.protocols).toEqual(["ethernet", "ipv4", "tcp"]);
		expect(layer(d, "ipv4").fields).toMatchObject({
			dontFragment: true,
			ttl: 64,
		});
		expect(layer(d, "tcp").fields).toEqual({
			srcPort: 35920,
			dstPort: 54321,
			seq: 2809239067,
			ack: 0,
			headerLength: 40,
			flags: ["syn"],
			window: 64240,
			urgent: 0,
			payloadLength: 0,
		});
	});
});

describe("dissect: Ethernet and VLAN", () => {
	test("a frame shorter than an Ethernet header is truncated, with no fields", () => {
		for (const length of [0, 1, 13]) {
			const d = dissect(new Uint8Array(length));
			expect(d.layers).toEqual([
				{
					protocol: "ethernet",
					offset: 0,
					length,
					problem: "truncated",
					reason: "header",
				},
			]);
			expect(d.problem).toEqual({
				protocol: "ethernet",
				problem: "truncated",
				reason: "header",
			});
		}
	});

	test("an 802.3 length frame: LLC is left as data", () => {
		const d = dissect(bytes(eth(6, "424203000000")));
		expect(layer(d, "ethernet").fields).toEqual({
			dst: MAC_B,
			src: MAC_A,
			length: 6,
		});
		expect(d.protocols).toEqual(["ethernet", "data"]);
		expect(d.problem).toBeUndefined();
	});

	test("type/length 1501 to 1535 is malformed", () => {
		const d = dissect(bytes(eth(1501, "00")));
		expect(layer(d, "ethernet")).toMatchObject({
			problem: "malformed",
			reason: "type-length",
		});
	});

	test("an EtherType with no dissector is data, not a problem", () => {
		const d = dissect(bytes(eth(0x88b5, "0207")));
		expect(layer(d, "ethernet").fields?.etherType).toBe("0x88b5");
		expect(d.protocols).toEqual(["ethernet", "data"]);
		expect(d.problem).toBeUndefined();
	});

	test("802.1Q: priority, DEI and id, then the inner EtherType", () => {
		const tci = (5 << 13) | 0x1000 | 10;
		const d = dissect(
			bytes(
				eth(
					0x8100,
					`${h16(tci)}0800${ipv4({ proto: 17, payload: udp(1, 2, "") })}`,
				),
			),
		);
		expect(d.protocols).toEqual(["ethernet", "vlan", "ipv4", "udp"]);
		expect(layer(d, "vlan").fields).toEqual({
			priority: 5,
			dei: true,
			id: 10,
			etherType: "0x0800",
		});
	});

	test("QinQ: an 802.1ad outer tag, then an 802.1Q inner one", () => {
		const d = dissect(bytes(eth(0x88a8, `0064810000c80806${"00".repeat(28)}`)));
		expect(d.protocols).toEqual(["ethernet", "vlan", "vlan", "arp"]);
		const ids = d.layers.flatMap((l) =>
			l.protocol === "vlan" ? [l.fields?.id] : [],
		);
		expect(ids).toEqual([100, 200]);
	});

	test(`more than ${MAX_VLAN_TAGS} tags stop as unsupported`, () => {
		const tags = "00018100".repeat(MAX_VLAN_TAGS);
		const d = dissect(bytes(eth(0x8100, `${tags}0001080000`)));
		expect(d.layers.filter((l) => l.protocol === "vlan")).toHaveLength(
			MAX_VLAN_TAGS + 1,
		);
		expect(d.layers.at(-1)).toMatchObject({
			protocol: "vlan",
			problem: "unsupported",
			reason: "tag-limit",
		});
	});

	test("a cut VLAN tag is truncated", () => {
		const d = dissect(bytes(eth(0x8100, "00")));
		expect(d.layers.at(-1)).toMatchObject({
			protocol: "vlan",
			problem: "truncated",
			reason: "header",
		});
	});
});

describe("dissect: ARP", () => {
	const arp = (op: number) =>
		`00010800060400${h8(op)}${MAC_A.split(":").join("")}0a00020f${"00".repeat(6)}0a000203`;

	test("a request and a reply, and padding after them is not ARP's", () => {
		const padded = dissect(bytes(eth(0x0806, arp(1) + "00".repeat(18))));
		expect(layer(padded, "arp")).toEqual({
			protocol: "arp",
			offset: 14,
			length: 28,
			fields: {
				hardwareType: 1,
				protocolType: "0x0800",
				operation: 1,
				operationName: "request",
				senderMac: MAC_A,
				senderIp: "10.0.2.15",
				targetMac: "00:00:00:00:00:00",
				targetIp: "10.0.2.3",
			},
		});
		expect(
			layer(dissect(bytes(eth(0x0806, arp(2)))), "arp").fields?.operationName,
		).toBe("reply");
	});

	test("addresses that are not Ethernet and IPv4 are unsupported; a cut packet is truncated", () => {
		const other = dissect(
			bytes(eth(0x0806, `0006080006040001${"00".repeat(20)}`)),
		);
		expect(layer(other, "arp")).toMatchObject({
			problem: "unsupported",
			reason: "address-type",
		});
		expect(layer(other, "arp").fields?.senderIp).toBeUndefined();
		expect(
			layer(dissect(bytes(eth(0x0806, arp(1).slice(0, 30)))), "arp"),
		).toMatchObject({
			problem: "truncated",
			reason: "addresses",
		});
		expect(layer(dissect(bytes(eth(0x0806, "0001"))), "arp")).toMatchObject({
			problem: "truncated",
			reason: "header",
		});
	});
});

describe("dissect: IPv4", () => {
	const packet = (o: Parameters<typeof ipv4>[0]) =>
		dissect(bytes(eth(0x0800, ipv4(o))));

	test("a total length shorter than the frame trims Ethernet padding", () => {
		const d = dissect(
			bytes(
				eth(
					0x0800,
					ipv4({ proto: 17, payload: udp(5678, 5678, "aa") }) + "00".repeat(17),
				),
			),
		);
		expect(layer(d, "ipv4").length).toBe(29);
		expect(layer(d, "udp")).toMatchObject({
			length: 9,
			fields: { payloadLength: 1 },
		});
		expect(layer(d, "data").length).toBe(1);
	});

	test("options are kept as hex", () => {
		const d = packet({
			proto: 17,
			payload: udp(1, 2, ""),
			options: "94040000",
		});
		expect(layer(d, "ipv4").fields).toMatchObject({
			headerLength: 24,
			options: "94040000",
		});
		expect(layer(d, "udp").offset).toBe(38);
	});

	test("malformed and truncated headers", () => {
		const cases: [string, Partial<Layer>][] = [
			[eth(0x0800, "4500"), { problem: "truncated", reason: "header" }],
			[
				eth(0x0800, ipv4({ proto: 17, payload: "", version: 6 })),
				{ problem: "malformed", reason: "version" },
			],
			[
				eth(0x0800, ipv4({ proto: 17, payload: "", ihl: 4 })),
				{ problem: "malformed", reason: "header-length" },
			],
			// A 60-byte header that declares 60 bytes, but only 20 were captured.
			[
				eth(0x0800, ipv4({ proto: 17, payload: "", ihl: 15, totalLength: 60 })),
				{ problem: "truncated", reason: "header" },
			],
			// A 60-byte header in a 20-byte packet contradicts itself, whatever was captured.
			[
				eth(0x0800, ipv4({ proto: 17, payload: "", ihl: 15 })),
				{ problem: "malformed", reason: "total-length" },
			],
			[
				eth(0x0800, ipv4({ proto: 17, payload: "", totalLength: 19 })),
				{ problem: "malformed", reason: "total-length" },
			],
		];
		for (const [hex, expected] of cases) {
			const d = dissect(bytes(hex));
			expect(layer(d, "ipv4")).toMatchObject(expected);
			expect(d.layers.at(-1)?.protocol).toBe("ipv4");
		}
	});

	test("a later fragment is data; a first fragment's UDP length past the bytes is not a problem", () => {
		const later = packet({ proto: 17, payload: "aabbcc", flagsOffset: 185 });
		expect(later.protocols).toEqual(["ethernet", "ipv4", "data"]);
		expect(layer(later, "ipv4").fields).toMatchObject({
			fragmentOffset: 1480,
			moreFragments: false,
		});
		// 16 bytes of payload: a multiple of 8, as a non-final fragment must be.
		const first = packet({
			proto: 17,
			payload: udp(1, 2, "aabbccddeeff0011", 3000),
			flagsOffset: 0x2000,
		});
		expect(first.problem).toBeUndefined();
		expect(layer(first, "udp").fields).toMatchObject({
			length: 3000,
			payloadLength: 8,
		});
		const misaligned = packet({
			proto: 17,
			payload: udp(1, 2, "aabb", 3000),
			flagsOffset: 0x2000,
		});
		expect(layer(misaligned, "ipv4")).toMatchObject({
			problem: "malformed",
			reason: "fragment-length",
		});
		expect(misaligned.protocols).toEqual(["ethernet", "ipv4", "udp", "data"]);
	});

	test("a TCP header split across fragments: a whole first fragment holds data, a cut capture is truncated", () => {
		// 8 bytes of a TCP header in a complete first fragment: the rest is in the next one.
		const split = packet({
			proto: 6,
			payload: tcp({ sp: 1, dp: 2, flags: 2 }).slice(0, 16),
			flagsOffset: 0x2000,
		});
		expect(split.protocols).toEqual(["ethernet", "ipv4", "data"]);
		expect(split.problem).toBeUndefined();
		// The same 8 bytes in a packet that declares more: the capture ended early.
		const cut = packet({
			proto: 6,
			payload: tcp({ sp: 1, dp: 2, flags: 2 }).slice(0, 16),
			totalLength: 40,
		});
		expect(layer(cut, "tcp")).toMatchObject({
			problem: "truncated",
			reason: "header",
		});
	});

	test("an IP protocol with no dissector is data, named when known", () => {
		const d = packet({ proto: 47, payload: "00006558" });
		expect(layer(d, "ipv4").fields).toMatchObject({
			protocol: 47,
			protocolName: "gre",
		});
		expect(d.protocols).toEqual(["ethernet", "ipv4", "data"]);
	});
});

describe("dissect: IPv6", () => {
	const packet = (o: Parameters<typeof ipv6>[0]) =>
		dissect(bytes(eth(0x86dd, ipv6(o))));

	test("addresses in RFC 5952 form, and UDP after it", () => {
		const d = packet({ next: 17, payload: udp(546, 547, "01") });
		expect(layer(d, "ipv6").fields).toMatchObject({
			src: "fe80::1",
			dst: "2001:db8::2",
			hopLimit: 64,
			protocol: 17,
			protocolName: "udp",
			extensions: [],
		});
		expect(layer(d, "udp").fields?.dstPort).toBe(547);
	});

	test("extension headers are walked to the upper-layer protocol", () => {
		const d = packet({
			next: 0,
			extensions: ext8(60) + ext8(58),
			payload: echo(128, 1, 2),
		});
		expect(layer(d, "ipv6").fields?.extensions.map((e) => e.name)).toEqual([
			"hop-by-hop",
			"destination-options",
		]);
		expect(layer(d, "icmpv6")).toMatchObject({
			offset: 70,
			fields: { typeName: "echo-request", id: 1, sequence: 2 },
		});
	});

	test("a later fragment is data, with the fragment header's fields", () => {
		// Offset 185 units of 8 bytes (1480 bytes) in the top 13 bits, M set.
		const fragment = `1100${((185 << 3) | 1).toString(16).padStart(4, "0")}0000abcd`;
		const d = packet({
			next: 44,
			extensions: fragment,
			payload: "aa".repeat(8),
		});
		expect(layer(d, "ipv6").problem).toBeUndefined();
		expect(layer(d, "ipv6").fields).toMatchObject({
			fragmentOffset: 1480,
			moreFragments: true,
			fragmentId: 0xabcd,
			protocol: 17,
		});
		expect(d.protocols).toEqual(["ethernet", "ipv6", "data"]);
	});

	test("a fragment with M set must carry a multiple of 8 bytes", () => {
		const fragment = `1100${((185 << 3) | 1).toString(16).padStart(4, "0")}0000abcd`;
		const d = packet({ next: 44, extensions: fragment, payload: "aabb" });
		expect(layer(d, "ipv6")).toMatchObject({
			problem: "malformed",
			reason: "fragment-length",
		});
		// Still read: the data after the fragment header is there.
		expect(layer(d, "data").length).toBe(2);
	});

	test("a whole first fragment too short for the TCP header is malformed", () => {
		// Offset 0, M set, next header TCP; 16 bytes of TCP (a multiple of 8).
		const fragment = "0600000100000001";
		const d = packet({
			next: 44,
			extensions: fragment,
			payload: tcp({ sp: 1, dp: 2, flags: 2 }).slice(0, 32),
		});
		expect(layer(d, "tcp")).toMatchObject({
			problem: "malformed",
			reason: "header",
		});
	});

	test(`more than ${MAX_IPV6_EXTENSIONS} extension headers stop as unsupported`, () => {
		const chain = Array.from({ length: MAX_IPV6_EXTENSIONS + 1 }, () =>
			ext8(60),
		).join("");
		const d = packet({ next: 60, extensions: chain, payload: "" });
		expect(layer(d, "ipv6")).toMatchObject({
			problem: "unsupported",
			reason: "extension-limit",
		});
		expect(layer(d, "ipv6").fields?.extensions).toHaveLength(
			MAX_IPV6_EXTENSIONS,
		);
	});

	test("truncated and malformed", () => {
		expect(
			layer(dissect(bytes(eth(0x86dd, "60000000"))), "ipv6"),
		).toMatchObject({
			problem: "truncated",
			reason: "header",
		});
		expect(
			layer(packet({ next: 17, payload: "", version: 4 }), "ipv6"),
		).toMatchObject({
			problem: "malformed",
			reason: "version",
		});
		const long = packet({
			next: 17,
			payload: udp(1, 2, ""),
			payloadLength: 100,
		});
		expect(layer(long, "ipv6")).toMatchObject({
			problem: "truncated",
			reason: "payload-length",
		});
		expect(layer(long, "udp").fields?.srcPort).toBe(1);
		// A 16-byte extension in an 8-byte payload: the declaration contradicts it.
		const longExtension = packet({
			next: 0,
			extensions: "3b01000000000000",
			payload: "",
		});
		expect(layer(longExtension, "ipv6")).toMatchObject({
			problem: "malformed",
			reason: "extension-header",
		});
		// The payload declares the 16 bytes, but the capture ends after 8.
		const cutExtension = packet({
			next: 0,
			extensions: "3b01000000000000",
			payload: "",
			payloadLength: 16,
		});
		expect(layer(cutExtension, "ipv6")).toMatchObject({
			problem: "truncated",
			reason: "extension-header",
		});
	});

	test("ICMPv6 neighbor solicitation and advertisement carry their target address", () => {
		const ns = `8700000000000000${"20010db8000000000000000000000009"}`;
		const d = packet({ next: 58, payload: ns });
		expect(layer(d, "icmpv6").fields).toMatchObject({
			typeName: "neighbor-solicitation",
			targetAddress: "2001:db8::9",
		});
		// A neighbor advertisement: flags (router, solicited, override), then the target.
		const na = `88000000e0000000${"20010db8000000000000000000000009"}`;
		expect(layer(packet({ next: 58, payload: na }), "icmpv6").fields).toEqual({
			type: 136,
			code: 0,
			typeName: "neighbor-advertisement",
			length: 24,
			targetAddress: "2001:db8::9",
		});
		const cut = packet({ next: 58, payload: ns.slice(0, 20) });
		expect(layer(cut, "icmpv6")).toMatchObject({
			problem: "truncated",
			reason: "message",
		});
	});

	test("a whole IPv6 first fragment with a short ICMPv6 message is not exempt", () => {
		// Offset 0, M set, next header ICMPv6; 8 of the 24 bytes a neighbor
		// solicitation needs. Unlike IPv4, IPv6 puts the whole upper-layer
		// header in the first fragment, so the rest is not in a later one.
		const ns = `8700000000000000${"20010db8000000000000000000000009"}`;
		const d = packet({
			next: 44,
			extensions: "3a00000100000001",
			payload: ns.slice(0, 16),
		});
		expect(layer(d, "ipv6").problem).toBeUndefined();
		expect(layer(d, "icmpv6")).toMatchObject({
			problem: "truncated",
			reason: "message",
		});
	});
});

describe("dissect: cross-review vectors (#20)", () => {
	test("an 802.3 length bounds the LLC data: padding is not LLC's, a short frame is truncated", () => {
		const padded = dissect(bytes(eth(2, "4242aaaaaaaa")));
		expect(layer(padded, "data").length).toBe(2);
		expect(padded.problem).toBeUndefined();
		const cut = dissect(bytes(eth(9, "4242aaaaaaaa")));
		expect(layer(cut, "ethernet")).toMatchObject({
			problem: "truncated",
			reason: "length",
			fields: { length: 9 },
		});
		expect(layer(cut, "data").length).toBe(6);
	});

	test("the line names LLC after a VLAN tag's inner length, as untagged", () => {
		expect(packetLine(dissect(bytes(eth(0x8100, "000a0003424203"))))).toBe(
			`vlan 10 ${MAC_A} > ${MAC_B} llc len=21`,
		);
		expect(packetLine(dissect(bytes(eth(0x8100, "000a88b50207"))))).toBe(
			`vlan 10 ${MAC_A} > ${MAC_B} ethertype 0x88b5 len=20`,
		);
	});

	test("a reserved type/length (1501 to 1535) is not named LLC, untagged or tagged", () => {
		const untagged = dissect(bytes(eth(0x05dd, "00")));
		expect(packetLine(untagged)).toBe(
			`${MAC_A} > ${MAC_B} ethernet len=15 [malformed ethernet/type-length]`,
		);
		expect(viewPacket(untagged).protocol).toBe("ethernet");
		const tagged = dissect(bytes(eth(0x8100, "000a05dd00")));
		expect(packetLine(tagged)).toBe(
			`vlan 10 ${MAC_A} > ${MAC_B} vlan len=19 [malformed vlan/type-length]`,
		);
		expect(viewPacket(tagged).protocol).toBe("vlan");
		// A real 802.3 length is still LLC.
		expect(viewPacket(dissect(bytes(eth(3, "424203")))).protocol).toBe("llc");
	});

	test("a VLAN tag's inner type/length follows the same rules", () => {
		const llc = dissect(bytes(eth(0x8100, "000a0003424203aaaa")));
		expect(layer(llc, "vlan").fields).toEqual({
			priority: 0,
			dei: false,
			id: 10,
			length: 3,
		});
		expect(layer(llc, "data").length).toBe(3);
		const odd = dissect(bytes(eth(0x8100, "000a05dd00")));
		expect(layer(odd, "vlan")).toMatchObject({
			problem: "malformed",
			reason: "type-length",
		});
	});

	test("ARP with Ethernet and IPv4 types but other address lengths is malformed", () => {
		const d = dissect(bytes(eth(0x0806, "0001080000000001")));
		expect(layer(d, "arp")).toMatchObject({
			problem: "malformed",
			reason: "address-length",
		});
		// hlen 7 with only the 8-byte header captured: still the contradiction,
		// not missing addresses.
		const header = dissect(bytes(eth(0x0806, "0001080007040001")));
		expect(layer(header, "arp")).toMatchObject({
			length: 8,
			problem: "malformed",
			reason: "address-length",
		});
		// hlen 6 and plen 4, addresses not captured: truncated.
		const cut = dissect(bytes(eth(0x0806, "0001080006040001")));
		expect(layer(cut, "arp")).toMatchObject({
			problem: "truncated",
			reason: "addresses",
		});
	});

	test("an AH header too short for its fixed fields is malformed", () => {
		const ah = `1100${"00".repeat(6)}`; // next header UDP, payload length 0: 8 bytes
		const d = dissect(
			bytes(
				eth(0x86dd, ipv6({ next: 51, extensions: ah, payload: udp(1, 2, "") })),
			),
		);
		expect(layer(d, "ipv6")).toMatchObject({
			problem: "malformed",
			reason: "ah-length",
		});
		expect(d.protocols).toEqual(["ethernet", "ipv6"]);
	});

	test("after a later fragment's header, a next header that names an extension is still data", () => {
		// Next header 60 (destination options), offset 16: the 8 bytes after are fragment data.
		const fragment = "3c0000100000abcd";
		const d = dissect(
			bytes(
				eth(
					0x86dd,
					ipv6({ next: 44, extensions: fragment, payload: "0001020304050607" }),
				),
			),
		);
		expect(layer(d, "ipv6").fields?.extensions.map((e) => e.name)).toEqual([
			"fragment",
		]);
		expect(layer(d, "ipv6").problem).toBeUndefined();
		expect(layer(d, "data").length).toBe(8);
	});

	test("an ICMP error shorter than its fixed fields is truncated", () => {
		const d = dissect(
			bytes(eth(0x86dd, ipv6({ next: 58, payload: "02000000" }))),
		);
		expect(layer(d, "icmpv6")).toMatchObject({
			problem: "truncated",
			reason: "message",
			fields: { typeName: "packet-too-big" },
		});
		const v4 = dissect(
			bytes(
				eth(0x0800, ipv4({ proto: 1, payload: "0d000000" + "00".repeat(12) })),
			),
		);
		expect(layer(v4, "icmp")).toMatchObject({
			problem: "truncated",
			reason: "message",
		});
	});
});

describe("formatIpv6", () => {
	const cases: [string, string][] = [
		["00000000000000000000000000000000", "::"],
		["00000000000000000000000000000001", "::1"],
		["20010db8000000000000000000000001", "2001:db8::1"],
		// One zero group is not compressed.
		["20010db8000000010001000100010001", "2001:db8:0:1:1:1:1:1"],
		// The longest run wins.
		["20010db8000000000001000000000000", "2001:db8:0:0:1::"],
		// On a tie, the first run.
		["20010000000000010000000000010001", "2001::1:0:0:1:1"],
		["00000000000000000000ffffc0000201", "::ffff:192.0.2.1"],
		["fe800000000000000a0b0c0d0e0f0001", "fe80::a0b:c0d:e0f:1"],
	];
	for (const [hex, text] of cases) {
		test(`${hex} is ${text}`, () => expect(formatIpv6(bytes(hex))).toBe(text));
	}
});

describe("dissect: ICMP, UDP, TCP", () => {
	const v4 = (proto: number, payload: string) =>
		dissect(bytes(eth(0x0800, ipv4({ proto, payload }))));

	test("ICMP: a type with no name keeps its number; cut headers are truncated", () => {
		expect(layer(v4(1, "2a01000000"), "icmp").fields).toEqual({
			type: 42,
			code: 1,
			length: 5,
		});
		expect(layer(v4(1, "0800"), "icmp")).toMatchObject({
			problem: "truncated",
			reason: "header",
		});
		expect(layer(v4(1, "08000000b200"), "icmp")).toMatchObject({
			problem: "truncated",
			reason: "message",
			fields: { typeName: "echo-request" },
		});
	});

	test("UDP: a length under 8 or past the declared packet is malformed; past the captured bytes, truncated", () => {
		expect(layer(v4(17, udp(1, 2, "", 7)), "udp")).toMatchObject({
			problem: "malformed",
			reason: "length",
		});
		// 100 bytes of UDP in a packet that declares 9: a contradiction.
		expect(layer(v4(17, udp(1, 2, "aa", 100)), "udp")).toMatchObject({
			problem: "malformed",
			reason: "length",
			fields: { payloadLength: 1 },
		});
		// The packet declares the 100 bytes, but the capture ends after 9.
		const cut = dissect(
			bytes(
				eth(
					0x0800,
					ipv4({ proto: 17, payload: udp(1, 2, "aa", 100), totalLength: 120 }),
				),
			),
		);
		expect(layer(cut, "udp")).toMatchObject({
			problem: "truncated",
			reason: "length",
			fields: { payloadLength: 1 },
		});
		// Two bytes declared for UDP: no 8-byte header fits, whatever is captured.
		expect(layer(v4(17, "0001"), "udp")).toMatchObject({
			problem: "malformed",
			reason: "header",
		});
		// Twenty declared, two captured: the capture ended inside the header.
		const shortCut = dissect(
			bytes(eth(0x0800, ipv4({ proto: 17, payload: "0001", totalLength: 40 }))),
		);
		expect(layer(shortCut, "udp")).toMatchObject({
			problem: "truncated",
			reason: "header",
		});
	});

	test("TCP: flags, payload as data, and bad header lengths", () => {
		const d = v4(
			6,
			tcp({ sp: 8291, dp: 50000, flags: 0x18, ack: 7, payload: "deadbeef" }),
		);
		expect(layer(d, "tcp").fields).toMatchObject({
			flags: ["psh", "ack"],
			ack: 7,
			payloadLength: 4,
		});
		expect(d.protocols).toEqual(["ethernet", "ipv4", "tcp", "data"]);
		expect(
			layer(v4(6, tcp({ sp: 1, dp: 2, flags: 2, offset: 4 })), "tcp"),
		).toMatchObject({
			problem: "malformed",
			reason: "header-length",
		});
		// Data offset 24 in a packet that declares 20 TCP bytes: a contradiction.
		const noOptions = tcp({ sp: 1, dp: 2, flags: 2, offset: 6 });
		expect(layer(v4(6, noOptions), "tcp")).toMatchObject({
			problem: "malformed",
			reason: "header",
		});
		// The packet declares 24, the capture holds 20: truncated.
		const cutOptions = dissect(
			bytes(
				eth(0x0800, ipv4({ proto: 6, payload: noOptions, totalLength: 44 })),
			),
		);
		expect(layer(cutOptions, "tcp")).toMatchObject({
			problem: "truncated",
			reason: "header",
		});
		expect(layer(v4(6, "0001"), "tcp")).toMatchObject({
			problem: "malformed",
			reason: "header",
		});
		const cutHeader = dissect(
			bytes(eth(0x0800, ipv4({ proto: 6, payload: "0001", totalLength: 60 }))),
		);
		expect(layer(cutHeader, "tcp")).toMatchObject({
			problem: "truncated",
			reason: "header",
		});
	});

	test("ICMP in a whole IPv4 first fragment may go on in the next one", () => {
		// A 20-byte timestamp message, 16 bytes of it in this fragment (MF set).
		const head = `0d000000${"00".repeat(12)}`;
		const whole = dissect(
			bytes(
				eth(0x0800, ipv4({ proto: 1, payload: head, flagsOffset: 0x2000 })),
			),
		);
		expect(layer(whole, "icmp").problem).toBeUndefined();
		expect(whole.problem).toBeUndefined();
		// The fragment declares 24 bytes but the capture holds 16: truncated.
		const cut = dissect(
			bytes(
				eth(
					0x0800,
					ipv4({
						proto: 1,
						payload: head,
						flagsOffset: 0x2000,
						totalLength: 44,
					}),
				),
			),
		);
		expect(layer(cut, "icmp")).toMatchObject({
			problem: "truncated",
			reason: "message",
		});
	});
});

const LLDP_MULTICAST = "01:80:c2:00:00:0e";
const CHASSIS = tlv(1, "04020000000001");
const PORT = tlv(2, `05${utf8("ether1")}`);
const TTL = tlv(3, "0079");
const END = tlv(0, "");
const lldpFrame = (...tlvs: string[]) =>
	bytes(eth(0x88cc, tlvs.join(""), LLDP_MULTICAST));
const lldpOf = (...tlvs: string[]) => {
	const d = dissect(lldpFrame(...tlvs));
	return { d, l: layer(d, "lldp") };
};

describe("dissect: LLDP", () => {
	// test/lab/lldp/ (REPORT.md): what RouterOS sends with discovery as
	// booted, with lldp-vlan-info, lldp-mac-phy-config and
	// lldp-max-frame-size on, and with identity "lab-café" (UTF8_IDENTITY).
	test("RouterOS's own LLDPDUs decode whole, with no problem", () => {
		const index = lldpFixtureIndex();
		expect(index.map((e) => e.file).sort()).toEqual(
			["7.24.6-arm64", "7.24.6-x86", "7.25.1-arm64", "7.25.1-x86"].flatMap(
				(s) =>
					["default", "identity-utf8", "optional-tlvs"].map(
						(e) => `${s}-${e}.hex`,
					),
			),
		);
		for (const entry of index) {
			for (const hex of lldpFixture(entry.file)) {
				const frame = frameOf(hex);
				const d = dissect(frame);
				expect(d.protocols).toEqual(["ethernet", "lldp"]);
				expect(d.problem).toBeUndefined();
				expect(layer(d, "ethernet").fields?.dst).toBe(LLDP_MULTICAST);
				const l = layer(d, "lldp");
				// End is the last TLV RouterOS sends: nothing follows it.
				expect(l.offset + l.length).toBe(frame.length);
				const f = l.fields;
				expect(f).toMatchObject({
					chassisIdSubtype: "mac-address",
					chassisId: entry.mac,
					portIdSubtype: "interface-name",
					portId: "ether1",
					ttl: 121,
					portDescription: "ether1",
					systemName:
						entry.experiment === "identity-utf8" ? "lab-café" : entry.identity,
					capabilities: ["bridge", "router"],
					enabledCapabilities: ["router"],
				});
				expect(f?.systemDescription).toStartWith(
					`MikroTik RouterOS ${entry.routeros} `,
				);
				expect(f?.managementAddresses).toEqual([
					expect.objectContaining({
						familyName: "ipv4",
						address: "10.0.2.15",
						interfaceNumberingName: "ifIndex",
					}),
					expect.objectContaining({
						familyName: "ipv6",
						address: expect.stringMatching(/^fe80::/),
						interfaceNumberingName: "ifIndex",
					}),
				]);
				const named = f?.otherTlvs.map((t) => `${t.ouiName}/${t.subtypeName}`);
				expect(named).toEqual(
					entry.experiment === "default"
						? ["tia-lldp-med/capabilities"]
						: [
								"tia-lldp-med/capabilities",
								"ieee-802.3/mac-phy-config-status",
								"ieee-802.3/max-frame-size",
								"ieee-802.1/port-and-protocol-vlan-id",
							],
				);
				expect(packetLine(d)).toEndWith(
					`> ${LLDP_MULTICAST} lldp chassis ${entry.mac} port ether1 ttl 121 name ${f?.systemName}`,
				);
			}
		}
	});

	test("each id subtype is read as its kind", () => {
		const ids = (chassis: string, port: string) =>
			lldpOf(tlv(1, chassis), tlv(2, port), TTL, END).l.fields;
		expect(ids("05010a000001", "03020000000002")).toMatchObject({
			chassisIdSubtype: "network-address",
			chassisId: "10.0.0.1",
			portIdSubtype: "mac-address",
			portId: "02:00:00:00:00:02",
		});
		expect(
			ids("050220010db8000000000000000000000001", `07${utf8("p1")}`),
		).toMatchObject({
			chassisId: "2001:db8::1",
			portIdSubtype: "locally-assigned",
			portId: "p1",
		});
		expect(ids(`01${utf8("slot 1")}`, "060102")).toMatchObject({
			chassisIdSubtype: "chassis-component",
			chassisId: "slot 1",
			portIdSubtype: "agent-circuit-id",
			portId: "0102",
		});
		// A family other than IPv4, IPv6 and MAC, and a reserved subtype, are hex.
		expect(ids("0503aabb", "06aabb")).toMatchObject({
			chassisId: "aabb",
			portIdSubtype: "agent-circuit-id",
			portId: "aabb",
		});
		expect(ids("09aabb", "00cc")).toMatchObject({
			chassisIdSubtype: "subtype-9",
			chassisId: "aabb",
			portIdSubtype: "subtype-0",
			portId: "cc",
		});
	});

	test("a MAC or address whose length does not fit is malformed (tlv-length), and kept raw", () => {
		const cases: [string, string][] = [
			["chassisId", tlv(1, "0501")],
			["chassisId", tlv(1, "05010a0000")],
			["chassisId", tlv(1, "040200000001")],
			["portId", tlv(2, "03aabb")],
		];
		for (const [field, bad] of cases) {
			const tlvs = [CHASSIS, PORT, TTL, END];
			tlvs[field === "chassisId" ? 0 : 1] = bad;
			const { l } = lldpOf(...tlvs);
			expect(l).toMatchObject({ problem: "malformed", reason: "tlv-length" });
			expect(l.fields).not.toHaveProperty(field);
			expect(l.fields?.otherTlvs).toEqual([
				{
					type: field === "chassisId" ? 1 : 2,
					length: (bad.length - 4) / 2,
					value: bad.slice(4),
				},
			]);
		}
		// A management address of 3 bytes in family IPv4.
		const value = "04010a00000200000001" + "00";
		const mgmt = lldpOf(CHASSIS, PORT, TTL, tlv(8, value), END);
		expect(mgmt.l).toMatchObject({
			problem: "malformed",
			reason: "tlv-length",
		});
		expect(mgmt.l.fields?.managementAddresses).toEqual([]);
		expect(mgmt.l.fields?.otherTlvs).toEqual([{ type: 8, length: 11, value }]);
	});

	test("a management address whose lengths run past it is read only inside its span", () => {
		// The address length (0x20) puts the OID length past the TLV and the frame.
		const frame = lldpFrame(
			CHASSIS,
			tlv(2, "03020000000002"),
			TTL,
			tlv(8, "20010a000001020000"),
		);
		let furthest = -1;
		const watched = new Proxy(frame, {
			get(target, key) {
				if (typeof key === "string" && /^\d+$/.test(key))
					furthest = Math.max(furthest, Number(key));
				const v = Reflect.get(target, key, target);
				return typeof v === "function" ? v.bind(target) : v;
			},
		});
		const l = layer(dissect(watched), "lldp");
		expect(furthest).toBeLessThan(frame.length);
		expect(l).toMatchObject({ problem: "malformed", reason: "tlv-length" });
	});

	test("text that is not UTF-8 is malformed, and read with replacement characters", () => {
		const { d, l } = lldpOf(CHASSIS, PORT, TTL, tlv(5, "61ff"), END);
		expect(l.fields?.systemName).toBe("a�");
		expect(d.problem).toEqual({
			protocol: "lldp",
			problem: "malformed",
			reason: "text",
		});
		const id = lldpOf(tlv(1, "06ff"), PORT, TTL, END);
		expect(id.l).toMatchObject({ problem: "malformed", reason: "text" });
		expect(id.l.fields?.chassisId).toBe("�");
	});

	test("capabilities by name, an unnamed bit by number", () => {
		const { l } = lldpOf(
			CHASSIS,
			PORT,
			TTL,
			tlv(4, ""),
			tlv(6, utf8("desc")),
			tlv(7, "08140010"),
			END,
		);
		expect(l.fields).toMatchObject({
			portDescription: "",
			systemDescription: "desc",
			capabilities: ["bridge", "router", "bit-12"],
			enabledCapabilities: ["router"],
		});
		expect(l.problem).toBeUndefined();
	});

	test("management addresses: families, numbering and the OID", () => {
		// 1.3.6.1.4.1.14988 (MikroTik's enterprise number), BER-encoded.
		const oid = "2b06010401f50c";
		// An arc past 2^53 (2^54) still parses.
		const big = lldpOf(
			CHASSIS,
			PORT,
			TTL,
			tlv(8, "05010a000001" + "02" + "00000001" + "09" + "2ba080808080808000"),
			END,
		);
		expect(big.l.problem).toBeUndefined();
		expect(big.l.fields?.managementAddresses[0]?.oid).toBe(
			"1.3.18014398509481984",
		);
		const { l } = lldpOf(
			CHASSIS,
			PORT,
			TTL,
			tlv(8, `05010a000001030000000707${oid}`),
			tlv(8, "0706020000000003010000000000"),
			tlv(8, "036301ff090000000200"),
			END,
		);
		expect(l.problem).toBeUndefined();
		expect(l.fields?.managementAddresses).toEqual([
			{
				family: 1,
				familyName: "ipv4",
				address: "10.0.0.1",
				interfaceNumbering: 3,
				interfaceNumberingName: "system-port-number",
				interfaceNumber: 7,
				oid: "1.3.6.1.4.1.14988",
			},
			{
				family: 6,
				familyName: "mac",
				address: "02:00:00:00:00:03",
				interfaceNumbering: 1,
				interfaceNumberingName: "unknown",
				interfaceNumber: 0,
			},
			{
				family: 0x63,
				address: "01ff",
				interfaceNumbering: 9,
				interfaceNumber: 2,
			},
		]);
	});

	test("unknown interface numbering with a number other than 0 is malformed (interface-number)", () => {
		// 802.1AB-2009, 8.5.9.6: with unknown numbering the number "shall be set to zero".
		const { l } = lldpOf(
			CHASSIS,
			PORT,
			TTL,
			tlv(8, "05010a000001010000000100"),
			END,
		);
		expect(l).toMatchObject({
			problem: "malformed",
			reason: "interface-number",
		});
		expect(l.fields?.managementAddresses[0]).toMatchObject({
			interfaceNumberingName: "unknown",
			interfaceNumber: 1,
		});
	});

	test("a capability enabled but not supported is malformed (capabilities), and kept raw", () => {
		// 802.1AB-2009, 8.5.8.3: such a TLV "shall be discarded".
		const { l } = lldpOf(CHASSIS, PORT, TTL, tlv(7, "00000010"), END);
		expect(l).toMatchObject({ problem: "malformed", reason: "capabilities" });
		expect(l.fields).not.toHaveProperty("capabilities");
		expect(l.fields).not.toHaveProperty("enabledCapabilities");
		expect(l.fields?.otherTlvs).toEqual([
			{ type: 7, length: 4, value: "00000010" },
		]);
	});

	test("a frame in a Uint8Array subclass decodes, text included", () => {
		// subarray() would call the subclass's constructor, which takes an array here.
		class CaptureBytes extends Uint8Array {
			constructor(values: number[]) {
				super(values.map((b) => b));
			}
		}
		const plain = lldpFrame(CHASSIS, PORT, TTL, tlv(5, utf8("a")), END);
		const d = dissect(new CaptureBytes([...plain]));
		expect(d.problem).toBeUndefined();
		expect(layer(d, "lldp").fields).toMatchObject({
			portId: "ether1",
			systemName: "a",
		});
		const bad = lldpFrame(CHASSIS, PORT, TTL, tlv(5, "ff"), END);
		expect(
			layer(dissect(new CaptureBytes([...bad])), "lldp").fields?.systemName,
		).toBe("\uFFFD");
	});

	test("a management address with an OID that does not parse, or lengths that disagree, is malformed", () => {
		const badOid = lldpOf(
			CHASSIS,
			PORT,
			TTL,
			tlv(8, "05010a0000010200000001022b86"),
			END,
		);
		expect(badOid.l).toMatchObject({ problem: "malformed", reason: "oid" });
		expect(badOid.l.fields?.managementAddresses[0]).not.toHaveProperty("oid");
		// The address length runs past the OID length's place.
		const value = "09010a00000102000000010000";
		const bad = lldpOf(CHASSIS, PORT, TTL, tlv(8, value), END);
		expect(bad.l).toMatchObject({ problem: "malformed", reason: "tlv-length" });
		expect(bad.l.fields?.managementAddresses).toEqual([]);
		expect(bad.l.fields?.otherTlvs).toEqual([{ type: 8, length: 13, value }]);
	});

	test("organizationally specific and reserved TLVs are kept as hex", () => {
		const { l } = lldpOf(
			CHASSIS,
			PORT,
			TTL,
			tlv(127, "aabbcc01ff"),
			tlv(127, "0080c26300"),
			tlv(127, "00120f05aabb"),
			tlv(127, "00120f07cc"),
			tlv(9, "abcd"),
			END,
		);
		expect(l.problem).toBeUndefined();
		expect(l.fields?.otherTlvs).toEqual([
			{ type: 127, length: 5, value: "ff", oui: "aa-bb-cc", subtype: 1 },
			{
				type: 127,
				length: 5,
				value: "00",
				oui: "00-80-c2",
				ouiName: "ieee-802.1",
				subtype: 0x63,
			},
			{
				type: 127,
				length: 6,
				value: "aabb",
				oui: "00-12-0f",
				ouiName: "ieee-802.3",
				subtype: 5,
				subtypeName: "eee",
			},
			{
				type: 127,
				length: 5,
				value: "cc",
				oui: "00-12-0f",
				ouiName: "ieee-802.3",
				subtype: 7,
				subtypeName: "additional-ethernet-capabilities",
			},
			{ type: 9, length: 2, value: "abcd" },
		]);
	});

	test("a TLV past the frame is truncated, with the TLVs before it kept", () => {
		const { d, l } = lldpOf(CHASSIS, PORT, "060a", "616263");
		expect(l).toMatchObject({
			offset: 14,
			length: d.frame.length - 14,
			problem: "truncated",
			reason: "tlv",
		});
		expect(l.fields).toMatchObject({
			chassisId: "02:00:00:00:00:01",
			portId: "ether1",
		});
		// A TLV header cut short is the same.
		expect(lldpOf(CHASSIS, PORT, TTL, "02").l).toMatchObject({
			problem: "truncated",
			reason: "tlv",
		});
	});

	test("no End is truncated (end), with every TLV kept", () => {
		const { d, l } = lldpOf(CHASSIS, PORT, TTL);
		expect(l).toMatchObject({
			length: d.frame.length - 14,
			problem: "truncated",
			reason: "end",
		});
		expect(l.fields?.ttl).toBe(121);
		const empty = dissect(bytes(eth(0x88cc, "", LLDP_MULTICAST)));
		expect(layer(empty, "lldp")).toMatchObject({
			length: 0,
			fields: { managementAddresses: [], otherTlvs: [] },
			problem: "truncated",
			reason: "end",
		});
	});

	test("chassis id, port id and TTL not first and in order is malformed (order)", () => {
		const swapped = lldpOf(PORT, CHASSIS, TTL, END);
		expect(swapped.l).toMatchObject({ problem: "malformed", reason: "order" });
		expect(swapped.l.fields).toMatchObject({
			chassisId: "02:00:00:00:00:01",
			portId: "ether1",
			ttl: 121,
		});
		const short = lldpOf(CHASSIS, END);
		expect(short.l).toMatchObject({ problem: "malformed", reason: "order" });
		expect(short.l.fields).not.toHaveProperty("portId");
		expect(short.l.length).toBe(9 + 2);
	});

	test("a second chassis id, port id or TTL is malformed (repeated); a second optional TLV is only kept raw", () => {
		const name = lldpOf(
			CHASSIS,
			PORT,
			TTL,
			tlv(5, utf8("a")),
			tlv(5, utf8("b")),
			END,
		);
		// 802.1AB: "should not" appear more than once, not "shall".
		expect(name.l.problem).toBeUndefined();
		expect(name.l.fields?.systemName).toBe("a");
		expect(name.l.fields?.otherTlvs).toEqual([
			{ type: 5, length: 1, value: utf8("b") },
		]);
		const chassis = lldpOf(CHASSIS, PORT, TTL, tlv(1, "04020000000009"), END);
		expect(chassis.l).toMatchObject({
			problem: "malformed",
			reason: "repeated",
		});
		expect(chassis.l.fields?.chassisId).toBe("02:00:00:00:00:01");
		expect(chassis.l.fields?.otherTlvs).toEqual([
			{ type: 1, length: 7, value: "04020000000009" },
		]);
	});

	test("a TLV whose length is wrong for its type is malformed, and kept raw", () => {
		const ttl = lldpOf(CHASSIS, PORT, tlv(3, "007900"), END);
		expect(ttl.l).toMatchObject({ problem: "malformed", reason: "tlv-length" });
		expect(ttl.l.fields).not.toHaveProperty("ttl");
		expect(ttl.l.fields?.otherTlvs).toEqual([
			{ type: 3, length: 3, value: "007900" },
		]);
		for (const bad of [tlv(1, "04"), tlv(7, "0014"), tlv(127, "0080c2")]) {
			const { l } = lldpOf(CHASSIS, PORT, TTL, bad, END);
			expect(l).toMatchObject({ problem: "malformed", reason: "tlv-length" });
		}
		// An End with a length still ends the LLDPDU.
		const end = lldpOf(CHASSIS, PORT, TTL, tlv(0, "00"), tlv(5, utf8("x")));
		expect(end.l).toMatchObject({ problem: "malformed", reason: "tlv-length" });
		expect(end.l.fields).not.toHaveProperty("systemName");
		expect(end.l.fields?.otherTlvs).toEqual([
			{ type: 0, length: 1, value: "00" },
		]);
	});

	test(`at most ${MAX_LLDP_TLVS} TLVs are read, then unsupported (tlv-limit)`, () => {
		const reserved = (n: number) => Array(n).fill(tlv(9, "")).join("");
		const fits = lldpOf(CHASSIS, PORT, TTL, reserved(MAX_LLDP_TLVS - 4), END);
		expect(fits.l.problem).toBeUndefined();
		const over = lldpOf(CHASSIS, PORT, TTL, reserved(MAX_LLDP_TLVS - 3), END);
		expect(over.l).toMatchObject({
			length: 9 + 9 + 4 + 2 * (MAX_LLDP_TLVS - 3),
			problem: "unsupported",
			reason: "tlv-limit",
		});
		expect(over.l.fields?.otherTlvs).toHaveLength(MAX_LLDP_TLVS - 3);
	});

	test("bytes after End are not LLDP's, as Ethernet padding is not", () => {
		const { d, l } = lldpOf(CHASSIS, PORT, TTL, END, "ffffffff");
		expect(d.protocols).toEqual(["ethernet", "lldp"]);
		expect(d.problem).toBeUndefined();
		expect(l.length).toBe(9 + 9 + 4 + 2);
	});

	test("the line names chassis, port, TTL and system name, quoting text with spaces", () => {
		const { d } = lldpOf(CHASSIS, PORT, TTL, tlv(5, utf8("core sw")), END);
		expect(packetLine(d)).toBe(
			`${MAC_A} > ${LLDP_MULTICAST} lldp chassis 02:00:00:00:00:01 port ether1 ttl 121 name "core sw"`,
		);
		// Line and paragraph separators JSON leaves as they are are escaped too.
		const odd = lldpOf(
			CHASSIS,
			PORT,
			TTL,
			tlv(5, utf8("a\u0085b\u2028c")),
			END,
		);
		expect(packetLine(odd.d)).toEndWith(String.raw`name "a\u0085b\u2028c"`);
		expect(packetLine(lldpOf(PORT, END).d)).toBe(
			`${MAC_A} > ${LLDP_MULTICAST} lldp port ether1 [malformed lldp/order]`,
		);
		expect(viewPacket(d)).toMatchObject({
			protocol: "lldp",
			src: MAC_A,
			dst: LLDP_MULTICAST,
		});
	});
});

describe("dissect: DHCP", () => {
	const dhcpOf = (d: Dissection) => layer(d, "dhcp");
	/** The DHCP layer keeps every byte of the UDP payload, from AT to the frame's end. */
	const keepsAll = (d: Dissection) => {
		const l = dhcpOf(d);
		expect(l.offset).toBe(AT);
		expect(l.offset + l.length).toBe(d.frame.length);
	};
	/** Where the DHCP message starts in a dhcpFrame: Ethernet, IPv4 and UDP headers. */
	const AT = 14 + 20 + 8;

	// test/lab/dhcp/ (REPORT.md): RouterOS 7.25.1 and 7.24.6, x86_64 and
	// arm64, as a client of QEMU's SLIRP and of a RouterOS server, and as
	// that server, over a quickchr L2 link.
	test("what RouterOS sends and receives as a DHCP client and server decodes whole, with no problem", () => {
		const index = dhcpFixtureIndex();
		expect(index.map((e) => e.file).sort()).toEqual(
			["7.24.6-arm64", "7.24.6-x86", "7.25.1-arm64", "7.25.1-x86"].flatMap(
				(s) =>
					[
						"client-release",
						"client-renew",
						"server-exchange",
						"server-release",
					].map((e) => `${s}-${e}.hex`),
			),
		);
		const PRL = [
			"subnet-mask",
			"classless-static-route",
			"router",
			"static-route",
			"domain-server",
			"ntp-servers",
			"capwap-ac-v4",
			"vendor-specific",
			"domain-name",
		];
		let lines = 0;
		for (const entry of index) {
			const hexes = dhcpFixture(entry.file);
			expect(hexes).toHaveLength(entry.lines.length);
			hexes.forEach((hex, i) => {
				const { sender, message } = entry.lines[i] as {
					sender: string;
					message: string;
				};
				const frame = frameOf(hex);
				const d = dissect(frame);
				expect(d.protocols).toEqual(["ethernet", "ipv4", "udp", "dhcp"]);
				expect(d.problem).toBeUndefined();
				const l = dhcpOf(d);
				// RouterOS pads to the 300-byte BOOTP minimum; QEMU to 548.
				expect(l.offset + l.length).toBe(frame.length);
				expect(l.length).toBe(sender === "qemu-slirp" ? 548 : 300);
				const f = l.fields;
				expect(f?.messageTypeName).toBe(message);
				expect(f?.otherOptions).toEqual([]);
				const onEther1 = entry.experiment.startsWith("client-");
				const mac = onEther1 ? entry.serverEther1 : entry.clientEther2;
				expect(f?.chaddr).toBe(mac);
				if (sender === "routeros-client") {
					expect(f?.opName).toBe("request");
					expect(f?.clientId).toBe(`01${mac.replaceAll(":", "")}`);
					if (message === "discover" || message === "request") {
						expect(f?.parameterRequestList).toEqual(PRL);
						expect(f?.hostname).toBe(onEther1 ? "CHR" : "lab-café");
					}
					// use-broadcast=both: broadcast asked for until bound.
					expect(f?.broadcast).toBe(f?.ciaddr === "0.0.0.0");
				} else if (sender === "routeros-server") {
					expect(f).toMatchObject({
						opName: "reply",
						serverId: "192.168.88.1",
						subnetMask: "255.255.255.0",
						routers: ["192.168.88.1"],
						dnsServers: ["192.168.88.1"],
						domainName: "lab.test",
						leaseTime: 600,
						yiaddr: "192.168.88.20",
					});
					expect(f?.renewalTime).toBeUndefined();
				} else {
					expect(sender).toBe("qemu-slirp");
					expect(f).toMatchObject({
						opName: "reply",
						serverId: "10.0.2.2",
						yiaddr: "10.0.2.15",
						leaseTime: 86400,
					});
				}
				lines++;
			});
		}
		expect(lines).toBe(4 * (2 + 4 + 5 + 1));
	});

	test("a message with every decoded option reads into named fields", () => {
		const options =
			opt(53, "03") +
			opt(1, "ffffff00") +
			opt(3, "c0a85801c0a85802") +
			opt(6, "c0a85801") +
			opt(12, utf8("lab-café")) +
			opt(15, utf8("lab.test")) +
			opt(50, "c0a8580a") +
			opt(51, "00000258") +
			opt(54, "c0a85801") +
			opt(55, "0103060f79ff") +
			opt(57, "0240") +
			opt(58, "0000012c") +
			opt(59, "0000020d") +
			opt(60, utf8("MSFT 5.0")) +
			opt(61, `01${MAC_A.split(":").join("")}`) +
			opt(82, "0104000000010206aabbccddeeff") +
			opt(200, "beef") +
			"ff" +
			"000000";
		const frame = dhcpFrame(
			dhcpMessage({
				xid: 0x18152c13,
				flags: 0x8000,
				ciaddr: "192.168.88.10",
				giaddr: "10.0.0.1",
				sname: utf8("boot.lab"),
				file: utf8("pxelinux.0"),
				options,
			}),
		);
		const d = dissect(frame);
		expect(d.protocols).toEqual(["ethernet", "ipv4", "udp", "dhcp"]);
		expect(d.problem).toBeUndefined();
		const l = dhcpOf(d);
		// Padding after End is DHCP's: the layer runs to the datagram's end.
		expect(l.offset).toBe(AT);
		expect(l.offset + l.length).toBe(frame.length);
		expect(l.fields).toEqual({
			op: 1,
			opName: "request",
			hardwareType: 1,
			hardwareLength: 6,
			hops: 0,
			xid: "0x18152c13",
			secs: 0,
			flags: 0x8000,
			broadcast: true,
			ciaddr: "192.168.88.10",
			yiaddr: "0.0.0.0",
			siaddr: "0.0.0.0",
			giaddr: "10.0.0.1",
			chaddr: MAC_A,
			serverName: "boot.lab",
			bootFile: "pxelinux.0",
			messageType: 3,
			messageTypeName: "request",
			subnetMask: "255.255.255.0",
			routers: ["192.168.88.1", "192.168.88.2"],
			dnsServers: ["192.168.88.1"],
			hostname: "lab-café",
			domainName: "lab.test",
			requestedAddress: "192.168.88.10",
			leaseTime: 600,
			serverId: "192.168.88.1",
			parameterRequestList: [
				"subnet-mask",
				"router",
				"domain-server",
				"domain-name",
				"classless-static-route",
				"option-255",
			],
			maxMessageSize: 576,
			renewalTime: 300,
			rebindingTime: 525,
			vendorClassId: "MSFT 5.0",
			clientId: `01${MAC_A.split(":").join("")}`,
			otherOptions: [
				{
					code: 82,
					name: "relay-agent-information",
					length: 14,
					value: "0104000000010206aabbccddeeff",
				},
				{ code: 200, length: 2, value: "beef" },
			],
		});
	});

	test("a reply, an unnamed message type and a hardware address that is not Ethernet", () => {
		const d = dissect(
			dhcpFrame(
				dhcpMessage({
					op: 2,
					htype: 6,
					hlen: 8,
					yiaddr: "10.0.2.15",
					siaddr: "10.0.2.2",
					chaddr: "0102030405060708ffff",
					options: `${opt(53, "63")}ff`,
				}),
				67,
				68,
			),
		);
		expect(d.problem).toBeUndefined();
		expect(dhcpOf(d).fields).toMatchObject({
			op: 2,
			opName: "reply",
			chaddr: "0102030405060708",
			yiaddr: "10.0.2.15",
			messageType: 99,
		});
		expect(dhcpOf(d).fields?.messageTypeName).toBeUndefined();
		expect(dhcpOf(d).fields?.serverName).toBeUndefined();
		const unknown = dissect(dhcpFrame(dhcpMessage({ op: 7, options: "ff" })));
		expect(dhcpOf(unknown).fields?.opName).toBeUndefined();
	});

	test("reached by port with no decline: bytes on UDP 67 that are not DHCP are a dhcp layer with a problem, not data", () => {
		const d = dissect(dhcpFrame("0011223344", 40000, 67));
		expect(d.protocols).toEqual(["ethernet", "ipv4", "udp", "dhcp"]);
		const l = dhcpOf(d);
		expect(l).toMatchObject({
			offset: AT,
			length: 5,
			problem: "truncated",
			reason: "header",
		});
		expect(l.fields).toBeUndefined();
	});

	test("a header cut short is truncated (header), with no fields; one cut in the cookie keeps the header", () => {
		const message = dhcpMessage();
		const header = dissect(dhcpFrame(message.slice(0, 235 * 2)));
		expect(dhcpOf(header)).toMatchObject({
			length: 235,
			problem: "truncated",
			reason: "header",
		});
		expect(dhcpOf(header).fields).toBeUndefined();
		const cookie = dissect(dhcpFrame(message.slice(0, 238 * 2)));
		expect(dhcpOf(cookie)).toMatchObject({
			length: 238,
			problem: "truncated",
			reason: "cookie",
		});
		expect(dhcpOf(cookie).fields?.xid).toBe("0x12345678");
		expect(dhcpOf(cookie).fields?.messageType).toBeUndefined();
	});

	test("a wrong cookie is malformed (cookie), and nothing after it is read as options", () => {
		const d = dissect(
			dhcpFrame(
				dhcpMessage({ cookie: "63825364", options: `${opt(53, "01")}ff` }),
			),
		);
		expect(d.problem).toEqual({
			protocol: "dhcp",
			problem: "malformed",
			reason: "cookie",
		});
		keepsAll(d);
		const f = dhcpOf(d).fields;
		expect(f?.messageType).toBeUndefined();
		expect(f?.otherOptions).toEqual([]);
		expect(f?.chaddr).toBe(MAC_A);
	});

	test("an option past the datagram is truncated (option); options before it are kept", () => {
		const header = dissect(
			dhcpFrame(dhcpMessage({ options: `${opt(53, "01")}0c` })),
		);
		expect(dhcpOf(header)).toMatchObject({
			problem: "truncated",
			reason: "option",
		});
		expect(dhcpOf(header).fields?.messageTypeName).toBe("discover");
		keepsAll(header);
		const value = dissect(
			dhcpFrame(dhcpMessage({ options: `${opt(53, "01")}0c05616263` })),
		);
		expect(dhcpOf(value)).toMatchObject({
			problem: "truncated",
			reason: "option",
		});
		expect(dhcpOf(value).fields?.hostname).toBeUndefined();
		keepsAll(value);
	});

	test("an option repeated, its last piece cut short, is truncated (option); the pieces before it are kept raw, not read", () => {
		// Two routers announced, the second cut (RFC 3396): the list is incomplete.
		const d = dissect(
			dhcpFrame(
				dhcpMessage({
					options: `${opt(53, "03")}${opt(3, "0a000001")}03040a00`,
				}),
			),
		);
		expect(dhcpOf(d)).toMatchObject({ problem: "truncated", reason: "option" });
		keepsAll(d);
		const f = dhcpOf(d).fields;
		expect(f?.routers).toBeUndefined();
		expect(f?.messageType).toBe(3);
		expect(f?.otherOptions).toEqual([
			{ code: 3, name: "router", length: 4, value: "0a000001" },
		]);
	});

	test("no End is truncated (end)", () => {
		const d = dissect(
			dhcpFrame(dhcpMessage({ options: `${opt(53, "01")}0000` })),
		);
		expect(dhcpOf(d)).toMatchObject({ problem: "truncated", reason: "end" });
		expect(dhcpOf(d).fields?.messageType).toBe(1);
		keepsAll(d);
	});

	test("trailing zero bytes of a host name or domain name are deleted (RFC 2132, 2)", () => {
		const d = dissect(
			dhcpFrame(
				dhcpMessage({
					options: `${opt(12, "6c616200")}${opt(15, "6c61622e74657374000000")}ff`,
				}),
			),
		);
		expect(d.problem).toBeUndefined();
		expect(dhcpOf(d).fields).toMatchObject({
			hostname: "lab",
			domainName: "lab.test",
		});
	});

	test("a vendor class id keeps a leading byte-order mark, so it differs from the same id without one", () => {
		const bom = dissect(
			dhcpFrame(dhcpMessage({ options: `${opt(60, "efbbbf41")}ff` })),
		);
		const plain = dissect(
			dhcpFrame(dhcpMessage({ options: `${opt(60, "41")}ff` })),
		);
		expect(dhcpOf(bom).fields?.vendorClassId).toBe("\uFEFFA");
		expect(dhcpOf(plain).fields?.vendorClassId).toBe("A");
	});

	test("an overload value other than 1 to 3 is malformed (option-value), kept raw; sname and file stay text", () => {
		for (const value of ["00", "04", "ff"]) {
			const d = dissect(
				dhcpFrame(
					dhcpMessage({
						sname: utf8("srv"),
						file: utf8("file"),
						options: `${opt(53, "05")}${opt(52, value)}ff`,
					}),
				),
			);
			expect(dhcpOf(d)).toMatchObject({
				problem: "malformed",
				reason: "option-value",
			});
			const f = dhcpOf(d).fields;
			expect(f?.overload).toBeUndefined();
			expect(f).toMatchObject({ serverName: "srv", bootFile: "file" });
			expect(f?.serverNameHex).toBeUndefined();
			expect(f?.bootFileHex).toBeUndefined();
			expect(f?.otherOptions).toEqual([
				{ code: 52, name: "overload", length: 1, value },
			]);
		}
	});

	test("bytes after End are not read as options", () => {
		const d = dissect(
			dhcpFrame(
				dhcpMessage({ options: `${opt(53, "01")}ff${opt(12, "41")}0c` }),
			),
		);
		expect(d.problem).toBeUndefined();
		expect(dhcpOf(d).fields?.hostname).toBeUndefined();
		expect(dhcpOf(d).fields?.otherOptions).toEqual([]);
	});

	test("a wrong length for a decoded option is malformed (option-length), the option kept raw", () => {
		const d = dissect(
			dhcpFrame(
				dhcpMessage({
					options: `${opt(53, "0101")}${opt(1, "ffffff")}${opt(3, "0a000002ff")}${opt(61, "01")}ff`,
				}),
			),
		);
		expect(dhcpOf(d)).toMatchObject({
			problem: "malformed",
			reason: "option-length",
		});
		const f = dhcpOf(d).fields;
		expect(f?.messageType).toBeUndefined();
		expect(f?.subnetMask).toBeUndefined();
		expect(f?.otherOptions).toEqual([
			{ code: 53, name: "message-type", length: 2, value: "0101" },
			{ code: 1, name: "subnet-mask", length: 3, value: "ffffff" },
			{ code: 3, name: "router", length: 5, value: "0a000002ff" },
			{ code: 61, name: "client-id", length: 1, value: "01" },
		]);
	});

	test("a repeated option is joined before it is read (RFC 3396)", () => {
		const d = dissect(
			dhcpFrame(
				dhcpMessage({
					options:
						opt(53, "01") +
						opt(55, "0103") +
						opt(12, utf8("lab-")) +
						opt(200, "aa") +
						opt(55, "06") +
						opt(12, utf8("café")) +
						opt(200, "bb") +
						"ff",
				}),
			),
		);
		expect(d.problem).toBeUndefined();
		const f = dhcpOf(d).fields;
		expect(f?.parameterRequestList).toEqual([
			"subnet-mask",
			"router",
			"domain-server",
		]);
		expect(f?.hostname).toBe("lab-café");
		expect(f?.otherOptions).toEqual([{ code: 200, length: 2, value: "aabb" }]);
		// Joined, a decoded option is checked whole: two pieces of a mask
		// make one of the right length.
		const mask = dissect(
			dhcpFrame(
				dhcpMessage({ options: `${opt(1, "ffff")}${opt(1, "ff00")}ff` }),
			),
		);
		expect(mask.problem).toBeUndefined();
		expect(dhcpOf(mask).fields?.subnetMask).toBe("255.255.255.0");
	});

	test("option overload is unsupported (overload): sname and file kept as hex, not read", () => {
		for (const [value, sname, file] of [
			[1, false, true],
			[2, true, false],
			[3, true, true],
		] as const) {
			const d = dissect(
				dhcpFrame(
					dhcpMessage({
						sname: opt(12, utf8("x")),
						file: `${opt(15, utf8("y"))}ff`,
						options: `${opt(53, "05")}${opt(52, h8(value))}ff`,
					}),
				),
			);
			expect(dhcpOf(d)).toMatchObject({
				problem: "unsupported",
				reason: "overload",
			});
			const f = dhcpOf(d).fields;
			expect(f?.overload).toBe(value);
			expect(f?.hostname).toBeUndefined();
			expect(f?.domainName).toBeUndefined();
			expect(f?.serverNameHex !== undefined).toBe(sname);
			expect(f?.serverName !== undefined).toBe(!sname);
			expect(f?.bootFileHex !== undefined).toBe(file);
			expect(f?.bootFile !== undefined).toBe(!file);
			if (sname) expect(f?.serverNameHex).toStartWith("0c0178");
			if (file) expect(f?.bootFileHex).toStartWith("0f0179ff");
		}
	});

	test("text that is not UTF-8 is malformed (text), read with replacement characters; a vendor class that is not is kept raw", () => {
		const d = dissect(
			dhcpFrame(
				dhcpMessage({ options: `${opt(53, "01")}${opt(12, "41ff42")}ff` }),
			),
		);
		expect(dhcpOf(d)).toMatchObject({ problem: "malformed", reason: "text" });
		expect(dhcpOf(d).fields?.hostname).toBe("A�B");
		const sname = dissect(
			dhcpFrame(dhcpMessage({ sname: "c3", options: "ff" })),
		);
		expect(dhcpOf(sname)).toMatchObject({
			problem: "malformed",
			reason: "text",
		});
		expect(dhcpOf(sname).fields?.serverName).toBe("�");
		const vendor = dissect(
			dhcpFrame(dhcpMessage({ options: `${opt(60, "00ff")}ff` })),
		);
		expect(vendor.problem).toBeUndefined();
		expect(dhcpOf(vendor).fields?.vendorClassId).toBeUndefined();
		expect(dhcpOf(vendor).fields?.otherOptions).toEqual([
			{ code: 60, name: "class-id", length: 2, value: "00ff" },
		]);
	});

	test("a hardware length over 16 is malformed (hardware-length); chaddr is its 16 bytes", () => {
		const d = dissect(
			dhcpFrame(dhcpMessage({ htype: 1, hlen: 17, chaddr: "11".repeat(16) })),
		);
		expect(dhcpOf(d)).toMatchObject({
			problem: "malformed",
			reason: "hardware-length",
		});
		expect(dhcpOf(d).fields?.chaddr).toBe("11".repeat(16));
		// What stopped the reading is the cause reported, not the length.
		const bad = { htype: 1, hlen: 17 };
		const cases: [string, string, string][] = [
			[dhcpMessage(bad).slice(0, 238 * 2), "truncated", "cookie"],
			[dhcpMessage({ ...bad, options: "0c0541" }), "truncated", "option"],
			[dhcpMessage({ ...bad, options: "350101" }), "truncated", "end"],
			[
				dhcpMessage({
					...bad,
					options: `${"c800".repeat(MAX_DHCP_OPTIONS + 1)}ff`,
				}),
				"unsupported",
				"option-limit",
			],
			[dhcpMessage({ ...bad, cookie: "00000000" }), "malformed", "cookie"],
		];
		for (const [message, problem, reason] of cases)
			expect(dhcpOf(dissect(dhcpFrame(message)))).toMatchObject({
				problem,
				reason,
			});
	});

	test(`after ${MAX_DHCP_OPTIONS} options the layer is unsupported (option-limit); pad does not count`, () => {
		const many = `${"00".repeat(10)}${opt(200, "01").repeat(MAX_DHCP_OPTIONS)}`;
		const atLimit = dissect(dhcpFrame(dhcpMessage({ options: `${many}ff` })));
		expect(atLimit.problem).toBeUndefined();
		expect(dhcpOf(atLimit).fields?.otherOptions).toEqual([
			{
				code: 200,
				length: MAX_DHCP_OPTIONS,
				value: "01".repeat(MAX_DHCP_OPTIONS),
			},
		]);
		const over = dissect(
			dhcpFrame(dhcpMessage({ options: `${many}${opt(53, "01")}ff` })),
		);
		expect(dhcpOf(over)).toMatchObject({
			problem: "unsupported",
			reason: "option-limit",
		});
		expect(dhcpOf(over).fields?.messageType).toBeUndefined();
	});

	test("its line names the message type, xid, client MAC and addresses", () => {
		const request = dissect(
			dhcpFrame(
				dhcpMessage({
					xid: 0x18152c13,
					ciaddr: "10.0.2.15",
					options: `${opt(53, "03")}ff`,
				}),
			),
		);
		expect(packetLine(request)).toBe(
			`10.0.2.15:68 > 10.0.2.3:67 dhcp request xid 0x18152c13 mac ${MAC_A} client-ip 10.0.2.15`,
		);
		const offer = dissect(
			dhcpFrame(
				dhcpMessage({
					op: 2,
					yiaddr: "192.168.88.10",
					options: `${opt(53, "02")}ff`,
				}),
				67,
				68,
			),
		);
		expect(packetLine(offer)).toEndWith(
			`dhcp offer xid 0x12345678 mac ${MAC_A} your-ip 192.168.88.10`,
		);
		const discover = dissect(
			dhcpFrame(
				dhcpMessage({ options: `${opt(53, "01")}${opt(50, "c0a8580a")}ff` }),
			),
		);
		expect(packetLine(discover)).toEndWith(
			`dhcp discover xid 0x12345678 mac ${MAC_A} requested 192.168.88.10`,
		);
		const bootp = dissect(
			dhcpFrame(dhcpMessage({ op: 2, options: "ff" }), 67, 68),
		);
		expect(packetLine(bootp)).toEndWith(
			`dhcp reply xid 0x12345678 mac ${MAC_A}`,
		);
		const odd = dissect(
			dhcpFrame(dhcpMessage({ op: 9, options: `${opt(53, "63")}ff` })),
		);
		expect(packetLine(odd)).toContain(" dhcp type-99 ");
		const opOnly = dissect(dhcpFrame(dhcpMessage({ op: 9, options: "ff" })));
		expect(packetLine(opOnly)).toContain(" dhcp op-9 ");
		const cut = dissect(dhcpFrame("00"));
		expect(packetLine(cut)).toBe(
			"10.0.2.15:68 > 10.0.2.3:67 udp len=1 [truncated dhcp/header]",
		);
	});
});

describe("dissect: never throws, spans stay inside the frame", () => {
	test("every cut of real and built frames", () => {
		const frames = [
			frameOf(fixture("7.25.1-x86-sniffer-stream")[0] as string),
			frameOf(lldpFixture("7.25.1-x86-optional-tlvs.hex")[0] as string),
			dhcpFrame(
				dhcpMessage({
					options: `${opt(53, "01")}${opt(55, "0103")}${opt(12, "41")}ff000000`,
				}),
			),
			bytes(
				eth(
					0x8100,
					`000a86dd${ipv6({ next: 0, extensions: ext8(6), payload: tcp({ sp: 1, dp: 2, flags: 2, payload: "aa" }) })}`,
				),
			),
			bytes(
				eth(
					0x0806,
					`00010800060400010200000000000a0a00020f0000000000000a000203`,
				),
			),
		];
		for (const frame of frames) {
			for (let cut = 0; cut <= frame.length; cut++) {
				const d = dissect(frame.subarray(0, cut));
				expectSpansInside(d);
			}
		}
	});

	test("random bytes after each EtherType", () => {
		let seed = 1;
		const random = () => {
			seed = (seed * 1103515245 + 12345) % 2 ** 31;
			return seed / 2 ** 31;
		};
		for (const type of [0x0800, 0x86dd, 0x0806, 0x8100, 0x88a8, 0x88cc]) {
			for (let i = 0; i < 300; i++) {
				const body = Uint8Array.from(
					{ length: Math.floor(random() * 120) },
					() => Math.floor(random() * 256),
				);
				// Keep a valid version nibble half the time, so deeper layers are reached.
				if (body.length && random() < 0.5)
					body[0] = type === 0x86dd ? 0x60 : 0x45;
				const frame = new Uint8Array(14 + body.length);
				frame.set(bytes(eth(type, "")));
				frame.set(body, 14);
				expectSpansInside(dissect(frame));
			}
		}
	});
});

// After every test in the file, in any order (`bun test --seed`): it reads
// what all of them produced. A failure here is reported as an afterAll hook.
afterAll(() => {
	// Every field a vector produces is declared, with its type, and every
	// declared field is produced.
	{
		const list = dissectors();
		expect([...produced.keys()].sort()).toEqual(
			list.map((d) => d.protocol).sort(),
		);
		for (const d of list) {
			const want = declared(d.fields);
			const got = produced.get(d.protocol) ?? new Map<string, Set<string>>();
			expect({ protocol: d.protocol, fields: [...got.keys()].sort() }).toEqual({
				protocol: d.protocol,
				fields: [...want.keys()].sort(),
			});
			for (const [name, types] of got) {
				const type = want.get(name)?.type;
				for (const t of types) {
					const ok =
						t === type ||
						(t === "[]" && (type === "string[]" || type === "object[]"));
					expect({ protocol: d.protocol, name, type: t, ok }).toEqual({
						protocol: d.protocol,
						name,
						type: t,
						ok: true,
					});
				}
			}
		}
	}
	// Every layer and list item a vector produced carries each field not
	// declared optional.
	expect(missing).toEqual([]);
});
