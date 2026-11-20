import { describe, expect, test } from "bun:test";
import {
	type Dissection,
	dissect as dissectFrame,
	dissectors,
	type FieldInfo,
	formatIpv6,
	type Layer,
	MAX_IPV6_EXTENSIONS,
	MAX_VLAN_TAGS,
} from "../../src/dissect.ts";
import { packetLine, viewPacket } from "../../src/records.ts";
import { parseTzsp } from "../../src/tzsp.ts";
import {
	bytes,
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
	MAC_A,
	MAC_B,
	tcp,
	udp,
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
		const d = dissect(bytes(eth(0x88cc, "0207")));
		expect(layer(d, "ethernet").fields?.etherType).toBe("0x88cc");
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
		expect(packetLine(dissect(bytes(eth(0x8100, "000a88cc0207"))))).toBe(
			`vlan 10 ${MAC_A} > ${MAC_B} ethertype 0x88cc len=20`,
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

describe("dissect: never throws, spans stay inside the frame", () => {
	test("every cut of real and built frames", () => {
		const frames = [
			frameOf(fixture("7.25.1-x86-sniffer-stream")[0] as string),
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
		for (const type of [0x0800, 0x86dd, 0x0806, 0x8100, 0x88a8]) {
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

// Last in the file: it reads what every test above produced.
describe("dissect: fields match dissectors()", () => {
	test("every field a vector produces is declared, with its type, and every declared field is produced", () => {
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
	});

	test("every layer and list item a vector produced carries each field not declared optional", () => {
		expect(missing).toEqual([]);
	});
});
