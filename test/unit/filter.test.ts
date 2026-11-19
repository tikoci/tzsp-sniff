import { describe, expect, test } from "bun:test";
import { dissect } from "../../src/dissect.ts";
import { TzspSniffError } from "../../src/errors.ts";
import {
	createFilter,
	FILTER_KEYS,
	type FilterSpec,
	filterFlag,
	filterFlags,
} from "../../src/filter.ts";
import type { Capture } from "../../src/listen.ts";
import { parseTzsp } from "../../src/tzsp.ts";
import {
	bytes,
	echo,
	eth,
	h8,
	ipv4,
	ipv6,
	MAC_A,
	MAC_B,
	TZSP_HEADER,
	tcp,
	udp,
} from "./helpers.ts";

/**
 * Filters (DESIGN.md, "Filters"): repeating a term ORs, different terms AND,
 * `not` excludes, and a packet without a term's field matches no positive
 * term and is not excluded by a negated one.
 */

/** A captured frame, as the listener hands it over. */
function capture(
	frameHex: string,
	from: { label?: string; address?: string; port?: number } = {},
): Capture {
	const datagram = bytes(TZSP_HEADER + frameHex);
	return {
		seq: 1,
		time: 0,
		listener: { address: "0.0.0.0", port: 37008, label: from.label ?? "37008" },
		peer: {
			address: from.address ?? "127.0.0.1",
			port: from.port ?? 40000,
			family: from.address?.includes(":") ? "IPv6" : "IPv4",
		},
		datagram,
		tzsp: parseTzsp(datagram),
	};
}

const SSH = capture(
	eth(
		0x0800,
		ipv4({
			proto: 6,
			src: "10.0.2.15",
			dst: "192.0.2.7",
			payload: tcp({ sp: 50000, dp: 22, flags: 0x02 }),
		}),
	),
);
const DNS = capture(
	eth(
		0x0800,
		ipv4({
			proto: 17,
			src: "10.0.2.15",
			dst: "10.0.2.3",
			payload: udp(40000, 53, "abcd"),
		}),
		MAC_A,
		MAC_B,
	),
);
const PING = capture(eth(0x0800, ipv4({ proto: 1, payload: echo(8, 1, 1) })));
const ARP = capture(
	eth(
		0x0806,
		`0001080006040001${MAC_A.split(":").join("")}0a00020f${"00".repeat(6)}0a000203`,
	),
);
/** A later IPv4 fragment of a TCP datagram: no TCP header, so no ports. */
const LATER_FRAGMENT = capture(
	eth(
		0x0800,
		ipv4({ proto: 6, payload: "aabbccdd", flagsOffset: 185, dst: "192.0.2.7" }),
	),
);
/** A TCP header cut short (the IPv4 total length runs past the bytes): the layer is there, its fields are not. */
const CUT_TCP = capture(
	eth(0x0800, ipv4({ proto: 6, payload: "c35000", totalLength: 40 })),
);
/** An IPv4 header cut short: no addresses. */
const CUT_IP = capture(eth(0x0800, "4500001c"));
/** An 802.3 frame: a length, not an EtherType. */
const LLC = capture(eth(0x0040, "00".repeat(64)));
const CUT_ETH = capture("02000000000b02");
const V6_UDP = capture(
	eth(0x86dd, ipv6({ next: 17, payload: udp(546, 547, "00") })),
);
const VLAN_GRE = capture(
	eth(
		0x8100,
		`0064${"0800"}${ipv4({ proto: 47, src: "198.51.100.1", dst: "198.51.100.2", payload: "00006558" })}`,
	),
);

const keeps = (spec: FilterSpec, c: Capture) => createFilter(spec)(c);
const codeOf = (fn: () => unknown) => {
	try {
		fn();
	} catch (error) {
		if (error instanceof TzspSniffError) return error.code;
		throw error;
	}
	return undefined;
};

describe("createFilter: terms", () => {
	test("no terms keep everything", () => {
		for (const c of [SSH, ARP, CUT_IP]) expect(keeps({}, c)).toBe(true);
	});

	test("proto matches the chain, and the protocol the IP header names", () => {
		expect(keeps({ proto: ["tcp"] }, SSH)).toBe(true);
		expect(keeps({ proto: ["udp"] }, SSH)).toBe(false);
		expect(keeps({ proto: ["ARP"] }, ARP)).toBe(true);
		expect(keeps({ proto: ["vlan"] }, VLAN_GRE)).toBe(true);
		// No GRE dissector: the IPv4 header names it.
		expect(keeps({ proto: ["gre"] }, VLAN_GRE)).toBe(true);
		// A later fragment of a TCP datagram is TCP by its IP header.
		expect(keeps({ proto: ["tcp"] }, LATER_FRAGMENT)).toBe(true);
		expect(keeps({ proto: ["ipv6"] }, V6_UDP)).toBe(true);
		// `data` is not a protocol.
		expect(codeOf(() => createFilter({ proto: ["data"] }))).toBe(
			"filter/invalid-value",
		);
	});

	test("host matches either endpoint, src- and dst- one side, ARP included", () => {
		expect(keeps({ host: ["192.0.2.7"] }, SSH)).toBe(true);
		expect(keeps({ host: ["10.0.2.15"] }, SSH)).toBe(true);
		expect(keeps({ srcHost: ["192.0.2.7"] }, SSH)).toBe(false);
		expect(keeps({ dstHost: ["192.0.2.7"] }, SSH)).toBe(true);
		expect(keeps({ srcHost: ["10.0.2.15"] }, ARP)).toBe(true);
		expect(keeps({ dstHost: ["10.0.2.3"] }, ARP)).toBe(true);
		// IPv6, written any way that names the same address.
		expect(keeps({ dstHost: ["2001:DB8:0:0::2"] }, V6_UDP)).toBe(true);
		expect(keeps({ srcHost: ["fe80::1"] }, V6_UDP)).toBe(true);
		expect(keeps({ host: ["fe80::2"] }, V6_UDP)).toBe(false);
	});

	test("net matches a prefix of either endpoint, IPv4 and IPv6", () => {
		expect(keeps({ net: ["192.0.2.0/24"] }, SSH)).toBe(true);
		expect(keeps({ net: ["192.0.3.0/24"] }, SSH)).toBe(false);
		expect(keeps({ srcNet: ["10.0.0.0/8"] }, SSH)).toBe(true);
		expect(keeps({ dstNet: ["10.0.0.0/8"] }, SSH)).toBe(false);
		// Bits past the prefix are ignored; /0 matches its family only.
		expect(keeps({ net: ["192.0.2.200/24"] }, SSH)).toBe(true);
		expect(keeps({ net: ["192.0.2.200/25"] }, SSH)).toBe(false);
		expect(keeps({ net: ["0.0.0.0/0"] }, V6_UDP)).toBe(false);
		expect(keeps({ net: ["2001:db8::/32"] }, V6_UDP)).toBe(true);
		expect(keeps({ dstNet: ["2001:db9::/32"] }, V6_UDP)).toBe(false);
		// A bare address is one host.
		expect(keeps({ net: ["10.0.2.15"] }, SSH)).toBe(true);
	});

	test("proto matches an IPv6 extension that is a protocol: AH", () => {
		// RFC 4302: next header UDP, payload length 4 (24 bytes), SPI, sequence, ICV.
		const ah = `1104${"0000"}${"00000001"}${"00000001"}${"00".repeat(12)}`;
		const c = capture(
			eth(0x86dd, ipv6({ next: 51, extensions: ah, payload: udp(1, 2, "") })),
		);
		expect(dissect(c.tzsp.payload as Uint8Array).protocols).toEqual([
			"ethernet",
			"ipv6",
			"udp",
		]);
		expect(keeps({ proto: ["ah"] }, c)).toBe(true);
		expect(keeps({ not: { proto: ["ah"] } }, c)).toBe(false);
		expect(keeps({ proto: ["ah"] }, V6_UDP)).toBe(false);
	});

	test("proto ah still matches when the AH header is malformed or cut short", () => {
		for (const [what, extensions, payload] of [
			[
				"too short for its fixed fields",
				`1100${"00".repeat(6)}`,
				udp(1, 2, ""),
			],
			["past the declared payload", "", ""],
		] as const) {
			const c = capture(eth(0x86dd, ipv6({ next: 51, extensions, payload })));
			const ip = dissect(c.tzsp.payload as Uint8Array).layers.find(
				(l) => l.protocol === "ipv6",
			);
			expect({
				what,
				problem: ip?.problem,
				name: ip?.fields?.protocolName,
			}).toEqual({
				what,
				problem: "malformed",
				name: undefined,
			});
			expect({ what, kept: keeps({ proto: ["ah"] }, c) }).toEqual({
				what,
				kept: true,
			});
			expect({ what, kept: keeps({ not: { proto: ["ah"] } }, c) }).toEqual({
				what,
				kept: false,
			});
		}
		// Cut short by the capture: a valid AH header whose IPv6 payload length
		// still counts all 24 bytes, sliced after 3 of them.
		const ah = `1104${"0000"}${"00000001"}${"00000001"}${"00".repeat(12)}`;
		const cut = capture(
			eth(
				0x86dd,
				ipv6({
					next: 51,
					extensions: ah.slice(0, 6),
					payload: "",
					payloadLength: 32,
				}),
			),
		);
		const ip = dissect(cut.tzsp.payload as Uint8Array).layers.find(
			(l) => l.protocol === "ipv6",
		);
		expect(ip).toMatchObject({ problem: "truncated" });
		expect(ip?.fields?.protocolName).toBeUndefined();
		expect(keeps({ proto: ["ah"] }, cut)).toBe(true);
		expect(keeps({ not: { proto: ["ah"] } }, cut)).toBe(false);
	});

	test("port-match matches UDP and TCP ports", () => {
		expect(keeps({ portMatch: [22] }, SSH)).toBe(true);
		expect(keeps({ portMatch: ["50000"] }, SSH)).toBe(true);
		expect(keeps({ srcPortMatch: [22] }, SSH)).toBe(false);
		expect(keeps({ dstPortMatch: [22] }, SSH)).toBe(true);
		expect(keeps({ dstPortMatch: [53] }, DNS)).toBe(true);
		expect(keeps({ portMatch: [547] }, V6_UDP)).toBe(true);
	});

	test("mac matches the Ethernet source or destination, in any common spelling", () => {
		expect(keeps({ mac: ["02-00-00-00-00-0A"] }, SSH)).toBe(true);
		expect(keeps({ srcMac: [MAC_A] }, SSH)).toBe(true);
		expect(keeps({ srcMac: [MAC_A] }, DNS)).toBe(false);
		expect(keeps({ dstMac: ["02000000000A"] }, DNS)).toBe(true);
		// DNS is sent from MAC_B.
		expect(keeps({ dstMac: [MAC_B] }, DNS)).toBe(false);
		expect(keeps({ mac: ["02:00:00:00:00:0c"] }, SSH)).toBe(false);
	});

	test("ether-type matches the Ethernet header or any VLAN tag", () => {
		expect(keeps({ etherType: ["0x0800"] }, SSH)).toBe(true);
		expect(keeps({ etherType: ["0x806"] }, ARP)).toBe(true);
		expect(keeps({ etherType: ["0x8100"] }, VLAN_GRE)).toBe(true);
		expect(keeps({ etherType: ["0x0800"] }, VLAN_GRE)).toBe(true);
		expect(keeps({ etherType: ["0x86DD"] }, SSH)).toBe(false);
	});

	test("sender matches the listener label or the UDP peer, never a field in the packet", () => {
		const c = capture(eth(0x0800, ipv4({ proto: 1, payload: echo(8, 1, 1) })), {
			label: "router-a",
			address: "10.0.2.2",
			port: 5000,
		});
		expect(keeps({ sender: ["router-a"] }, c)).toBe(true);
		expect(keeps({ sender: ["router-b"] }, c)).toBe(false);
		expect(keeps({ sender: ["10.0.2.2"] }, c)).toBe(true);
		expect(keeps({ sender: ["10.0.2.2:5000"] }, c)).toBe(true);
		expect(keeps({ sender: ["10.0.2.2:5001"] }, c)).toBe(false);
		// The packet's own source is 10.0.2.15; the sender is not.
		expect(keeps({ sender: ["10.0.2.15"] }, c)).toBe(false);
		// A socket bound to :: reports an IPv4 peer as IPv4-mapped.
		const mapped = capture(eth(0x0800, ipv4({ proto: 1, payload: "" })), {
			address: "::ffff:10.0.2.2",
		});
		expect(keeps({ sender: ["10.0.2.2"] }, mapped)).toBe(true);
		const v6 = capture(eth(0x0800, ipv4({ proto: 1, payload: "" })), {
			address: "fe80::1%lo",
			port: 7,
		});
		expect(keeps({ sender: ["[fe80::1]:7"] }, v6)).toBe(true);
		// The default label is the port.
		expect(keeps({ sender: ["37008"] }, PING)).toBe(true);
	});

	test("a sender label matches exactly as spelled, even one that reads as an address", () => {
		const c = capture(eth(0x0800, ipv4({ proto: 1, payload: "" })), {
			label: "2001:0DB8::0001",
			address: "127.0.0.1",
		});
		const f = createFilter({ sender: ["2001:0DB8::0001"] });
		expect(f(c)).toBe(true);
		// The spec it advertises makes the same decision.
		expect(f.spec.sender).toEqual(["2001:0DB8::0001"]);
		expect(createFilter(f.spec)(c)).toBe(true);
		// Two spellings of one address are two labels: both kept.
		const both = createFilter({ sender: ["2001:db8::1", "2001:0DB8::0001"] });
		expect(both.spec.sender).toEqual(["2001:db8::1", "2001:0DB8::0001"]);
		expect(both(c)).toBe(true);
		// The library takes any label a listener can have.
		const spaced = capture(eth(0x0800, ipv4({ proto: 1, payload: "" })), {
			label: "router west",
		});
		expect(keeps({ sender: ["router west"] }, spaced)).toBe(true);
		expect(keeps({ sender: ["router"] }, spaced)).toBe(false);
		// Not trimmed either: the spelling is the label.
		const padded = capture(eth(0x0800, ipv4({ proto: 1, payload: "" })), {
			label: " edge",
		});
		expect(keeps({ sender: [" edge"] }, padded)).toBe(true);
		expect(keeps({ sender: ["edge"] }, padded)).toBe(false);
	});
});

describe("createFilter: combining", () => {
	test("repeating a term ORs its values; different terms AND", () => {
		expect(keeps({ proto: ["udp", "tcp"] }, SSH)).toBe(true);
		expect(keeps({ proto: ["udp", "tcp"] }, PING)).toBe(false);
		expect(keeps({ proto: ["tcp"], portMatch: [22] }, SSH)).toBe(true);
		expect(keeps({ proto: ["tcp"], portMatch: [53] }, SSH)).toBe(false);
		expect(keeps({ proto: ["udp"], portMatch: [22] }, SSH)).toBe(false);
	});

	test("not excludes a packet matching any value of any negated term", () => {
		expect(keeps({ not: { portMatch: [22] } }, SSH)).toBe(false);
		expect(keeps({ not: { portMatch: [22] } }, DNS)).toBe(true);
		expect(keeps({ not: { portMatch: [80, 53] } }, DNS)).toBe(false);
		expect(keeps({ not: { proto: ["icmp"], host: ["192.0.2.7"] } }, SSH)).toBe(
			false,
		);
		expect(
			keeps({ proto: ["tcp"], not: { srcHost: ["10.0.2.15"] } }, SSH),
		).toBe(false);
	});

	// Each case: a packet that lacks the field. A positive term never keeps
	// it; the negated term never removes it.
	const missing: [string, Capture, FilterSpec][] = [
		["ports on an ARP frame", ARP, { portMatch: [22] }],
		["src ports on an ARP frame", ARP, { srcPortMatch: [22] }],
		["ports on a later IP fragment", LATER_FRAGMENT, { dstPortMatch: [22] }],
		["ports in a TCP header cut short", CUT_TCP, { portMatch: [50000] }],
		["addresses in an IP header cut short", CUT_IP, { host: ["10.0.2.15"] }],
		["a prefix in an IP header cut short", CUT_IP, { net: ["0.0.0.0/0"] }],
		["an IPv4 host on IPv6", V6_UDP, { net: ["0.0.0.0/0"] }],
		["an EtherType on an 802.3 frame", LLC, { etherType: ["0x0800"] }],
		["a MAC in an Ethernet header cut short", CUT_ETH, { mac: [MAC_A] }],
	];
	for (const [what, c, spec] of missing) {
		test(`a packet without the field: ${what}`, () => {
			expect(keeps(spec, c)).toBe(false);
			expect(keeps({ not: spec }, c)).toBe(true);
		});
	}

	test("the cut TCP header and the later fragment really have no ports", () => {
		const cut = dissect(CUT_TCP.tzsp.payload as Uint8Array);
		expect(cut.layers.find((l) => l.protocol === "tcp")).toMatchObject({
			problem: "truncated",
		});
		expect(
			cut.layers.find((l) => l.protocol === "tcp")?.fields,
		).toBeUndefined();
		const later = dissect(LATER_FRAGMENT.tzsp.payload as Uint8Array);
		expect(later.protocols).toEqual(["ethernet", "ipv4", "data"]);
	});

	test("a record that is not a frame has no frame fields, and still has a sender", () => {
		const keepalive: Capture = { ...PING, tzsp: parseTzsp(bytes("01040000")) };
		expect(keeps({ proto: ["ethernet"] }, keepalive)).toBe(false);
		expect(keeps({ not: { proto: ["ethernet"] } }, keepalive)).toBe(true);
		expect(keeps({ sender: ["37008"] }, keepalive)).toBe(true);
	});

	test("a dissection passed in is used, not made again", () => {
		const d = dissect(SSH.tzsp.payload as Uint8Array);
		const pretend = {
			...d,
			layers: d.layers.filter((l) => l.protocol !== "tcp"),
		};
		expect(createFilter({ proto: ["tcp"] })(SSH, pretend)).toBe(true);
		const noTcp = {
			...pretend,
			layers: pretend.layers.map((l) =>
				l.protocol === "ipv4" ? { ...l, fields: undefined } : l,
			),
		} as typeof d;
		expect(createFilter({ proto: ["tcp"] })(SSH, noTcp)).toBe(false);
	});
});

const CYCLIC: Record<string, unknown> = {};
CYCLIC.self = CYCLIC;

describe("createFilter: the spec", () => {
	test("canonical values, duplicates dropped, flags in registry order", () => {
		const f = createFilter({
			sender: ["router-a"],
			proto: ["TCP", "tcp"],
			net: ["10.1.2.3/8"],
			host: ["2001:0DB8::0001"],
			mac: ["02-00-00-00-00-0A"],
			etherType: ["0x800"],
			portMatch: ["0443"],
			not: { dstHost: ["::ffff:10.0.0.1"] },
		});
		expect(f.spec).toEqual({
			proto: ["tcp"],
			host: ["2001:db8::1"],
			net: ["10.0.0.0/8"],
			portMatch: [443],
			mac: ["02:00:00:00:00:0a"],
			etherType: ["0x0800"],
			sender: ["router-a"],
			not: { dstHost: ["::ffff:10.0.0.1"] },
		});
		expect(f.flags).toEqual([
			"--proto tcp",
			"--host 2001:db8::1",
			"--net 10.0.0.0/8",
			"--port-match 443",
			"--mac 02:00:00:00:00:0a",
			"--ether-type 0x0800",
			"--sender router-a",
			"--not-dst-host ::ffff:10.0.0.1",
		]);
		// The canonical spec makes the same filter.
		expect(createFilter(f.spec).spec).toEqual(f.spec);
	});

	test("flags quote a value that is not one shell word, so it pastes back", () => {
		const labels = ["router west", "it's", "[::1]:5", "*", ""];
		const flags = filterFlags({ sender: ["a-b.c", ...labels] });
		expect(flags).toEqual([
			"--sender a-b.c",
			"--sender 'router west'",
			"--sender 'it'\\''s'",
			"--sender '[::1]:5'",
			"--sender '*'",
			"--sender ''",
		]);
	});

	// The quoting is POSIX shell's; Windows runners do not promise an `sh`.
	test.skipIf(process.platform === "win32")(
		"a POSIX shell reads each quoted flag back as the flag and the value, whole",
		() => {
			const labels = [
				"router west",
				"it's",
				"[::1]:5",
				"*",
				"",
				"--help",
				"-x y",
			];
			for (const label of labels) {
				const [flag] = filterFlags({ sender: [label] });
				const out = Bun.spawnSync(["sh", "-c", `printf '%s\\n' ${flag}`]);
				// A value starting with "-" is joined: one word, flag=value.
				expect(out.stdout.toString()).toBe(
					label.startsWith("-")
						? `--sender=${label}\n`
						: `--sender\n${label}\n`,
				);
			}
		},
	);

	test("empty lists and undefined terms are not set", () => {
		// As a JavaScript caller may write it.
		const f = createFilter({
			host: [],
			proto: undefined,
			not: {},
		} as unknown as FilterSpec);
		expect(f.spec).toEqual({});
		expect(f.flags).toEqual([]);
	});

	test("every term has a flag", () => {
		expect(FILTER_KEYS.map(filterFlag)).toContain("src-port-match");
		expect(FILTER_KEYS.map(filterFlag)).toContain("ether-type");
	});

	test("an unknown term or a value it cannot read is refused, naming the flag", () => {
		const cases: [unknown, string][] = [
			[{ hosts: ["10.0.0.1"] }, '"hosts"'],
			[{ not: { not: {} } }, '"not.not"'],
			[{ proto: ["ip"] }, "--proto"],
			[{ proto: "tcp" }, "proto"],
			[{ host: ["10.0.0.256"] }, "--host"],
			[{ srcHost: ["fe80::1%eth0"] }, "--src-host"],
			[{ host: ["10.0.0.0/8"] }, "--host"],
			[{ net: ["10.0.0.0/33"] }, "--net"],
			[{ net: ["10.0.0.0/8/1"] }, "--net"],
			[{ dstNet: ["2001:db8::/129"] }, "--dst-net"],
			[{ portMatch: [65536] }, "--port-match"],
			[{ portMatch: ["-1"] }, "--port-match"],
			[{ portMatch: [1.5] }, "--port-match"],
			[{ mac: ["02:00:00:00:00"] }, "--mac"],
			[{ mac: ["02:00-00:00:00:0a"] }, "--mac"],
			[{ etherType: ["2048"] }, "--ether-type"],
			[{ etherType: ["0x05dc"] }, "--ether-type"],
			[{ sender: [""] }, "--sender"],
			[{ sender: [7] }, "--sender"],
			// Whatever a JavaScript caller passes, the error is still coded.
			[{ sender: [1n] }, "--sender (a bigint)"],
			[{ host: [Symbol("x")] }, "--host (a symbol)"],
			[{ mac: [CYCLIC] }, "--mac (an object)"],
			[{ proto: [null] }, "--proto (null)"],
			[{ not: { host: ["x"] } }, "--not-host"],
			["tcp", "object"],
		];
		for (const [spec, names] of cases) {
			let caught: unknown;
			try {
				createFilter(spec as FilterSpec);
			} catch (error) {
				caught = error;
			}
			expect({ spec, caught }).toMatchObject({
				spec,
				caught: {
					code: "filter/invalid-value",
					message: expect.stringContaining(names),
					fix: expect.any(String),
				},
			});
		}
	});

	test("matching never throws, whatever the bytes", () => {
		// One predicate per term and polarity, so a throw in any matcher shows.
		const values: Record<string, (string | number)[]> = {
			proto: ["tcp"],
			host: ["10.0.2.15"],
			srcHost: ["fe80::1"],
			dstHost: ["192.0.2.7"],
			net: ["10.0.0.0/8"],
			srcNet: ["2001:db8::/32"],
			dstNet: ["0.0.0.0/0"],
			portMatch: [22],
			srcPortMatch: [50000],
			dstPortMatch: [547],
			mac: [MAC_A],
			srcMac: [MAC_B],
			dstMac: [MAC_B],
			etherType: ["0x0800"],
			sender: ["10.0.2.2:5000"],
		};
		const filters = FILTER_KEYS.flatMap((key) => [
			createFilter({ [key]: values[key] }),
			createFilter({ not: { [key]: values[key] } }),
		]);
		// Every prefix of frames whose headers decode in part (IPv4 and IPv6,
		// TCP and UDP, ARP, VLAN), then the same with each byte flipped.
		const frames = [SSH, DNS, ARP, V6_UDP, VLAN_GRE, LATER_FRAGMENT].map(
			(c) => c.tzsp.payload as Uint8Array,
		);
		let calls = 0;
		for (const frame of frames) {
			for (let n = 0; n <= frame.length; n++) {
				const cut = frame.slice(0, n);
				for (const variant of [
					cut,
					cut.map((b, i) => (i === n - 1 ? b ^ 0xff : b)),
				]) {
					const hex = Array.from(variant, h8).join("");
					const c = capture(hex, { address: "10.0.2.2", port: 5000 });
					for (const f of filters) {
						expect(() => f(c)).not.toThrow();
						calls += 1;
					}
				}
			}
		}
		expect(calls).toBeGreaterThan(5000);
	});
});
