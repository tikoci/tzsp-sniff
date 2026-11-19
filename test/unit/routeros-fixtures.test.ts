import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseTzsp, toHex } from "../../src/tzsp.ts";

/**
 * What RouterOS sends, pinned from CHR captures (issue #5). Fixtures are in
 * test/fixtures/routeros/ with their provenance in index.json; each entry
 * names the lab run (test/lab/tzsp-senders/evidence/) it came from, and
 * these tests check the fixture against that run. REPORT.md in the lab says
 * what each one shows.
 *
 * parseTzsp's result is changing (#4), so these assert only the fields that
 * stay (version, type, encapsulation, tags, payload) or the raw bytes, read
 * here independently of the lab's own code.
 */
const ROOT = join(import.meta.dir, "..", "..");
const DIR = join(ROOT, "test", "fixtures", "routeros");

/** Every fixture, by name. A family that goes missing fails here, not silently. */
const X86 = [
	"mangle-input.hex",
	"mangle-mirrors-sniffer.hex",
	"mangle-output.hex",
	"mangle-postrouting.hex",
	"mangle-prerouting.hex",
	"mangle-self-output.hex",
	"mangle-self-postrouting.hex",
	"mangle-sniff-id.hex",
	"mangle-sniff-pc.hex",
	"sniffer-file.pcapng",
	"sniffer-filter-stream-no.hex",
	"sniffer-filter-stream-yes.hex",
	"sniffer-only-headers.hex",
	"sniffer-or-two-protocols.hex",
	"sniffer-stream.hex",
];
const EXPECTED = [
	...X86.map((f) => `7.24.6-x86-${f}`),
	"7.25.1-arm64-sniffer-stream.hex",
	...X86.map((f) => `7.25.1-x86-${f}`),
].sort();

interface Entry {
	file: string;
	experiment: string;
	routeros: string;
	architecture: string;
	channel: string;
	accelerator: string;
	date: string;
	listenerPort: number;
	evidence: string;
}

interface Run {
	date: string;
	accelerator: string;
	listenerPort: number;
	router: { version: string; architecture: string };
	snifferDefaults: Record<string, string>;
	pcapng?: { sha256: string };
	experiments: {
		name: string;
		datagrams: { hex: string }[];
		summary: {
			datagrams: number;
			tzspHeaderNoTags: number;
			maxNesting: number;
			maxLength: number;
		};
		state?: {
			counters?: number[];
			restRecord?: Record<string, string>[];
			snifferRunningAfterStart?: string;
		};
	}[];
}

const index = JSON.parse(
	readFileSync(join(DIR, "index.json"), "utf8"),
) as Entry[];
const runs = new Map<string, Run>();
const runOf = (e: Entry): Run => {
	let r = runs.get(e.evidence);
	if (!r) {
		r = JSON.parse(readFileSync(join(ROOT, e.evidence), "utf8")) as Run;
		runs.set(e.evidence, r);
	}
	return r;
};
const experimentOf = (e: Entry) => {
	const x = runOf(e).experiments.find((x) => x.name === e.experiment);
	if (!x) throw new Error(`${e.file}: no ${e.experiment} in ${e.evidence}`);
	return x;
};

const lines = (e: Entry) =>
	readFileSync(join(DIR, e.file), "utf8")
		.split("\n")
		.filter((l) => l.length > 0);
const datagrams = (e: Entry): Uint8Array[] =>
	lines(e).map((hex) => Uint8Array.from(Buffer.from(hex, "hex")));

const label = (e: Entry) => `${e.routeros} ${e.architecture} ${e.experiment}`;
const of = (...experiments: string[]) =>
	index.filter((e) => experiments.includes(e.experiment));

const ZERO_MAC = "000000000000";
const GUEST = "10.0.2.15";
const PEER = "10.0.2.3";
const ip4 = (b: Uint8Array) => Array.from(b).join(".");

/** The IPv4 packet at `at`, by the raw layout. */
function ipv4(b: Uint8Array, at: number) {
	const ip = b.subarray(at);
	const view = new DataView(ip.buffer, ip.byteOffset, ip.byteLength);
	const ihl = ((ip[0] ?? 0) & 0x0f) * 4;
	return {
		version: (ip[0] ?? 0) >> 4,
		totalLength: view.getUint16(2),
		protocol: ip[9],
		src: ip4(ip.subarray(12, 16)),
		dst: ip4(ip.subarray(16, 20)),
		icmpType: ip[9] === 1 ? ip[ihl] : undefined,
		udpDstPort: ip[9] === 17 ? view.getUint16(ihl + 2) : undefined,
		udpPayload: ip.subarray(ihl + 8),
	};
}

/** The Ethernet frame inside a TZSP datagram that has no tags. */
function frame(d: Uint8Array) {
	const eth = d.subarray(5);
	return {
		eth,
		dst: toHex(eth.subarray(0, 6)),
		src: toHex(eth.subarray(6, 12)),
		etherType: ((eth[12] ?? 0) << 8) | (eth[13] ?? 0),
		ip: ipv4(eth, 14),
	};
}

/** TZSP layers, each inside UDP to the listener's own port: 0 for an ordinary frame. */
function depth(d: Uint8Array, port: number): number {
	let n = 0;
	let cur = d;
	while (
		cur.length >= 5 + 14 + 28 &&
		toHex(cur.subarray(0, 5)) === "0100000101" &&
		frame(cur).etherType === 0x0800 &&
		frame(cur).ip.udpDstPort === port
	) {
		cur = frame(cur).ip.udpPayload;
		n += 1;
	}
	return n;
}

/** A ping between the guest and SLIRP's DNS address: requests out, replies in. */
function expectPing(d: Uint8Array, type: 8 | 0) {
	const ip = frame(d).ip;
	expect(frame(d).etherType).toBe(0x0800);
	expect(ip.protocol).toBe(1);
	expect(ip.icmpType).toBe(type);
	expect([ip.src, ip.dst]).toEqual(type === 8 ? [GUEST, PEER] : [PEER, GUEST]);
}

const types = (e: Entry) => datagrams(e).map((d) => frame(d).ip.icmpType);

describe("fixture set and provenance", () => {
	test("is exactly the expected set", () => {
		expect(index.map((e) => e.file).sort()).toEqual(EXPECTED);
		expect(readdirSync(DIR).sort()).toEqual([...EXPECTED, "index.json"].sort());
	});

	for (const e of index) {
		test(`${e.file} matches its run`, () => {
			const run = runOf(e);
			expect(run.router.version).toBe(e.routeros);
			expect(run.router.architecture).toBe(e.architecture);
			expect(run.accelerator).toBe(e.accelerator);
			expect(run.listenerPort).toBe(e.listenerPort);
			expect(run.date.slice(0, 10)).toBe(e.date);
			expect(e.accelerator.split(",")[0]).toBe(
				e.architecture === "arm64" ? "tcg" : "kvm",
			);
			if (e.file.endsWith(".pcapng")) {
				const sha = createHash("sha256")
					.update(readFileSync(join(DIR, e.file)))
					.digest("hex");
				expect(sha).toBe(run.pcapng?.sha256 ?? "");
			} else {
				expect(lines(e)).toEqual(experimentOf(e).datagrams.map((d) => d.hex));
			}
		});
	}
});

const TZSP = X86.filter(
	(f) => f.endsWith(".hex") && f !== "mangle-sniff-pc.hex",
).map((f) => f.replace(".hex", ""));

describe("both senders: version 1, received, Ethernet, the end tag alone", () => {
	for (const e of of(...TZSP)) {
		test(label(e), () => {
			const all = datagrams(e);
			expect(all.length).toBeGreaterThan(0);
			for (const d of all) {
				expect(toHex(d.subarray(0, 5))).toBe("0100000101");
				const t = parseTzsp(d);
				expect(t.version).toBe(1);
				expect(t.type).toBe(0);
				expect(t.encapsulation).toBe(1);
				expect(t.tags).toEqual([]);
				expect(toHex(t.payload)).toBe(toHex(d.subarray(5)));
			}
			// Every datagram of the run, not only the kept ones.
			const s = experimentOf(e).summary;
			expect(s.tzspHeaderNoTags).toBe(s.datagrams);
		});
	}
});

describe("/tool/sniffer streaming", () => {
	test("defaults on a fresh CHR: filter-stream no, entries OR-ed", () => {
		for (const run of new Set(index.map(runOf))) {
			expect(run.snifferDefaults["filter-stream"]).toBe("false");
			expect(run.snifferDefaults["filter-operator-between-entries"]).toBe("or");
		}
	});

	for (const e of of("sniffer-stream")) {
		test(`${label(e)}: whole frames with real MACs, both directions`, () => {
			expect(types(e)).toEqual([8, 0, 8, 0, 8, 0]);
			for (const [i, d] of datagrams(e).entries()) {
				expectPing(d, i % 2 === 0 ? 8 : 0);
				expect(frame(d).dst).not.toBe(ZERO_MAC);
				expect(frame(d).src).not.toBe(ZERO_MAC);
				expect(frame(d).eth.length).toBe(14 + frame(d).ip.totalLength);
			}
		});
	}

	for (const e of of("sniffer-only-headers")) {
		test(`${label(e)}: a 1000-byte ping arrives as its first 60 bytes, no tag`, () => {
			expect(types(e)).toEqual([8, 0, 8, 0]);
			for (const d of datagrams(e)) {
				expect(frame(d).ip.totalLength).toBe(1000);
				expect(frame(d).eth.length).toBe(60);
				expect(d.length).toBe(65);
			}
		});
	}

	for (const e of of("sniffer-or-two-protocols")) {
		test(`${label(e)}: OR with icmp,udp streams; AND streamed nothing`, () => {
			expect(types(e)).toEqual([8, 0, 8, 0]);
			const and = runOf(e).experiments.find(
				(x) => x.name === "sniffer-and-two-protocols",
			);
			expect(and?.state?.snifferRunningAfterStart).toBe("true");
			expect(and?.summary.datagrams).toBe(0);
		});
	}

	for (const e of of("sniffer-filter-stream-yes")) {
		test(`${label(e)}: filter-stream=yes sends the ping only`, () => {
			expect(types(e)).toEqual([8, 0]);
			for (const d of datagrams(e)) expect(depth(d, e.listenerPort)).toBe(0);
			expect(experimentOf(e).summary.datagrams).toBe(2);
		});
	}

	for (const e of of("sniffer-filter-stream-no")) {
		test(`${label(e)}: filter-stream=no captures its own stream, one layer per pass, to a fragment`, () => {
			const all = datagrams(e);
			const depths = all.map((d) => depth(d, e.listenerPort));
			const kept = all.slice(0, -1);
			const deepest = all.at(-1) as Uint8Array;
			const s = experimentOf(e).summary;
			// The ping, then a copy of it, a copy of that, ... (the first 8 kept;
			// the reply and its copies may interleave), then the run's deepest.
			// Unwrapping a copy once gives an earlier datagram, byte for byte.
			expectPing(all[0] as Uint8Array, 8);
			for (const [i, d] of kept.entries()) {
				if ((depths[i] ?? 0) === 0) continue;
				const earlier = kept.slice(0, i).map((x) => toHex(x));
				expect(earlier).toContain(toHex(frame(d).ip.udpPayload));
			}
			expect(Math.max(...depths.slice(0, 8))).toBeGreaterThanOrEqual(5);
			// A whole copy adds 47 bytes: TZSP 5, Ethernet 14, IPv4 20, UDP 8.
			for (const [i, d] of kept.entries())
				expect(d.length).toBe(75 + 47 * (depths[i] ?? 0));
			// 30 whole layers make 1485 bytes; a 31st would need 1532, more
			// than one Ethernet frame, so it goes out as IPv4 fragments. The
			// deepest datagram is the sniffer's capture of a first fragment
			// (more-fragments set), and the ping inside it is cut short.
			expect(experimentOf(e).summary.datagrams).toBeGreaterThan(500);
			expect(depths.at(-1)).toBe(s.maxNesting);
			expect(s.maxNesting).toBe(31);
			expect(deepest.length).toBe(1519);
			expect(s.maxLength).toBe(1519);
			expect((deepest[5 + 14 + 6] ?? 0) & 0x20).toBe(0x20);
			let inner = deepest;
			for (let k = 0; k < s.maxNesting; k++) inner = frame(inner).ip.udpPayload;
			expectPing(inner, 8);
			expect(inner.length).toBeLessThan(75);
		});
	}
});

describe("mangle action=sniff-tzsp", () => {
	for (const e of of("mangle-prerouting", "mangle-input")) {
		test(`${label(e)}: echo replies with their MACs`, () => {
			expect(types(e)).toEqual([0, 0]);
			for (const d of datagrams(e)) {
				expectPing(d, 0);
				expect(frame(d).src).not.toBe(ZERO_MAC);
				expect(frame(d).dst).not.toBe(ZERO_MAC);
			}
		});
	}

	for (const e of of(
		"mangle-output",
		"mangle-postrouting",
		"mangle-sniff-id",
	)) {
		test(`${label(e)}: the router's echo requests behind all-zero MACs`, () => {
			expect(types(e)).toEqual([8, 8]);
			for (const d of datagrams(e)) {
				expectPing(d, 8);
				expect(frame(d).dst).toBe(ZERO_MAC);
				expect(frame(d).src).toBe(ZERO_MAC);
				expect(frame(d).eth.length).toBe(14 + frame(d).ip.totalLength);
			}
		});
	}

	for (const e of of("mangle-sniff-id")) {
		test(`${label(e)}: sniff-id is not kept on a sniff-tzsp rule`, () => {
			const rule = experimentOf(e).state?.restRecord?.[0];
			expect(rule?.action).toBe("sniff-tzsp");
			expect(rule && "sniff-id" in rule).toBe(false);
		});
	}

	for (const e of of("mangle-sniff-pc")) {
		test(`${label(e)}: sniff-pc keeps sniff-id and is not TZSP`, () => {
			expect(experimentOf(e).state?.restRecord?.[0]?.["sniff-id"]).toBe("4660");
			const all = datagrams(e);
			expect(all.length).toBe(2);
			for (const d of all) {
				// sniff-id=4660 big-endian, 8 bytes, the IPv4 packet at byte 12, 14 bytes after it.
				expect(toHex(d.subarray(0, 4))).toBe("00001234");
				const ip = ipv4(d, 12);
				expect(ip.version).toBe(4);
				expect([ip.protocol, ip.icmpType, ip.src, ip.dst]).toEqual([
					1,
					8,
					GUEST,
					PEER,
				]);
				expect(ip.totalLength).toBe(56);
				expect(d.length).toBe(12 + 56 + 14);
				expect(parseTzsp(d).version).toBe(0);
			}
		});
	}

	for (const [experiment, counters] of [
		["mangle-self-output", [2, 0]],
		["mangle-self-postrouting", [2, 2]],
		["mangle-mirrors-sniffer", [4]],
	] as const) {
		for (const e of of(experiment)) {
			test(`${label(e)}: rule counters ${counters.join(",")}, and no copy of TZSP arrives`, () => {
				expect(experimentOf(e).state?.counters).toEqual([...counters]);
				expect(types(e)).toEqual(
					experiment === "mangle-mirrors-sniffer" ? [8, 0, 8, 0] : [8, 8],
				);
				for (const d of datagrams(e)) expect(depth(d, e.listenerPort)).toBe(0);
				expect(experimentOf(e).summary.datagrams).toBe(datagrams(e).length);
			});
		}
	}
});

describe("a file saved by /tool/sniffer", () => {
	for (const e of of("sniffer-file")) {
		test(`${label(e)}: pcapng, Ethernet, one interface per direction, ns timestamps`, () => {
			const b = readFileSync(join(DIR, e.file));
			// Section header block, little-endian byte-order magic, no options.
			expect(b.readUInt32LE(0)).toBe(0x0a0d0d0a);
			expect(b.readUInt32LE(8)).toBe(0x1a2b3c4d);
			const opts = (from: number, to: number) => {
				const out: [number, Buffer][] = [];
				for (let p = from; p + 4 <= to; ) {
					const code = b.readUInt16LE(p);
					const len = b.readUInt16LE(p + 2);
					if (code === 0) break;
					out.push([code, b.subarray(p + 4, p + 4 + len)]);
					p += 4 + Math.ceil(len / 4) * 4;
				}
				return out;
			};
			const blocks: number[] = [];
			const interfaces: unknown[] = [];
			const packets: {
				iface: number;
				ts: bigint;
				cap: number;
				orig: number;
				data: Buffer;
				options: [number, string][];
			}[] = [];
			for (let o = 0; o + 12 <= b.length; ) {
				const type = b.readUInt32LE(o);
				const len = b.readUInt32LE(o + 4);
				blocks.push(type);
				if (type === 0x0a0d0d0a) expect(opts(o + 24, o + len - 4)).toEqual([]);
				if (type === 1)
					interfaces.push({
						linkType: b.readUInt16LE(o + 8),
						snapLen: b.readUInt32LE(o + 12),
						options: opts(o + 16, o + len - 4).map(([c, v]) => [
							c,
							c === 9 ? v[0] : v.toString("utf8"),
						]),
					});
				if (type === 6) {
					const cap = b.readUInt32LE(o + 20);
					packets.push({
						iface: b.readUInt32LE(o + 8),
						ts:
							(BigInt(b.readUInt32LE(o + 12)) << 32n) |
							BigInt(b.readUInt32LE(o + 16)),
						cap,
						orig: b.readUInt32LE(o + 24),
						data: b.subarray(o + 28, o + 28 + cap),
						options: opts(o + 28 + Math.ceil(cap / 4) * 4, o + len - 4).map(
							([c, v]) => [c, v.toString("utf8")],
						),
					});
				}
				o += len;
			}
			expect(blocks).toEqual([0x0a0d0d0a, 1, 1, 6, 6, 6, 6, 6, 6]);
			// if_name (2) and if_tsresol (9) = 9: nanoseconds.
			expect(interfaces).toEqual([
				{
					linkType: 1,
					snapLen: 65536,
					options: [
						[2, "ether1 rx"],
						[9, 9],
					],
				},
				{
					linkType: 1,
					snapLen: 65536,
					options: [
						[2, "ether1 tx"],
						[9, 9],
					],
				},
			]);
			// Three pings: each request on tx (1), then its reply on rx (0).
			expect(packets.map((p) => p.iface)).toEqual([1, 0, 1, 0, 1, 0]);
			for (const [i, p] of packets.entries()) {
				expect(p.cap).toBe(70);
				expect(p.orig).toBe(70);
				expect(p.options).toEqual([[1, "cpu:0 fp:0"]]);
				const asTzsp = Buffer.concat([
					Buffer.from("0100000101", "hex"),
					p.data,
				]);
				expectPing(asTzsp, p.iface === 1 ? 8 : 0);
				if (i > 0) expect(p.ts > (packets[i - 1]?.ts ?? 0n)).toBe(true);
			}
			// The timestamps fall on the run's date (UTC).
			const first = new Date(Number((packets[0]?.ts ?? 0n) / 1_000_000n));
			expect(first.toISOString().slice(0, 10)).toBe(e.date);
		});
	}
});
