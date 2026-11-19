import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseTzsp, toHex } from "../../src/tzsp.ts";

/**
 * What RouterOS sends, pinned from CHR captures (issue #5). The fixtures,
 * their RouterOS version, architecture and the router commands are in
 * test/fixtures/routeros/index.json; README.md there and
 * test/lab/tzsp-senders/REPORT.md say what each one shows.
 *
 * parseTzsp's result is changing (#4), so these assert only the fields that
 * stay (version, type, encapsulation, tags, payload) or the raw bytes.
 */
const DIR = join(import.meta.dir, "..", "fixtures", "routeros");

interface Entry {
	file: string;
	experiment: string;
	routeros: string;
	architecture: string;
	listenerPort: number;
}

const index = JSON.parse(
	readFileSync(join(DIR, "index.json"), "utf8"),
) as Entry[];

const datagrams = (e: Entry): Uint8Array[] =>
	readFileSync(join(DIR, e.file), "utf8")
		.split("\n")
		.filter((l) => l.length > 0)
		.map((hex) => Uint8Array.from(Buffer.from(hex, "hex")));

const label = (e: Entry) => `${e.routeros} ${e.architecture} ${e.experiment}`;
const of = (...experiments: string[]) =>
	index.filter((e) => experiments.includes(e.experiment));

const ZERO_MAC = "000000000000";

/** The frame RouterOS put inside a TZSP datagram, by the raw layout. */
function frame(d: Uint8Array) {
	const eth = d.subarray(5);
	const view = new DataView(eth.buffer, eth.byteOffset, eth.byteLength);
	const ip = eth.subarray(14);
	const ihl = ((ip[0] ?? 0) & 0x0f) * 4;
	return {
		eth,
		dst: toHex(eth.subarray(0, 6)),
		src: toHex(eth.subarray(6, 12)),
		etherType: view.getUint16(12),
		ipTotalLength: view.getUint16(16),
		ipProtocol: ip[9],
		udpDstPort: ip[9] === 17 ? view.getUint16(14 + ihl + 2) : Number.NaN,
		udpPayload: ip.subarray(ihl + 8),
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
		frame(cur).udpDstPort === port
	) {
		cur = frame(cur).udpPayload;
		n += 1;
	}
	return n;
}

const TZSP_EXPERIMENTS = [
	"sniffer-stream",
	"sniffer-only-headers",
	"sniffer-filter-stream-yes",
	"sniffer-filter-stream-no",
	"mangle-prerouting",
	"mangle-input",
	"mangle-output",
	"mangle-postrouting",
	"mangle-sniff-id",
	"mangle-self-output",
	"mangle-self-postrouting",
	"mangle-mirrors-sniffer",
];

describe("RouterOS fixtures", () => {
	test("cover both senders on stable and long-term x86, and arm64", () => {
		const has = (experiment: string, arch: string) =>
			index.filter(
				(e) => e.experiment === experiment && e.architecture === arch,
			).length;
		expect(has("sniffer-stream", "x86_64")).toBe(2);
		expect(has("mangle-prerouting", "x86_64")).toBe(2);
		expect(has("sniffer-stream", "arm64")).toBe(1);
		expect(new Set(index.map((e) => e.routeros)).size).toBe(2);
	});
});

describe("both senders: version 1, received, Ethernet, the end tag alone", () => {
	for (const e of of(...TZSP_EXPERIMENTS)) {
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
				expect(frame(d).etherType).toBe(0x0800);
			}
		});
	}
});

describe("/tool/sniffer streaming", () => {
	for (const e of of("sniffer-stream")) {
		test(`${label(e)}: whole frames with real MACs`, () => {
			for (const d of datagrams(e)) {
				const f = frame(d);
				expect(f.dst).not.toBe(ZERO_MAC);
				expect(f.src).not.toBe(ZERO_MAC);
				expect(f.eth.length).toBe(14 + f.ipTotalLength);
			}
		});
	}

	for (const e of of("sniffer-only-headers")) {
		test(`${label(e)}: only-headers cuts the frame, and no tag says so`, () => {
			for (const d of datagrams(e)) {
				const f = frame(d);
				// A 1000-byte ping arrives as its first 60 bytes.
				expect(f.ipTotalLength).toBe(1000);
				expect(f.eth.length).toBe(60);
				expect(parseTzsp(d).tags).toEqual([]);
			}
		});
	}

	for (const e of of("sniffer-filter-stream-yes")) {
		test(`${label(e)}: filter-stream=yes keeps its own stream out`, () => {
			for (const d of datagrams(e)) expect(depth(d, e.listenerPort)).toBe(0);
		});
	}

	for (const e of of("sniffer-filter-stream-no")) {
		test(`${label(e)}: filter-stream=no captures its own stream, nesting`, () => {
			const all = datagrams(e);
			const depths = all.map((d) => depth(d, e.listenerPort));
			expect(Math.max(...depths)).toBeGreaterThanOrEqual(2);
			// Each layer adds TZSP (5), Ethernet (14), IPv4 (20) and UDP (8).
			for (const [i, d] of all.entries()) {
				const n = depths[i] ?? 0;
				if (n === 0) continue;
				let inner = d;
				for (let k = 0; k < n; k++) inner = frame(inner).udpPayload;
				expect(d.length - inner.length).toBe(47 * n);
			}
		});
	}
});

describe("mangle action=sniff-tzsp", () => {
	for (const e of of("mangle-prerouting", "mangle-input")) {
		test(`${label(e)}: inbound frames keep their MACs`, () => {
			for (const d of datagrams(e)) {
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
		test(`${label(e)}: locally sent packets get zero MACs`, () => {
			for (const d of datagrams(e)) {
				expect(frame(d).dst).toBe(ZERO_MAC);
				expect(frame(d).src).toBe(ZERO_MAC);
				expect(frame(d).eth.length).toBe(14 + frame(d).ipTotalLength);
			}
		});
	}

	for (const e of of(
		"mangle-self-output",
		"mangle-self-postrouting",
		"mangle-mirrors-sniffer",
	)) {
		test(`${label(e)}: a rule matching TZSP to the listener mirrors nothing back`, () => {
			for (const d of datagrams(e)) expect(depth(d, e.listenerPort)).toBe(0);
		});
	}

	for (const e of of("mangle-sniff-pc")) {
		test(`${label(e)}: sniff-pc is not TZSP; it starts with sniff-id`, () => {
			for (const d of datagrams(e)) {
				// sniff-id=4660, big-endian.
				expect(toHex(d.subarray(0, 4))).toBe("00001234");
				expect(parseTzsp(d).version).toBe(0);
			}
		});
	}
});

describe("a file saved by /tool/sniffer", () => {
	for (const e of index.filter((x) => x.file.endsWith(".pcapng"))) {
		test(`${label(e)}: pcapng, Ethernet, one interface per direction`, () => {
			const b = readFileSync(join(DIR, e.file));
			// Section header block, little-endian byte-order magic.
			expect(b.readUInt32LE(0)).toBe(0x0a0d0d0a);
			expect(b.readUInt32LE(8)).toBe(0x1a2b3c4d);
			const interfaces: { linkType: number; name: string }[] = [];
			const packets: { iface: number; data: Buffer }[] = [];
			for (let o = 0; o + 12 <= b.length; ) {
				const type = b.readUInt32LE(o);
				const len = b.readUInt32LE(o + 4);
				expect(len).toBeGreaterThanOrEqual(12);
				if (type === 1) {
					// if_name is option 2.
					let name = "";
					for (let p = o + 16; p + 4 <= o + len - 4; ) {
						const code = b.readUInt16LE(p);
						const olen = b.readUInt16LE(p + 2);
						if (code === 0) break;
						if (code === 2) name = b.toString("utf8", p + 4, p + 4 + olen);
						p += 4 + Math.ceil(olen / 4) * 4;
					}
					interfaces.push({ linkType: b.readUInt16LE(o + 8), name });
				}
				if (type === 6) {
					const cap = b.readUInt32LE(o + 20);
					packets.push({
						iface: b.readUInt32LE(o + 8),
						data: b.subarray(o + 28, o + 28 + cap),
					});
				}
				o += len;
			}
			expect(interfaces).toEqual([
				{ linkType: 1, name: "ether1 rx" },
				{ linkType: 1, name: "ether1 tx" },
			]);
			// Three pings: a request (tx) and a reply (rx) each.
			expect(packets.length).toBe(6);
			for (const p of packets) {
				expect(p.data.readUInt16BE(12)).toBe(0x0800);
				expect(p.data[14 + 9]).toBe(1); // ICMP
			}
			expect(packets.filter((p) => p.iface === 1).length).toBe(3);
		});
	}
});
