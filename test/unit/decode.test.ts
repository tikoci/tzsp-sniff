// cspell:ignore tsresol -- pcapng option name
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { openCapture } from "../../src/capture.ts";
import { type DecodeOptions, openDecode } from "../../src/decode.ts";
import { TzspSniffError } from "../../src/errors.ts";
import { MAX_BLOCK_BYTES, MAX_HEX_LINE } from "../../src/input.ts";
import { type ByteSink, pcapngWriter } from "../../src/pcapng.ts";
import type {
	DatagramRecord,
	PacketRecord,
	StreamRecord,
	SummaryRecord,
	WarningRecord,
} from "../../src/records.ts";
import {
	bytes,
	echo,
	eth,
	fixture,
	h16,
	h32,
	ipv4,
	ipv6,
	send,
	udp,
} from "./helpers.ts";

const FIXTURES = join(import.meta.dir, "..", "fixtures", "routeros");
/** /tool/sniffer's saved file, 7.25.1 x86_64 (#5): Ethernet, two interfaces, ns times. */
const ROUTEROS_FILE = readFileSync(
	join(FIXTURES, "7.25.1-x86-sniffer-file.pcapng"),
);
const STREAM = fixture("7.25.1-x86-sniffer-stream");
const REQUEST = STREAM[0] as string;
const KEEPALIVE = "01040000";
const NOT_TZSP = "02000001";

// --- builders --------------------------------------------------------------

const pad4 = (hex: string) =>
	hex + "00".repeat((4 - ((hex.length / 2) % 4)) % 4);
const le16 = (n: number) => h16(n).match(/../g)?.reverse().join("") as string;
const le32 = (n: number) => h32(n).match(/../g)?.reverse().join("") as string;

/** pcapng, hex, in either byte order. */
function pcapngBuilder(little = true) {
	const u16 = little ? le16 : h16;
	const u32 = little ? le32 : h32;
	const option = (code: number, valueHex: string) =>
		u16(code) + u16(valueHex.length / 2) + pad4(valueHex);
	const options = (list: string[]) =>
		list.length ? list.join("") + u16(0) + u16(0) : "";
	const block = (type: number, body: string) => {
		const length = 12 + body.length / 2;
		return u32(type) + u32(length) + body + u32(length);
	};
	const text = (s: string) => Buffer.from(s).toString("hex");
	return {
		section: () =>
			block(0x0a0d0d0a, u32(0x1a2b3c4d) + u16(1) + u16(0) + "ffffffffffffffff"),
		iface: (linkType: number, o: { name?: string; tsresol?: number } = {}) =>
			block(
				1,
				u16(linkType) +
					u16(0) +
					u32(0) +
					options([
						...(o.name ? [option(2, text(o.name))] : []),
						...(o.tsresol !== undefined
							? [option(9, h16(o.tsresol).slice(2))]
							: []),
					]),
			),
		packet: (
			id: number,
			dataHex: string,
			o: { units?: bigint; comments?: string[]; captured?: number } = {},
		) => {
			const units = o.units ?? 0n;
			return block(
				6,
				u32(id) +
					u32(Number(units >> 32n)) +
					u32(Number(units & 0xffffffffn)) +
					u32(o.captured ?? dataHex.length / 2) +
					u32(dataHex.length / 2) +
					pad4(dataHex) +
					options((o.comments ?? []).map((c) => option(1, text(c)))),
			);
		},
		simple: (dataHex: string) =>
			block(3, u32(dataHex.length / 2) + pad4(dataHex)),
		other: (type: number, bodyHex: string) => block(type, bodyHex),
	};
}

/** pcap, hex. */
function pcapBuilder(o: {
	little?: boolean;
	nano?: boolean;
	linkType: number;
}) {
	const little = o.little ?? true;
	const u16 = little ? le16 : h16;
	const u32 = little ? le32 : h32;
	return {
		header: () =>
			u32(o.nano ? 0xa1b23c4d : 0xa1b2c3d4) +
			u16(2) +
			u16(4) +
			u32(0) +
			u32(0) +
			u32(65535) +
			u32(o.linkType),
		record: (dataHex: string, seconds = 0, fraction = 0) =>
			u32(seconds) +
			u32(fraction) +
			u32(dataHex.length / 2) +
			u32(dataHex.length / 2) +
			dataHex,
	};
}

/** Frames of a host capture of the TZSP stream: Ethernet, IPv4, UDP to `port`. */
const udpToTzsp = (datagram: string, port = 37008, srcPort = 40000) =>
	ipv4({
		proto: 17,
		src: "10.0.2.15",
		dst: "10.0.2.2",
		payload: udp(srcPort, port, datagram),
	});

async function decode(
	input: Uint8Array | string | Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
	options: DecodeOptions = {},
): Promise<StreamRecord[]> {
	const stream = await openDecode(
		typeof input === "string" ? bytes(input) : input,
		options,
	);
	const records: StreamRecord[] = [];
	for await (const r of stream) records.push(r);
	return records;
}

const summaryOf = (records: StreamRecord[]) => records.at(-1) as SummaryRecord;
const packetsOf = (records: StreamRecord[]) =>
	records.filter((r): r is PacketRecord => r.type === "packet");
const entriesOf = (records: StreamRecord[]) =>
	records.filter(
		(r): r is PacketRecord | DatagramRecord =>
			r.type === "packet" || r.type === "record",
	);
const warningsOf = (records: StreamRecord[]) =>
	records.filter((r): r is WarningRecord => r.type === "warning");

async function rejection(promise: Promise<unknown>): Promise<string> {
	try {
		await promise;
	} catch (error) {
		if (error instanceof TzspSniffError) return error.code;
		throw error;
	}
	throw new Error("did not reject");
}

/** Bytes in one-byte chunks, as a slow pipe might give them. */
function* trickle(data: Uint8Array) {
	for (const b of data) yield Uint8Array.of(b);
}

// --- tests -----------------------------------------------------------------

describe("format detection", () => {
	test("pcapng and pcap in either byte order and resolution; hex only when asked", async () => {
		const n = pcapngBuilder();
		const pcapng = n.section() + n.iface(128) + n.packet(0, REQUEST);
		const big = pcapngBuilder(false);
		const pcapngBig = big.section() + big.iface(128) + big.packet(0, REQUEST);
		const cases: [string, string][] = [
			[pcapng, "pcapng"],
			[pcapngBig, "pcapng"],
		];
		for (const little of [true, false]) {
			for (const nano of [true, false]) {
				const p = pcapBuilder({ little, nano, linkType: 128 });
				cases.push([p.header() + p.record(REQUEST), "pcap"]);
			}
		}
		for (const [input, format] of cases) {
			const records = await decode(input);
			const header = records[0];
			expect(header).toMatchObject({
				type: "header",
				command: "decode",
				input: { name: "input", format },
				tzspPorts: [37008],
			});
			expect(packetsOf(records)).toHaveLength(1);
			expect(summaryOf(records)).toMatchObject({
				status: "complete",
				stoppedBy: "end",
			});
		}
	});

	test("anything else is refused before any record, with a fix that names hex for hex text", async () => {
		const hexText = new TextEncoder().encode(`${REQUEST}\n`);
		const reject = (input: Uint8Array) => openDecode(input);
		expect(await rejection(reject(hexText))).toBe("decode/unknown-format");
		await reject(hexText).catch((e: TzspSniffError) => {
			expect(e.fix).toContain("--input hex");
		});
		expect(await rejection(reject(new Uint8Array(0)))).toBe(
			"decode/unknown-format",
		);
		expect(await rejection(reject(bytes("deadbeef00")))).toBe(
			"decode/unknown-format",
		);
		// Hex text is decoded only when asked for.
		expect(packetsOf(await decode(hexText, { format: "hex" }))).toHaveLength(1);
	});

	test("options are checked before the input is read", async () => {
		const bad: DecodeOptions[] = [
			{ count: 0 },
			{ expect: 1.5 },
			{ tzspPorts: [0] },
			{ tzspPorts: [] },
			{ format: "json" as "hex" },
			{ detail: "most" as "full" },
		];
		for (const options of bad) {
			let pulled = false;
			const input = (function* () {
				pulled = true;
				yield bytes(REQUEST);
			})();
			expect({
				options,
				code: await rejection(openDecode(input, options)),
			}).toEqual({ options, code: "decode/invalid-option" });
			expect(pulled).toBe(false);
		}
		expect(
			await rejection(openDecode(bytes("00"), { filter: { proto: ["nope"] } })),
		).toBe("filter/invalid-value");
	});
});

describe("a file RouterOS saved", () => {
	test("Ethernet frames, with the interface, the comment and the router's time; no listener or peer", async () => {
		const records = await decode(ROUTEROS_FILE, { detail: "layers" });
		const packets = packetsOf(records);
		expect(packets).toHaveLength(6);
		for (const p of packets) {
			expect(p.listener).toBeUndefined();
			expect(p.peer).toBeUndefined();
			expect(["ether1 rx", "ether1 tx"]).toContain(p.interface as string);
			expect(p.comment).toBe("cpu:0 fp:0");
			expect(p.protocols).toEqual(["ethernet", "ipv4", "icmp"]);
			// No TZSP layer: the frame is the record's bytes.
			expect(p.layers?.[0]?.protocol).toBe("ethernet");
			expect(p.layers?.[0]?.offset).toBe(0);
		}
		// Requests go out on tx and replies come in on rx.
		expect(packets.map((p) => p.interface)).toEqual([
			"ether1 tx",
			"ether1 rx",
			"ether1 tx",
			"ether1 rx",
			"ether1 tx",
			"ether1 rx",
		]);
		// Nanosecond timestamps, read as ms: the lab ran on 2026-11-19, one
		// ping a second.
		const times = packets.map((p) => Date.parse(p.time as string));
		expect(packets[0]?.time?.slice(0, 10)).toBe("2026-11-19");
		expect((times[2] as number) - (times[0] as number)).toBeGreaterThan(900);
		expect((times[2] as number) - (times[0] as number)).toBeLessThan(1100);
		const summary = summaryOf(records);
		expect(summary.durationMs).toBe(
			(times.at(-1) as number) - (times[0] as number),
		);
		// No listener or peer: no sender.
		expect(summary.senders.top).toEqual([]);
		expect(summary.counters).toMatchObject({ datagrams: 6, packets: 6 });
	});

	test("at full detail the record's bytes are the frame", async () => {
		const [first] = packetsOf(await decode(ROUTEROS_FILE, { detail: "full" }));
		expect(first?.datagram?.length).toBe((first?.length as number) * 2);
		expect(first?.datagram?.slice(24, 28)).toBe("0800");
	});

	test("filters apply; --sender matches nothing in a file with no sender", async () => {
		const icmp = await decode(ROUTEROS_FILE, {
			filter: { srcHost: ["10.0.2.3"] },
		});
		expect(packetsOf(icmp)).toHaveLength(3);
		const sender = await decode(ROUTEROS_FILE, {
			filter: { sender: ["37008"] },
		});
		expect(packetsOf(sender)).toHaveLength(0);
		expect(warningsOf(sender).map((w) => w.code)).toEqual([
			"capture/all-filtered",
		]);
		const notSender = await decode(ROUTEROS_FILE, {
			filter: { not: { sender: ["37008"] } },
		});
		expect(packetsOf(notSender)).toHaveLength(6);
	});

	test("read in one-byte chunks, it decodes the same", async () => {
		const whole = await decode(ROUTEROS_FILE, { detail: "full" });
		const chunked = await decode(trickle(ROUTEROS_FILE), { detail: "full" });
		expect(entriesOf(chunked)).toEqual(entriesOf(whole));
	});
});

describe("round trip: --write, then decode", () => {
	test("a file openCapture wrote decodes to the records it reported", async () => {
		const chunks: Uint8Array[] = [];
		const sink: ByteSink = {
			async write(chunk) {
				chunks.push(chunk);
			},
		};
		const datagrams = [...STREAM, KEEPALIVE, NOT_TZSP, "01"];
		const stream = await openCapture({
			ports: [{ port: 0, label: "router-a" }],
			count: STREAM.length,
			durationMs: 5000,
			detail: "full",
			write: pcapngWriter(sink),
		});
		const captured: StreamRecord[] = [];
		for await (const r of stream) {
			captured.push(r);
			if (r.type === "header")
				await send(r.listeners[0]?.port as number, datagrams);
		}
		const written = Buffer.concat(chunks);
		const decoded = await decode(written, { detail: "full" });
		const listened = entriesOf(captured);
		// The capture stopped at its count, so the decode holds what it read.
		expect(listened.length).toBeGreaterThanOrEqual(STREAM.length);
		expect(entriesOf(decoded)).toEqual(listened);
		expect(listened[0]).toMatchObject({ listener: "router-a" });
		expect(listened[0]?.peer).toMatch(/^127\.0\.0\.1:\d+$/);
	});

	test("control, unsupported and invalid TZSP records come back as records", async () => {
		const n = pcapngBuilder();
		const input =
			n.section() +
			n.iface(128, { name: "37008", tsresol: 3 }) +
			n.packet(0, KEEPALIVE, {
				units: 1000n,
				comments: ["peer=10.0.2.15:5000"],
			}) +
			n.packet(0, NOT_TZSP, { comments: ["peer=[fe80::1]:5000", "a note"] }) +
			n.packet(0, "01");
		const records = entriesOf(await decode(input, { detail: "layers" }));
		expect(records.map((r) => [r.type, (r as DatagramRecord).kind])).toEqual([
			["record", "control"],
			["record", "invalid"],
			["record", "invalid"],
		]);
		expect(records[0]).toMatchObject({
			listener: "37008",
			peer: "10.0.2.15:5000",
			time: "1970-01-01T00:00:01.000Z",
		});
		// The peer comes back from its comment; any other comment stays a comment.
		expect(records[1]).toMatchObject({
			peer: "[fe80::1]:5000",
			comment: "a note",
		});
		expect(records[2]?.peer).toBeUndefined();
	});
});

describe("captures of the stream: UDP to the TZSP port is unwrapped", () => {
	test("Ethernet: TZSP inside is the record, with the IP source as peer; other frames are frames", async () => {
		const p = pcapBuilder({ linkType: 1 });
		const other = eth(0x0800, ipv4({ proto: 1, payload: echo(8, 1, 1) }));
		const input =
			p.header() +
			p.record(eth(0x0800, udpToTzsp(REQUEST)), 1, 500_000) +
			p.record(other);
		const [tzsp, frame] = packetsOf(await decode(input, { detail: "layers" }));
		expect(tzsp).toMatchObject({
			listener: "37008",
			peer: "10.0.2.15:40000",
			time: "1970-01-01T00:00:01.500Z",
			protocols: ["ethernet", "ipv4", "icmp"],
			src: "10.0.2.15",
			dst: "10.0.2.3",
		});
		expect(tzsp?.layers?.[0]?.protocol).toBe("tzsp");
		expect(frame?.listener).toBeUndefined();
		expect(frame?.layers?.[0]?.protocol).toBe("ethernet");
	});

	test("--tzsp-port picks the ports; one per router keeps them apart", async () => {
		const p = pcapBuilder({ linkType: 1 });
		const input =
			p.header() +
			p.record(eth(0x0800, udpToTzsp(REQUEST, 37009))) +
			p.record(eth(0x0800, udpToTzsp(REQUEST, 37010)));
		const byDefault = packetsOf(await decode(input));
		// Not to 37008: both are frames, UDP to 37009 and 37010.
		expect(byDefault.map((r) => r.dstPort)).toEqual([37009, 37010]);
		const both = packetsOf(await decode(input, { tzspPorts: [37009, 37010] }));
		expect(both.map((r) => r.listener)).toEqual(["37009", "37010"]);
		expect(both.map((r) => r.protocols?.at(-1))).toEqual(["icmp", "icmp"]);
	});

	test("raw IP, IPv4, IPv6, Linux cooked v1 and v2; other packets are unsupported records", async () => {
		const v4 = udpToTzsp(REQUEST);
		const v6 = ipv6({ next: 17, payload: udp(40000, 37008, REQUEST) });
		const notTzsp = ipv4({ proto: 17, payload: udp(1, 53, "00") });
		const sll = (proto: number, packet: string) =>
			`0000000100060200000000000000${h16(proto)}${packet}`;
		const sll2 = (proto: number, packet: string) =>
			// protocol, reserved, ifindex, ARPHRD, packet type, address length, address
			`${h16(proto)}0000${"00000002"}0001${"00"}06${"0000000000000000"}${packet}`;
		const cases: [number, string, string][] = [
			[101, v4, "10.0.2.15:40000"],
			[101, v6, "[fe80::1]:40000"],
			[228, v4, "10.0.2.15:40000"],
			[229, v6, "[fe80::1]:40000"],
			[113, sll(0x0800, v4), "10.0.2.15:40000"],
			[276, sll2(0x86dd, v6), "[fe80::1]:40000"],
		];
		for (const [linkType, packet, peer] of cases) {
			const p = pcapBuilder({ linkType });
			const other =
				linkType === 113
					? sll(0x0800, notTzsp)
					: linkType === 276
						? sll2(0x0800, notTzsp)
						: notTzsp;
			const records = entriesOf(
				await decode(p.header() + p.record(packet) + p.record(other), {
					detail: "summary",
				}),
			);
			expect({ linkType, records }).toMatchObject({
				linkType,
				records: [
					{
						type: "packet",
						peer,
						listener: "37008",
						protocols: ["ethernet", "ipv4", "icmp"],
					},
					{
						type: "record",
						kind: "unsupported",
						problem: "unsupported",
						reason: "link/not-tzsp",
					},
				],
			});
			if (linkType !== 229)
				expect(records[1]?.line).toContain(
					"udp len=1 [unsupported link/not-tzsp]",
				);
		}
	});

	test("a capture with no TZSP at all says which port it looked for", async () => {
		const p = pcapBuilder({ linkType: 101 });
		const input =
			p.header() + p.record(ipv4({ proto: 17, payload: udp(1, 53, "00") }));
		const warnings = warningsOf(await decode(input));
		expect(warnings.map((w) => w.code)).toEqual(["capture/no-frames"]);
		expect(warnings[0]?.fix).toContain("--tzsp-port");
	});

	test("another link type ends the stream with decode/link-type, after what came before", async () => {
		const n = pcapngBuilder();
		const input =
			n.section() +
			n.iface(128) +
			n.iface(105) +
			n.packet(0, REQUEST) +
			n.packet(1, "00");
		const records = await decode(input);
		expect(packetsOf(records)).toHaveLength(1);
		expect(summaryOf(records)).toMatchObject({
			status: "error",
			stoppedBy: "error",
			error: { code: "decode/link-type" },
		});
	});
});

describe("bad input: bounded, and never a throw", () => {
	const n = pcapngBuilder();
	const good = n.section() + n.iface(128) + n.packet(0, REQUEST);

	test("a corrupt structure ends the stream as an error, after the packets before it", async () => {
		const huge = `06000000${le32(0xfffffff0)}`;
		const cases: [string, string][] = [
			// Over the cap: an error, not an allocation of 4 GiB.
			[good + huge, "over the"],
			[good + `06000000${le32(MAX_BLOCK_BYTES + 4)}`, "over the"],
			[good + `06000000${le32(30)}`, "not a multiple of 4"],
			[good + `06000000${le32(8)}`, "not a multiple of 4"],
			// The trailing length disagrees with the leading one.
			[good + n.packet(0, REQUEST).slice(0, -8) + le32(9999), "at its end"],
			[good + n.packet(5, REQUEST), "names interface 5"],
			[
				good + n.packet(0, REQUEST, { captured: 4000 }),
				"more than the block holds",
			],
			[`${good}0a0d0d0a${le32(28)}00000000`, "no byte-order magic"],
		];
		for (const [input, message] of cases) {
			const started = performance.now();
			const records = await decode(input);
			expect(performance.now() - started).toBeLessThan(1000);
			expect({ message, packets: packetsOf(records).length }).toEqual({
				message,
				packets: 1,
			});
			const summary = summaryOf(records);
			expect(summary).toMatchObject({
				status: "error",
				error: { code: "decode/malformed" },
			});
			expect(summary.error?.message).toContain(message);
		}
		const p = pcapBuilder({ linkType: 128 });
		const pcapHuge = `${p.header()}${p.record(REQUEST)}${le32(0)}${le32(0)}${le32(MAX_BLOCK_BYTES + 1)}${le32(0)}`;
		expect(summaryOf(await decode(pcapHuge)).error?.code).toBe(
			"decode/malformed",
		);
		// Given as pcapng, bytes that do not start with a section header.
		expect(
			summaryOf(await decode(bytes(REQUEST), { format: "pcapng" })).error,
		).toMatchObject({ code: "decode/malformed" });
	});

	test("an input that ends inside a block: the packets before it, a warning, incomplete", async () => {
		const whole = good + n.packet(0, REQUEST);
		const p = pcapBuilder({ linkType: 128 });
		const pcap = p.header() + p.record(REQUEST) + p.record(REQUEST);
		for (const cut of [
			whole.slice(0, -2),
			whole.slice(0, -100),
			`${good}0600`,
			pcap.slice(0, -2),
		]) {
			const records = await decode(cut);
			expect(packetsOf(records)).toHaveLength(1);
			expect(warningsOf(records).map((w) => w.code)).toEqual([
				"decode/truncated",
			]);
			expect(summaryOf(records)).toMatchObject({
				status: "incomplete",
				stoppedBy: "end",
			});
		}
		// Cut at a block boundary, the file is whole.
		expect(summaryOf(await decode(good)).status).toBe("complete");
	});

	test("other block types are skipped; simple packet blocks have no time", async () => {
		const input =
			n.section() +
			n.iface(128) +
			n.other(5, "00000000") +
			n.other(0x80000001, "deadbeef") +
			n.simple(REQUEST) +
			n.section() +
			n.iface(128, { name: "second" }) +
			n.packet(0, REQUEST);
		const packets = packetsOf(await decode(input));
		expect(packets).toHaveLength(2);
		expect(packets[0]?.time).toBeUndefined();
		// A new section has its own interfaces.
		expect(packets[1]?.listener).toBe("second");
	});

	test("hex: comments, blank lines, spaces and CRLF; a bad or over-long line is an error naming it", async () => {
		const spaced = REQUEST.replace(/(..)/g, "$1 ");
		const text = `# a comment\n\n${REQUEST}\r\n  ${spaced}\n${KEEPALIVE}`;
		const records = await decode(new TextEncoder().encode(text), {
			format: "hex",
		});
		expect(entriesOf(records).map((r) => r.type)).toEqual([
			"packet",
			"packet",
			"record",
		]);
		expect(packetsOf(records)[0]?.time).toBeUndefined();

		const bad = await decode(new TextEncoder().encode(`${REQUEST}\nzz\n`), {
			format: "hex",
		});
		expect(packetsOf(bad)).toHaveLength(1);
		expect(summaryOf(bad).error).toMatchObject({ code: "decode/malformed" });
		expect(summaryOf(bad).error?.message).toContain("Line 2");
		const odd = await decode(new TextEncoder().encode("010"), {
			format: "hex",
		});
		expect(summaryOf(odd).error?.code).toBe("decode/malformed");

		// Longer than the cap, in chunks: refused once the cap passes.
		let pulled = 0;
		const long = (function* () {
			for (;;) {
				pulled += 1;
				yield new Uint8Array(64 * 1024).fill(0x30);
			}
		})();
		const tooLong = await decode(long, { format: "hex" });
		expect(summaryOf(tooLong).error?.message).toContain("longer than");
		expect(pulled * 64 * 1024).toBeLessThan(MAX_HEX_LINE + 2 * 64 * 1024);
	});

	test("an input that fails while being read is decode/read-failed", async () => {
		const failing = (async function* () {
			yield bytes(good);
			throw new Error("EIO: i/o error");
		})();
		const records = await decode(failing);
		expect(packetsOf(records)).toHaveLength(1);
		expect(summaryOf(records).error).toMatchObject({
			code: "decode/read-failed",
		});
	});
});

describe("limits, signals and stopping early", () => {
	const n = pcapngBuilder();
	const three =
		n.section() +
		n.iface(128) +
		n.packet(0, REQUEST) +
		n.packet(0, REQUEST) +
		n.packet(0, REQUEST);

	test("--count stops reading and closes the input; --expect unmet is an error with its case", async () => {
		let closed = false;
		const input = {
			*[Symbol.iterator]() {
				try {
					yield bytes(three);
					yield bytes("ffffffff");
				} finally {
					closed = true;
				}
			},
		};
		const records = await decode(input, { count: 2 });
		expect(packetsOf(records).map((p) => p.seq)).toEqual([1, 2]);
		expect(summaryOf(records)).toMatchObject({
			status: "complete",
			stoppedBy: "count",
		});
		expect(closed).toBe(true);

		const unmet = summaryOf(await decode(three, { expect: 4 }));
		expect(unmet).toMatchObject({
			status: "error",
			error: { code: "capture/expect-unmet" },
		});
		const filtered = summaryOf(
			await decode(three, { expect: 1, filter: { proto: ["tcp"] } }),
		);
		expect(filtered.error).toMatchObject({
			code: "capture/expect-unmet",
			case: "capture/all-filtered",
		});
		const empty = await decode(n.section(), {});
		expect(warningsOf(empty).map((w) => w.code)).toEqual(["decode/empty"]);
	});

	test("an abort while waiting for input ends the stream as interrupted", async () => {
		const controller = new AbortController();
		let closed = false;
		const stdin = {
			[Symbol.asyncIterator]() {
				let sent = false;
				return {
					async next(): Promise<IteratorResult<Uint8Array>> {
						if (!sent) {
							sent = true;
							return { done: false, value: bytes(three) };
						}
						return new Promise(() => {});
					},
					async return(): Promise<IteratorResult<Uint8Array>> {
						closed = true;
						return { done: true, value: undefined };
					},
				};
			},
		};
		const stream = await openDecode(stdin, { signal: controller.signal });
		const records: StreamRecord[] = [];
		for await (const r of stream) {
			records.push(r);
			if (packetsOf(records).length === 3) controller.abort();
		}
		expect(summaryOf(records)).toMatchObject({
			status: "interrupted",
			stoppedBy: "interrupt",
		});
		expect(closed).toBe(true);
		// Input already in memory stops at the next packet too.
		const inMemory = new AbortController();
		const fromBytes: StreamRecord[] = [];
		for await (const r of await openDecode(bytes(three), {
			signal: inMemory.signal,
		})) {
			fromBytes.push(r);
			if (r.type === "packet") inMemory.abort();
		}
		expect(packetsOf(fromBytes)).toHaveLength(1);
		expect(summaryOf(fromBytes).status).toBe("interrupted");
		// Already aborted: nothing is read.
		await expect(
			openDecode(bytes(three), { signal: AbortSignal.abort() }),
		).rejects.toBeDefined();
	});

	test("return() before reading closes the input; a second read is refused", async () => {
		let closed = false;
		const input = {
			[Symbol.asyncIterator]() {
				return {
					async next(): Promise<IteratorResult<Uint8Array>> {
						return { done: false, value: bytes(three) };
					},
					async return(): Promise<IteratorResult<Uint8Array>> {
						closed = true;
						return { done: true, value: undefined };
					},
				};
			},
		};
		const stream = await openDecode(input, { format: "pcapng" });
		await stream[Symbol.asyncIterator]().return?.();
		expect(closed).toBe(true);
		expect(() => stream[Symbol.asyncIterator]()).toThrow(TzspSniffError);
	});
});
