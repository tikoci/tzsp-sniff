// cspell:ignore tsresol -- pcapng option name
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { openCapture } from "../../src/capture.ts";
import { type DecodeOptions, openDecode } from "../../src/decode.ts";
import { TzspSniffError } from "../../src/errors.ts";
import {
	ByteReader,
	MAX_BLOCK_BYTES,
	MAX_HEX_LINE,
	MAX_INTERFACES,
} from "../../src/input.ts";
import { type ByteSink, pcapngWriter, peerComment } from "../../src/pcapng.ts";
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
	const u64 = (n: bigint) => {
		const hex = BigInt.asUintN(64, n).toString(16).padStart(16, "0");
		return little ? (hex.match(/../g)?.reverse().join("") as string) : hex;
	};
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
		/** A section header; `length` is the section's, -1 for unknown. */
		section: (length = -1n) =>
			block(0x0a0d0d0a, u32(0x1a2b3c4d) + u16(1) + u16(0) + u64(length)),
		iface: (
			linkType: number,
			o: {
				name?: string;
				tsresol?: number;
				tsoffset?: bigint;
				snapLength?: number;
			} = {},
		) =>
			block(
				1,
				u16(linkType) +
					u16(0) +
					u32(o.snapLength ?? 0) +
					options([
						...(o.name ? [option(2, text(o.name))] : []),
						...(o.tsresol !== undefined
							? [option(9, h16(o.tsresol).slice(2))]
							: []),
						...(o.tsoffset !== undefined ? [option(14, u64(o.tsoffset))] : []),
					]),
			),
		packet: (
			id: number,
			dataHex: string,
			o: {
				units?: bigint;
				comments?: string[];
				captured?: number;
				original?: number;
			} = {},
		) => {
			const units = o.units ?? 0n;
			return block(
				6,
				u32(id) +
					u32(Number(units >> 32n)) +
					u32(Number(units & 0xffffffffn)) +
					u32(o.captured ?? dataHex.length / 2) +
					u32(o.original ?? dataHex.length / 2) +
					pad4(dataHex) +
					options((o.comments ?? []).map((c) => option(1, text(c)))),
			);
		},
		/** An obsolete packet block (type 2): a 16-bit interface id and drops count. */
		obsolete: (
			id: number,
			dataHex: string,
			o: { units?: bigint; original?: number } = {},
		) => {
			const units = o.units ?? 0n;
			return block(
				2,
				u16(id) +
					u16(0) +
					u32(Number(units >> 32n)) +
					u32(Number(units & 0xffffffffn)) +
					u32(dataHex.length / 2) +
					u32(o.original ?? dataHex.length / 2) +
					pad4(dataHex),
			);
		},
		/** A simple packet block; `original` may contradict the data, for tests. */
		simple: (dataHex: string, original = dataHex.length / 2) =>
			block(3, u32(original) + pad4(dataHex)),
		other: (type: number, bodyHex: string) => block(type, bodyHex),
	};
}

/** pcap, hex. */
function pcapBuilder(o: {
	little?: boolean;
	nano?: boolean;
	linkType: number;
	magic?: number;
	major?: number;
	snapLength?: number;
}) {
	const little = o.little ?? true;
	const u16 = little ? le16 : h16;
	const u32 = little ? le32 : h32;
	return {
		header: () =>
			u32(o.magic ?? (o.nano ? 0xa1b23c4d : 0xa1b2c3d4)) +
			u16(o.major ?? 2) +
			u16(4) +
			u32(0) +
			u32(0) +
			u32(o.snapLength ?? 65535) +
			u32(o.linkType),
		record: (
			dataHex: string,
			seconds = 0,
			fraction = 0,
			original = dataHex.length / 2,
		) =>
			u32(seconds) +
			u32(fraction) +
			u32(dataHex.length / 2) +
			u32(original) +
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
		const cases: [string, string, string?][] = [
			[pcapng, "pcapng"],
			[pcapngBig, "pcapng"],
		];
		// 125 ms after a whole second, at either resolution: a reader that
		// takes nanoseconds for microseconds is off by a factor of 1000.
		for (const little of [true, false]) {
			for (const nano of [true, false]) {
				const p = pcapBuilder({ little, nano, linkType: 128 });
				cases.push([
					p.header() +
						p.record(REQUEST, 1_700_000_000, nano ? 125_000_000 : 125_000),
					"pcap",
					"2023-11-14T22:13:20.125Z",
				]);
			}
		}
		for (const [input, format, time] of cases) {
			const records = await decode(input);
			if (time) expect(packetsOf(records)[0]?.time).toBe(time);
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
			// A label that starts with U+FEFF must survive the file (cross-review).
			ports: [{ port: 0, label: "\uFEFFedge" }],
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
		expect(listened[0]).toMatchObject({ listener: "\uFEFFedge" });
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
			n.packet(0, "01") +
			// Version 1, a type it does not decode (1, for transmit), the end tag.
			n.packet(0, "0101000101");
		const records = entriesOf(await decode(input, { detail: "layers" }));
		expect(records.map((r) => [r.type, (r as DatagramRecord).kind])).toEqual([
			["record", "control"],
			["record", "invalid"],
			["record", "invalid"],
			["record", "unsupported"],
		]);
		expect(records[3]).toMatchObject({ reason: "tzsp/record-type" });
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
		const notTzsp6 = ipv6({ next: 17, payload: udp(1, 53, "00") });
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
						: linkType === 229
							? notTzsp6
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
			expect({ linkType, line: records[1]?.line }).toMatchObject({
				linkType,
				line: expect.stringContaining("udp len=1 [unsupported link/not-tzsp]"),
			});
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
			// Given in one chunk, then the end: a reader that went on to read
			// a block it should have refused asks for more.
			let pulledPast = false;
			const records = await decode(
				(function* () {
					yield bytes(input);
					pulledPast = true;
				})(),
			);
			expect({
				message,
				packets: packetsOf(records).length,
				pulledPast: message === "over the" ? pulledPast : false,
			}).toEqual({ message, packets: 1, pulledPast: false });
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

		// Longer than the cap, in chunks: refused once the cap passes. Three
		// chunks cross it; a fourth pull means the cap did not hold.
		let fourth = false;
		const long = (function* () {
			for (let i = 0; i < 3; i++) yield new Uint8Array(64 * 1024).fill(0x30);
			fourth = true;
			throw new Error("pulled a fourth chunk");
		})();
		expect(3 * 64 * 1024).toBeGreaterThan(MAX_HEX_LINE);
		const tooLong = await decode(long, { format: "hex" });
		expect(summaryOf(tooLong).error?.message).toContain("longer than");
		expect(fourth).toBe(false);
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

describe("cross-review of 7d0d428: structure the readers must refuse or keep", () => {
	const n = pcapngBuilder();
	const ok = n.section() + n.iface(128);
	const errorOf = async (
		input: string | Uint8Array,
		options: DecodeOptions = {},
	) => summaryOf(await decode(input, options)).error?.code;

	test("--input pcap checks the magic number and the version", async () => {
		const bad = pcapBuilder({ linkType: 128, magic: 0 });
		expect(
			await errorOf(bad.header() + bad.record(REQUEST), { format: "pcap" }),
		).toBe("decode/malformed");
		const v99 = pcapBuilder({ linkType: 128, major: 99 });
		expect(await errorOf(v99.header() + v99.record(REQUEST))).toBe(
			"decode/malformed",
		);
	});

	test("pcap: a record over the snap length, or over 1 MiB with its header, is malformed", async () => {
		const snap = pcapBuilder({ linkType: 128, snapLength: 1 });
		expect(await errorOf(snap.header() + snap.record(REQUEST))).toBe(
			"decode/malformed",
		);
		const p = pcapBuilder({ linkType: 1, snapLength: 0 });
		const fits = "00".repeat(MAX_BLOCK_BYTES - 16);
		const fitting = await decode(p.header() + p.record(fits));
		expect(summaryOf(fitting).status).toBe("complete");
		expect(await errorOf(p.header() + p.record(`${fits}00`))).toBe(
			"decode/malformed",
		);
	});

	test("a simple packet block must hold its packet, cut to the snap length, padded", async () => {
		// The original length says 16 bytes more than the block holds.
		const short =
			n.section() + n.iface(128) + n.simple(REQUEST, REQUEST.length / 2 + 16);
		expect(await errorOf(short)).toBe("decode/malformed");
		// More bytes than the packet needs.
		const long =
			n.section() +
			n.iface(128) +
			n.simple(`${REQUEST}00000000`, REQUEST.length / 2);
		expect(await errorOf(long)).toBe("decode/malformed");
		// A snap length cuts it: what is held is the packet's first bytes.
		const cut =
			n.section() +
			n.iface(128, { snapLength: 8 }) +
			n.simple(REQUEST.slice(0, 16), REQUEST.length / 2);
		const records = entriesOf(await decode(cut));
		expect(records).toHaveLength(1);
		expect(summaryOf(await decode(cut)).status).toBe("complete");
	});

	test("a section's declared length: blocks past it are malformed, a section cut short is incomplete", async () => {
		const iface = n.iface(128);
		const packet = n.packet(0, REQUEST);
		const size = (hex: string) => BigInt(hex.length / 2);
		// Room for the interface only, then a packet.
		expect(await errorOf(n.section(size(iface)) + iface + packet)).toBe(
			"decode/malformed",
		);
		// Room for two packets, one there.
		const cut = await decode(
			n.section(size(iface + packet + packet)) + iface + packet,
		);
		expect(packetsOf(cut)).toHaveLength(1);
		expect(summaryOf(cut).status).toBe("incomplete");
		// Exact, then a new section with its own length unknown.
		const exact = await decode(
			n.section(size(iface + packet)) +
				iface +
				packet +
				n.section() +
				iface +
				packet,
		);
		expect(packetsOf(exact)).toHaveLength(2);
		expect(summaryOf(exact).status).toBe("complete");
		// Not a multiple of 4 (Copilot review of 10ada3c): malformed, not cut short.
		for (const length of [1n, size(iface) + 2n]) {
			expect({
				length,
				code: await errorOf(n.section(length) + iface),
			}).toEqual({ length, code: "decode/malformed" });
		}
	});

	test("a UDP length that contradicts its packet is not unwrapped", async () => {
		const badUdp = ipv4({
			proto: 17,
			src: "192.0.2.1",
			dst: "10.0.2.2",
			payload: udp(40000, 37008, REQUEST, 7),
		});
		const raw = pcapBuilder({ linkType: 101 });
		const [record] = entriesOf(
			await decode(raw.header() + raw.record(badUdp), { detail: "summary" }),
		);
		expect(record).toMatchObject({ type: "record", reason: "link/not-tzsp" });
		const ether = pcapBuilder({ linkType: 1 });
		const [frame] = packetsOf(
			await decode(ether.header() + ether.record(eth(0x0800, badUdp)), {
				detail: "summary",
			}),
		);
		expect(frame).toMatchObject({ problem: "malformed", reason: "udp/length" });
		expect(frame?.listener).toBeUndefined();
	});

	test("timestamps are exact, and one past a Date's range is malformed whatever the output", async () => {
		// 1 Hz units with an offset of -2^53 s: the epoch, then one second on.
		const exact =
			n.section() +
			n.iface(128, { tsresol: 0, tsoffset: -(2n ** 53n) }) +
			n.packet(0, REQUEST, { units: 2n ** 53n }) +
			n.packet(0, REQUEST, { units: 2n ** 53n + 1n });
		expect(packetsOf(await decode(exact)).map((p) => p.time)).toEqual([
			"1970-01-01T00:00:00.000Z",
			"1970-01-01T00:00:01.000Z",
		]);
		// 2^-10 s units: 1023/1024 s rounds down to 999 ms, not up to 1000.
		const binary =
			n.section() +
			n.iface(128, { tsresol: 0x8a }) +
			n.packet(0, REQUEST, { units: 1023n });
		expect(packetsOf(await decode(binary))[0]?.time).toBe(
			"1970-01-01T00:00:00.999Z",
		);
		const far =
			n.section() +
			n.iface(128, { tsresol: 0, tsoffset: 8_640_000_000_001n }) +
			n.packet(0, REQUEST);
		for (const stats of [false, true]) {
			expect({ stats, code: await errorOf(far, { stats }) }).toEqual({
				stats,
				code: "decode/malformed",
			});
		}
	});

	test("a section holds at most MAX_INTERFACES interfaces; a new section starts again", async () => {
		const many = n.iface(128).repeat(MAX_INTERFACES);
		const full = await decode(
			n.section() + many + n.packet(MAX_INTERFACES - 1, REQUEST),
		);
		expect(summaryOf(full).status).toBe("complete");
		expect(await errorOf(n.section() + many + n.iface(128))).toBe(
			"decode/malformed",
		);
		const again = await decode(
			n.section() + many + n.section() + n.iface(128) + n.packet(0, REQUEST),
		);
		expect(summaryOf(again).status).toBe("complete");
		// Names count too: an option holds at most 64 KiB, so 17 names of
		// 62 KiB pass 1 MiB, and 16 do not.
		const named = n.iface(128, { name: "x".repeat(62 * 1024) });
		expect(await errorOf(n.section() + named.repeat(16))).toBeUndefined();
		expect(await errorOf(n.section() + named.repeat(17))).toBe(
			"decode/malformed",
		);
	});

	test("hex in one-byte chunks: each byte is scanned once, and lines split right", async () => {
		const line = "ab".repeat(30 * 1024);
		const text = new TextEncoder().encode(`${line}\n${KEEPALIVE}\n`);
		const reader = new ByteReader(trickle(text));
		// Quadratic scanning of 61,450 one-byte chunks takes minutes; linear, milliseconds.
		const first = await reader.readLine(MAX_HEX_LINE);
		expect((first as Uint8Array).length).toBe(line.length);
		const second = await reader.readLine(MAX_HEX_LINE);
		expect(new TextDecoder().decode(second as Uint8Array)).toBe(KEEPALIVE);
		expect(await reader.readLine(MAX_HEX_LINE)).toBeUndefined();
	}, 5000);

	test("a source that reuses its buffer for each chunk decodes the same", async () => {
		const p = pcapBuilder({ linkType: 128 });
		const file = bytes(p.header() + p.record(REQUEST) + p.record(KEEPALIVE));
		const reused = (function* () {
			const one = new Uint8Array(1);
			for (const b of file) {
				one[0] = b;
				yield one;
			}
		})();
		const whole = entriesOf(await decode(file, { detail: "full" }));
		expect(entriesOf(await decode(reused, { detail: "full" }))).toEqual(whole);
	});

	test("an abort while a read waits on the input ends the stream, also during detection", async () => {
		// A source whose next() never settles, and whose return() would wait
		// behind it, as an async generator's does.
		const parked = (first?: Uint8Array) => ({
			[Symbol.asyncIterator]() {
				let sent = first === undefined;
				let release = () => {};
				const pending = new Promise<void>((resolve) => {
					release = resolve;
				});
				return {
					async next(): Promise<IteratorResult<Uint8Array>> {
						if (!sent && first) {
							sent = true;
							return { done: false, value: first };
						}
						await new Promise(() => {});
						return { done: true, value: undefined };
					},
					async return(): Promise<IteratorResult<Uint8Array>> {
						await pending;
						release();
						return { done: true, value: undefined };
					},
				};
			},
		});
		const controller = new AbortController();
		const stream = await openDecode(parked(bytes(ok + n.packet(0, REQUEST))), {
			signal: controller.signal,
		});
		const records: StreamRecord[] = [];
		for await (const r of stream) {
			records.push(r);
			if (r.type === "packet") setTimeout(() => controller.abort(), 10);
		}
		expect(summaryOf(records).status).toBe("interrupted");

		const detecting = new AbortController();
		setTimeout(() => detecting.abort(), 10);
		await expect(
			openDecode(parked(Uint8Array.of(0x0a, 0x0d)), {
				signal: detecting.signal,
			}),
		).rejects.toBeDefined();
	}, 5000);
});

describe("CodeRabbit review of 64ff141", () => {
	/** The reader's private state, for what it holds. */
	const inside = (reader: ByteReader) =>
		reader as unknown as {
			buffered: number;
			chunks: Uint8Array[];
			head: number;
		};
	const n = pcapngBuilder();
	const ok = n.section() + n.iface(128);
	const errorOf = async (
		input: string | Uint8Array,
		options: DecodeOptions = {},
	) => summaryOf(await decode(input, options)).error?.code;

	test("a Buffer reused for each chunk decodes the same (Buffer#slice is a view)", async () => {
		const p = pcapBuilder({ linkType: 128 });
		const file = bytes(p.header() + p.record(REQUEST) + p.record(KEEPALIVE));
		const reused = (function* () {
			const one = Buffer.alloc(1);
			for (const b of file) {
				one[0] = b;
				yield one;
			}
		})();
		const whole = entriesOf(await decode(file, { detail: "full" }));
		expect(entriesOf(await decode(reused, { detail: "full" }))).toEqual(whole);
	});

	test("one huge chunk is copied in spans as needed, not whole", async () => {
		const huge = new Uint8Array(8 * 1024 * 1024).fill(0x30);
		const reader = new ByteReader([huge]);
		expect(await reader.readLine(MAX_HEX_LINE)).toBe("too-long");
		// What the reader holds, not the 8 MiB the source gave.
		expect(inside(reader).buffered).toBeLessThanOrEqual(
			MAX_HEX_LINE + 64 * 1024,
		);
		// Lines inside a huge chunk still split right.
		const text = new TextEncoder().encode(
			`${"ab".repeat(200_000)}\n`.repeat(5),
		);
		const many = new ByteReader([text]);
		const lengths: number[] = [];
		for (;;) {
			const line = await many.readLine(MAX_HEX_LINE * 4);
			if (line === undefined) break;
			lengths.push((line as Uint8Array).length);
		}
		expect(lengths).toEqual([400_000, 400_000, 400_000, 400_000, 400_000]);
	});

	test("chunks used up are released, not held until the array is compacted", async () => {
		const reader = new ByteReader(
			Array.from({ length: 100 }, () => new Uint8Array(100)),
		);
		for (let i = 0; i < 100; i++) await reader.read(100);
		const { chunks, head } = inside(reader);
		expect(head).toBeGreaterThan(0);
		expect(chunks.slice(0, head).every((c) => c.length === 0)).toBe(true);
	});

	test("an abort races a pull that is a thenable, or one aborted from inside next()", async () => {
		const stalled = (next: (signal: AbortController) => unknown) => {
			const controller = new AbortController();
			return {
				controller,
				input: {
					[Symbol.asyncIterator]: () => ({ next: () => next(controller) }),
				} as unknown as AsyncIterable<Uint8Array>,
			};
		};
		// A promise from another realm is not `instanceof Promise`: a thenable.
		// biome-ignore lint/suspicious/noThenProperty: the test needs a thenable that is not a Promise.
		const thenable = stalled(() => ({ then() {} }));
		setTimeout(() => thenable.controller.abort(), 10);
		await expect(
			openDecode(thenable.input, { signal: thenable.controller.signal }),
		).rejects.toBeDefined();
		// The source aborts while next() runs, then never settles.
		const inside = stalled((c) => {
			c.abort();
			return new Promise(() => {});
		});
		await expect(
			openDecode(inside.input, { signal: inside.controller.signal }),
		).rejects.toBeDefined();
	}, 2000);

	test("an abort after the last packet, or with nothing to read, is interrupted, not end", async () => {
		const controller = new AbortController();
		const stream = await openDecode(new Uint8Array(0), {
			format: "hex",
			signal: controller.signal,
		});
		const records: StreamRecord[] = [];
		for await (const r of stream) {
			records.push(r);
			if (r.type === "header") controller.abort();
		}
		expect(summaryOf(records)).toMatchObject({
			status: "interrupted",
			stoppedBy: "interrupt",
		});
	});

	test("on an abort, a source's return() is not waited for", async () => {
		const controller = new AbortController();
		const source = {
			[Symbol.asyncIterator]() {
				let sent = false;
				return {
					async next(): Promise<IteratorResult<Uint8Array>> {
						if (sent) return { done: true, value: undefined };
						sent = true;
						return {
							done: false,
							value: bytes(ok + n.packet(0, REQUEST) + n.packet(0, REQUEST)),
						};
					},
					return: () => new Promise<IteratorResult<Uint8Array>>(() => {}),
				};
			},
		};
		const stream = await openDecode(source, { signal: controller.signal });
		const records: StreamRecord[] = [];
		for await (const r of stream) {
			records.push(r);
			if (r.type === "packet") controller.abort();
		}
		expect(summaryOf(records).status).toBe("interrupted");
	}, 2000);

	test("pcapng: the exact time is checked against a Date's range before it rounds", async () => {
		const at = (units: bigint, tsoffset?: bigint) =>
			n.section() +
			n.iface(128, {
				tsresol: 6,
				...(tsoffset === undefined ? {} : { tsoffset }),
			}) +
			n.packet(0, REQUEST, { units });
		const max = 8_640_000_000_000_000n;
		expect(packetsOf(await decode(at(max * 1000n)))[0]?.time).toBe(
			"+275760-09-13T00:00:00.000Z",
		);
		expect(await errorOf(at(max * 1000n + 1n))).toBe("decode/malformed");
		const back = -8_640_000_000_000n;
		expect(packetsOf(await decode(at(0n, back)))[0]?.time).toBe(
			"-271821-04-20T00:00:00.000Z",
		);
		expect(await errorOf(at(0n, back - 1n))).toBe("decode/malformed");
	});

	test("pcapng: a packet over its interface's snap length, or a simple block that wraps, is malformed", async () => {
		const snapped = n.section() + n.iface(128, { snapLength: 8 });
		expect(await errorOf(snapped + n.packet(0, REQUEST))).toBe(
			"decode/malformed",
		);
		// Zero is no limit.
		expect(packetsOf(await decode(ok + n.packet(0, REQUEST)))).toHaveLength(1);
		// 0xfffffffd rounds up past 2^32: a 32-bit mask wraps it to 0.
		expect(await errorOf(ok + n.simple("", 0xfffffffd))).toBe(
			"decode/malformed",
		);
	});

	test("pcap: the fraction rounds down before the seconds are added", async () => {
		const p = pcapBuilder({ linkType: 128, nano: true });
		const records = await decode(
			p.header() + p.record(REQUEST, 1_700_000_000, 999_999),
		);
		expect(packetsOf(records)[0]?.time).toBe("2023-11-14T22:13:20.000Z");
	});
});

describe("final review of 71d400c", () => {
	const n = pcapngBuilder();
	const errorOf = async (
		input: string | Uint8Array,
		options: DecodeOptions = {},
	) => summaryOf(await decode(input, options)).error?.code;

	test("an abort during detection: a settled pull still loses, and return() is not waited for", async () => {
		const controller = new AbortController();
		let entered = false;
		const source = {
			[Symbol.asyncIterator]: () => ({
				async next(): Promise<IteratorResult<Uint8Array>> {
					controller.abort();
					return { done: false, value: new Uint8Array(0) };
				},
				return(): Promise<IteratorResult<Uint8Array>> {
					entered = true;
					return new Promise(() => {});
				},
			}),
		};
		const error = await openDecode(source, { signal: controller.signal }).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(error).toMatchObject({ name: "AbortError" });
		expect(entered).toBe(true);

		// A sync source that aborts and ends: the abort, not decode/unknown-format.
		const sync = new AbortController();
		const ended = {
			[Symbol.iterator]: () => ({
				next(): IteratorResult<Uint8Array> {
					sync.abort();
					return { done: true, value: undefined };
				},
			}),
		};
		const second = await openDecode(ended, { signal: sync.signal }).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(second).toMatchObject({ name: "AbortError" });
	}, 2000);

	test("an abort before a bad line already buffered is interrupted, not decode/malformed", async () => {
		const controller = new AbortController();
		const stream = await openDecode(new TextEncoder().encode("zz\n"), {
			format: "hex",
			signal: controller.signal,
		});
		const records: StreamRecord[] = [];
		for await (const r of stream) {
			records.push(r);
			if (r.type === "header") controller.abort();
		}
		expect(summaryOf(records)).toMatchObject({
			status: "interrupted",
			stoppedBy: "interrupt",
		});
	});

	test("a hex line in one huge buffer is searched no further than the cap", async () => {
		let widest = 0;
		class Watched extends Uint8Array {
			override indexOf(value: number, from = 0): number {
				widest = Math.max(widest, this.length - from);
				return super.indexOf(value, from);
			}
		}
		const huge = new Watched(8 * 1024 * 1024).fill(0x30);
		expect(await new ByteReader(huge).readLine(MAX_HEX_LINE)).toBe("too-long");
		expect(widest).toBeLessThanOrEqual(MAX_HEX_LINE + 1);
		// A line exactly at the cap is read; one byte more is too long.
		const text = (length: number) =>
			new TextEncoder().encode(`${"0".repeat(length)}\n${KEEPALIVE}\n`);
		const atCap = new ByteReader(text(16));
		expect((await atCap.readLine(16)) as Uint8Array).toHaveLength(16);
		expect(
			new TextDecoder().decode((await atCap.readLine(16)) as Uint8Array),
		).toBe(KEEPALIVE);
		expect(await new ByteReader(text(17)).readLine(16)).toBe("too-long");
	});

	test("pcap: a fraction of a whole second or more is malformed", async () => {
		for (const [nano, top] of [
			[true, 1_000_000_000],
			[false, 1_000_000],
		] as const) {
			const p = pcapBuilder({ linkType: 128, nano });
			const at = (fraction: number) =>
				p.header() + p.record(KEEPALIVE, 1_700_000_000, fraction);
			expect({
				nano,
				time: entriesOf(await decode(at(top - 1)))[0]?.time,
			}).toEqual({ nano, time: "2023-11-14T22:13:20.999Z" });
			expect({ nano, code: await errorOf(at(top)) }).toEqual({
				nano,
				code: "decode/malformed",
			});
		}
	});

	test("obsolete packet blocks: the record, its time and interface; over the snap length is malformed", async () => {
		const input =
			n.section() +
			n.iface(128, { name: "edge", tsresol: 3 }) +
			n.obsolete(0, KEEPALIVE, { units: 1500n });
		const records = entriesOf(await decode(input));
		expect(records).toHaveLength(1);
		expect(records[0]).toMatchObject({
			type: "record",
			kind: "control",
			listener: "edge",
			time: "1970-01-01T00:00:01.500Z",
		});
		const snapped =
			n.section() + n.iface(128, { snapLength: 2 }) + n.obsolete(0, KEEPALIVE);
		expect(await errorOf(snapped)).toBe("decode/malformed");
	});
});

describe("CodeRabbit review of f3e1d01", () => {
	test("a scoped IPv6 peer comes back from the comment the writer puts", async () => {
		const n = pcapngBuilder();
		const input =
			n.section() +
			n.iface(128, { name: "37008", tsresol: 3 }) +
			n.packet(0, KEEPALIVE, {
				comments: [peerComment("fe80::1%eth0", 5000)],
			});
		const records = entriesOf(await decode(input));
		expect(records[0]).toMatchObject({ peer: "[fe80::1%eth0]:5000" });
		expect(records[0]).not.toHaveProperty("comment");
	});

	test("an abort while an unknown input's return() hangs: the wait ends, and it is the abort", async () => {
		const controller = new AbortController();
		const source = {
			[Symbol.asyncIterator]: () => ({
				async next(): Promise<IteratorResult<Uint8Array>> {
					return { done: false, value: new TextEncoder().encode("zzzz") };
				},
				return(): Promise<IteratorResult<Uint8Array>> {
					setTimeout(() => controller.abort(), 20);
					return new Promise(() => {});
				},
			}),
		};
		const error = await openDecode(source, { signal: controller.signal }).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(error).toMatchObject({ name: "AbortError" });
	}, 2000);
});

describe("Copilot review of 4a2508e", () => {
	test("a packet that says it captured more than its original length is malformed", async () => {
		const n = pcapngBuilder();
		const p = pcapBuilder({ linkType: 128 });
		const length = KEEPALIVE.length / 2;
		const inputs = (original: number) => ({
			epb: n.section() + n.iface(128) + n.packet(0, KEEPALIVE, { original }),
			pb: n.section() + n.iface(128) + n.obsolete(0, KEEPALIVE, { original }),
			pcap: p.header() + p.record(KEEPALIVE, 0, 0, original),
		});
		for (const [name, input] of Object.entries(inputs(length - 1))) {
			const summary = summaryOf(await decode(input));
			expect({ name, code: summary.error?.code }).toEqual({
				name,
				code: "decode/malformed",
			});
		}
		// Equal, or a packet cut to fewer bytes than it had, decodes.
		for (const original of [length, length + 100]) {
			for (const [name, input] of Object.entries(inputs(original))) {
				const records = entriesOf(await decode(input));
				expect({ name, original, kinds: records.map((r) => r.type) }).toEqual({
					name,
					original,
					kinds: ["record"],
				});
			}
		}
	});
});
