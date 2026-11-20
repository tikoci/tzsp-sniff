/**
 * `decode`: the capture pipeline over a file or stdin, with no network
 * (DESIGN.md, "`decode` input"). The same records as `listen` (header,
 * packets and records, warnings, one summary), from packets a pcapng, pcap
 * or hex input held.
 *
 * The link type decides what a packet is:
 *
 * - `LINKTYPE_TZSP` (128): a TZSP datagram, as `--write` saves it. The
 *   interface name is the listener's label and a `peer=` comment the UDP
 *   peer, so a file this tool wrote decodes to the records it printed.
 * - Ethernet (1): a frame that is UDP to a TZSP port is unwrapped to its
 *   datagram (a host capture of the stream, such as tshark's); any other is
 *   an inner frame (a file RouterOS saved), with no listener or peer.
 * - Raw IP (101), IPv4 (228), IPv6 (229), Linux cooked SLL (113) and SLL2
 *   (276): UDP to a TZSP port is unwrapped; any other packet is an
 *   `unsupported` record, since it carries no frame to dissect.
 * - Any other link type ends the stream with `decode/link-type`.
 *
 * IP fragments are not reassembled: a datagram's first fragment unwraps to
 * a TZSP record cut short, and a later one is not UDP.
 */
import {
	type Dissection,
	dissect,
	dissectFrom,
	type Ipv4Layer,
	type Ipv6Layer,
	type UdpLayer,
} from "./dissect.ts";
import { type Code, TzspSniffError } from "./errors.ts";
import { createFilter, type FilterSpec } from "./filter.ts";
import {
	ByteReader,
	type DecodeInput,
	detectFormat,
	type FilePacket,
	InputAborted,
	type InputState,
	readPackets,
} from "./input.ts";
import type { Peer } from "./listen.ts";
import { LINKTYPE_TZSP } from "./pcapng.ts";
import {
	type Counters,
	type DatagramRecord,
	type DecodeHeaderRecord,
	type Detail,
	DETAILS,
	datagramRecord,
	type Entry,
	INPUT_FORMATS,
	type InputFormat,
	isoTime,
	type PacketRecord,
	packetLine,
	packetRecord,
	SCHEMA_VERSION,
	type DecodeRecord,
	type StopReason,
	type SummaryRecord,
	type SummaryStatus,
	type TzspEntry,
	viewPacket,
	type WarningRecord,
} from "./records.ts";
import { summarize } from "./summary.ts";
import { parseTzsp, TZSP_PORT, toHex } from "./tzsp.ts";
import { VERSION } from "./version.ts";

export interface DecodeOptions {
	/** What the header calls the input: a path, `-` for stdin. Default `input`. */
	name?: string;
	/** The input's format; detected from its first bytes when left out. `hex` is never detected. */
	format?: InputFormat;
	/** UDP ports whose datagrams are unwrapped as TZSP (default 37008). */
	tzspPorts?: readonly number[];
	/** Stop after this many packets are reported. */
	count?: number;
	/** Fewer packets reported than this makes the summary an error. */
	expect?: number;
	/** How much each packet record carries (default `summary`). */
	detail?: Detail;
	/** Report only the summary: no packet or record entries. */
	stats?: boolean;
	/** Keep only the frames this spec matches; as in `openCapture`. */
	filter?: FilterSpec;
	/** Aborting ends the stream as `interrupted`; an already aborted signal opens nothing. */
	signal?: AbortSignal;
}

/** A decode's record stream. Read it once, as a capture. */
export interface DecodeStream extends AsyncIterable<DecodeRecord> {
	readonly header: DecodeHeaderRecord;
}

const LINK_ETHERNET = 1;
const LINK_RAW = 101;
const LINK_IPV4 = 228;
const LINK_IPV6 = 229;
const LINK_SLL = 113;
const LINK_SLL2 = 276;

const LINK_NAMES: Record<number, string> = {
	[LINK_ETHERNET]: "ethernet",
	[LINK_RAW]: "raw ip",
	[LINK_IPV4]: "ipv4",
	[LINK_IPV6]: "ipv6",
	[LINK_SLL]: "linux cooked",
	[LINK_SLL2]: "linux cooked v2",
	[LINKTYPE_TZSP]: "tzsp",
};

const positive = (name: string, value: number | undefined) => {
	if (
		value !== undefined &&
		(!Number.isSafeInteger(value) || (value as number) < 1)
	) {
		throw new TzspSniffError(
			"decode/invalid-option",
			`${name} must be a whole number above 0, not ${value}.`,
			`Leave ${name} unset, or give a whole number above 0.`,
		);
	}
};

/**
 * `peer=10.0.2.15:37008`, `peer=[::1]:37008` or, with a zone,
 * `peer=[fe80::1%eth0]:37008`, as the pcapng writer puts it.
 */
function peerOf(comment: string): Peer | undefined {
	const m =
		/^peer=(?:\[([0-9A-Fa-f:.]+(?:%[^\]]+)?)\]|([0-9.]+)):([0-9]{1,5})$/.exec(
			comment,
		);
	const port = Number(m?.[3]);
	if (!m || port > 65535) return undefined;
	const address = (m[1] ?? m[2]) as string;
	return { address, port, family: m[1] ? "IPv6" : "IPv4" };
}

/** A packet in a capture that is not TZSP and not a frame: an `unsupported` record. */
interface NotTzsp {
	notTzsp: true;
	seq: number;
	time?: number;
	interface?: string;
	comment?: string;
	data: Uint8Array;
	line: string;
}

type Decoded = (Entry & { dissection?: Dissection }) | NotTzsp;

/** The UDP datagram to a TZSP port in `d`, as an entry's source fields. */
function unwrap(
	d: Dissection,
	ports: ReadonlySet<number>,
): { payload: Uint8Array; peer: Peer; port: number } | undefined {
	const udp = d.layers.find((l): l is UdpLayer => l.protocol === "udp");
	if (!udp?.fields || !ports.has(udp.fields.dstPort)) return undefined;
	// A UDP length that contradicts the packet leaves no payload to trust:
	// the packet is reported as it is. One cut short (a snap length, a first
	// fragment) still unwraps what is there.
	if (udp.problem === "malformed") return undefined;
	const ip = d.layers.findLast(
		(l): l is Ipv4Layer | Ipv6Layer =>
			(l.protocol === "ipv4" || l.protocol === "ipv6") && l.offset < udp.offset,
	);
	if (!ip?.fields) return undefined;
	const start = udp.offset + 8;
	return {
		payload: d.frame.subarray(start, Math.max(start, udp.offset + udp.length)),
		peer: {
			address: ip.fields.src,
			port: udp.fields.srcPort,
			family: ip.protocol === "ipv4" ? "IPv4" : "IPv6",
		},
		port: udp.fields.dstPort,
	};
}

/** The EtherType of a network-layer packet with no link header, or undefined. */
function networkType(
	p: FilePacket,
): { type: number; bytes: Uint8Array } | undefined {
	const data = p.data;
	const u16 = (at: number) => ((data[at] ?? 0) << 8) | (data[at + 1] ?? 0);
	switch (p.linkType) {
		case LINK_RAW: {
			const version = (data[0] ?? 0) >> 4;
			if (version === 4) return { type: 0x0800, bytes: data };
			if (version === 6) return { type: 0x86dd, bytes: data };
			return undefined;
		}
		case LINK_IPV4:
			return { type: 0x0800, bytes: data };
		case LINK_IPV6:
			return { type: 0x86dd, bytes: data };
		case LINK_SLL:
			return data.length < 16
				? undefined
				: { type: u16(14), bytes: data.subarray(16) };
		case LINK_SLL2:
			return data.length < 20
				? undefined
				: { type: u16(0), bytes: data.subarray(20) };
	}
	return undefined;
}

/** What a file's packet becomes: an entry for the pipeline, or an unsupported record. */
function decodePacket(
	p: FilePacket,
	seq: number,
	ports: ReadonlySet<number>,
): Decoded {
	const base: {
		seq: number;
		time?: number;
		interface?: string;
		comment?: string;
	} = { seq };
	if (p.time !== undefined) base.time = p.time;
	if (p.linkType === LINKTYPE_TZSP) {
		// Our own files: the interface is the listener, the comment the peer.
		const entry: TzspEntry = { ...base, tzsp: parseTzsp(p.data) };
		if (p.interfaceName !== undefined)
			entry.listener = { label: p.interfaceName };
		const others: string[] = [];
		for (const c of p.comments) {
			const peer = entry.peer === undefined ? peerOf(c) : undefined;
			if (peer) entry.peer = peer;
			else others.push(c);
		}
		if (others.length) entry.comment = others.join("\n");
		return entry;
	}
	if (p.interfaceName !== undefined) base.interface = p.interfaceName;
	if (p.comments.length) base.comment = p.comments.join("\n");
	const known = LINK_NAMES[p.linkType];
	if (known === undefined) {
		throw new TzspSniffError(
			"decode/link-type",
			`Packet ${seq} has link type ${p.linkType}, which decode does not read.`,
			"decode reads TZSP (128), Ethernet (1), raw IP (101, 228, 229) and Linux cooked (113, 276) captures; capture the TZSP stream on one of those.",
		);
	}
	const tzspFrom = (u: NonNullable<ReturnType<typeof unwrap>>): TzspEntry => ({
		...base,
		listener: { label: String(u.port) },
		peer: u.peer,
		tzsp: parseTzsp(u.payload),
	});
	if (p.linkType === LINK_ETHERNET) {
		const d = dissect(p.data);
		const u = unwrap(d, ports);
		if (u) return tzspFrom(u);
		return { ...base, frame: p.data, dissection: d };
	}
	const network = networkType(p);
	const d = network ? dissectFrom(network.bytes, network.type) : undefined;
	const u = d ? unwrap(d, ports) : undefined;
	if (u) return tzspFrom(u);
	const readable = d?.layers.some(
		(l) =>
			(l.protocol === "ipv4" ||
				l.protocol === "ipv6" ||
				l.protocol === "arp") &&
			l.fields,
	);
	return {
		notTzsp: true,
		...base,
		data: p.data,
		line: `${d && readable ? packetLine(d) : `${known} len=${p.data.length}`} [unsupported link/not-tzsp]`,
	};
}

function notTzspRecord(n: NotTzsp, detail: Detail): DatagramRecord {
	const record: DatagramRecord = { type: "record", seq: n.seq, line: n.line };
	if (n.time !== undefined) record.time = isoTime(n.time);
	if (detail === "line") return record;
	if (n.interface !== undefined) record.interface = n.interface;
	record.length = n.data.length;
	record.kind = "unsupported";
	record.problem = "unsupported";
	record.reason = "link/not-tzsp";
	if (detail === "summary") return record;
	if (n.comment !== undefined) record.comment = n.comment;
	if (detail === "layers") return record;
	record.datagram = toHex(n.data);
	return record;
}

/**
 * Read `input` and return its record stream. Iterating it yields the
 * `header` first and, unless the caller stops early, exactly one `summary`
 * last. Invalid options, an input whose format cannot be told and an
 * aborted signal reject here, before any record; everything the input
 * holds after its first bytes is reported in the stream.
 */
export async function openDecode(
	input: DecodeInput,
	options: DecodeOptions = {},
): Promise<DecodeStream> {
	const { count, expect, signal } = options;
	positive("count", count);
	positive("expect", expect);
	if (options.format !== undefined && !INPUT_FORMATS.includes(options.format)) {
		throw new TzspSniffError(
			"decode/invalid-option",
			`format must be one of ${INPUT_FORMATS.join(", ")}, not ${String(options.format)}.`,
			"Leave format unset to detect pcapng or pcap, or give hex for hex lines.",
		);
	}
	const detail = options.detail ?? "summary";
	if (!DETAILS.includes(detail)) {
		throw new TzspSniffError(
			"decode/invalid-option",
			`detail must be one of ${DETAILS.join(", ")}, not ${String(detail)}.`,
			"Leave detail unset for summary.",
		);
	}
	const tzspPorts = [...new Set(options.tzspPorts ?? [TZSP_PORT])];
	if (
		!tzspPorts.length ||
		tzspPorts.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)
	) {
		throw new TzspSniffError(
			"decode/invalid-option",
			`tzspPorts must be UDP ports from 1 to 65535, not ${JSON.stringify(options.tzspPorts)}.`,
			`Leave tzspPorts unset for ${TZSP_PORT}.`,
		);
	}
	const ports = new Set(tzspPorts);
	const statsOnly = options.stats ?? false;
	const filter = createFilter(options.filter);
	if (signal?.aborted) throw signal.reason;

	const reader = new ByteReader(input, signal);
	// Aborted while the input's iterator was made: nothing is opened.
	if (signal?.aborted) {
		await reader.close(false);
		throw signal.reason;
	}
	let format = options.format;
	if (format === undefined) {
		let head: Uint8Array;
		try {
			head = await reader.peek(4);
		} catch (error) {
			const aborted = error instanceof InputAborted;
			// Aborted: the source's return() is started, not waited for.
			await reader.close(!aborted).catch(() => {});
			if (aborted) throw signal?.reason ?? error;
			throw readFailure(error);
		}
		format = detectFormat(head);
		if (format === undefined) {
			await reader.close().catch(() => {});
			// Aborted while the source cleaned up: that is the outcome.
			if (signal?.aborted) throw signal.reason;
			const text = /^[0-9a-fA-F#\s]+$/.test(new TextDecoder().decode(head));
			throw new TzspSniffError(
				"decode/unknown-format",
				head.length === 0
					? "The input is empty, so its format cannot be told."
					: `The input starts with ${toHex(head)}, which is neither pcapng nor pcap.`,
				text
					? "For one datagram per line as hex, give --input hex (format: hex)."
					: "Give a pcapng or pcap capture, or --input hex for hex lines.",
			);
		}
	}

	const limits: DecodeHeaderRecord["limits"] = {};
	if (count !== undefined) limits.count = count;
	if (expect !== undefined) limits.expect = expect;
	const header: DecodeHeaderRecord = {
		type: "header",
		schemaVersion: SCHEMA_VERSION,
		tool: "tzsp-sniff",
		version: VERSION,
		command: "decode",
		time: isoTime(Date.now()),
		input: { name: options.name ?? "input", format },
		tzspPorts,
		limits,
		filters: filter.spec,
		detail,
		stats: statsOnly,
	};
	const inputFormat = format;

	async function* run(): AsyncGenerator<DecodeRecord> {
		const counters: Counters = {
			datagrams: 0,
			packets: 0,
			control: 0,
			unsupported: 0,
			invalid: 0,
			filtered: 0,
			dropped: 0,
			unread: 0,
			unsaved: 0,
		};
		const stats = summarize();
		const state: InputState = {};
		let failure: TzspSniffError | undefined;
		let stoppedBy: StopReason | undefined;
		/** Packets in an IP or Linux cooked capture that were not UDP to a TZSP port. */
		let notTzsp = 0;
		let first: number | undefined;
		let last: number | undefined;
		try {
			yield header;
			try {
				const packets = readPackets(reader, inputFormat, state);
				for (;;) {
					// Before each packet is asked for: bytes already buffered
					// (a bad hex line) must not turn an abort into an error.
					if (signal?.aborted) throw new InputAborted();
					const next = await packets.next();
					if (next.done) break;
					const p = next.value;
					const seq = counters.datagrams + 1;
					const decoded = decodePacket(p, seq, ports);
					counters.datagrams = seq;
					if (p.time !== undefined) {
						first = Math.min(first ?? p.time, p.time);
						last = Math.max(last ?? p.time, p.time);
					}
					let record: PacketRecord | DatagramRecord | undefined;
					if ("notTzsp" in decoded) {
						notTzsp += 1;
						counters.unsupported += 1;
						if (!statsOnly) record = notTzspRecord(decoded, detail);
					} else {
						const d =
							decoded.tzsp === undefined
								? decoded.dissection
								: decoded.tzsp.kind === "packet"
									? dissect(decoded.tzsp.payload)
									: undefined;
						stats.addDatagram(decoded);
						if (d) {
							if (filter(decoded, d)) {
								const view = viewPacket(d);
								counters.packets += 1;
								stats.addPacket(d, view);
								if (!statsOnly)
									record = packetRecord(decoded, d, detail, undefined, view);
							} else {
								counters.filtered += 1;
							}
						} else {
							const entry = decoded as TzspEntry;
							const kind = entry.tzsp.kind as Exclude<
								TzspEntry["tzsp"]["kind"],
								"packet"
							>;
							counters[kind] += 1;
							if (!statsOnly) record = datagramRecord(entry, detail);
						}
					}
					if (count !== undefined && counters.packets >= count)
						stoppedBy = "count";
					if (record) yield record;
					if (stoppedBy) {
						await packets.return(undefined);
						break;
					}
				}
				// The input ended while the consumer held a record, and the
				// signal fired then: that is an interrupt, not the end.
				if (!stoppedBy && signal?.aborted) throw new InputAborted();
			} catch (error) {
				if (error instanceof InputAborted) stoppedBy = "interrupt";
				else {
					failure =
						error instanceof TzspSniffError ? error : readFailure(error);
					stoppedBy = "error";
				}
			}
		} finally {
			// On an interrupt the source is told to stop, not waited for.
			await reader.close(stoppedBy !== "interrupt").catch(() => {});
		}
		// Aborted while the source cleaned up after its end: the abort ended
		// the wait, so it is the reason. A count reached stays.
		if (!stoppedBy && signal?.aborted) stoppedBy = "interrupt";
		stoppedBy ??= "end";

		if (state.truncatedAt !== undefined && !failure) {
			yield {
				type: "warning",
				code: "decode/truncated",
				message: `The input ends inside the block that starts at byte ${state.truncatedAt}; the packets before it were decoded.`,
				fix: "If the capture was still being written, decode it again once it has stopped; otherwise the file was cut short (a full disk, a copy that ended early).",
			} satisfies WarningRecord;
		}
		let emptyCase: WarningRecord | undefined;
		if (!failure && counters.packets === 0) {
			if (counters.datagrams === 0) {
				emptyCase = {
					type: "warning",
					code: "decode/empty",
					message: `${header.input.name} held no packets.`,
					fix: "Check that it is the capture you meant; a --write file holds what the listener read.",
				};
			} else if (
				counters.control + counters.unsupported + counters.invalid ===
				counters.datagrams
			) {
				emptyCase = {
					type: "warning",
					code: "capture/no-frames",
					message: `${header.input.name} held ${counters.datagrams} packets, but none was a frame to dissect.`,
					fix: notTzsp
						? `None of its packets was UDP to port ${tzspPorts.join(" or ")}: give the port the stream went to with --tzsp-port, or run with --detail summary to see what each packet is.`
						: "Run again with --format text or jsonl and --detail full to see each record's bytes.",
				};
			} else if (counters.filtered > 0) {
				const flags = filter.flags.join(" ");
				emptyCase = {
					type: "warning",
					code: "capture/all-filtered",
					message: `${header.input.name} held ${counters.filtered} frames, and the filters removed all of them: ${flags}.`,
					fix: `Loosen or drop the filters (${flags}); --stats without them shows what is there.`,
				};
			}
			if (emptyCase) yield emptyCase;
		}
		if (!failure && expect !== undefined && counters.packets < expect) {
			failure = new TzspSniffError(
				"capture/expect-unmet",
				`Expected at least ${expect} packets; ${counters.packets} were reported.`,
				emptyCase?.fix ?? "Check the input and the filters.",
			);
		}
		let status: SummaryStatus = "complete";
		if (failure) status = "error";
		else if (stoppedBy === "interrupt") status = "interrupted";
		else if (state.truncatedAt !== undefined) status = "incomplete";
		const summary: SummaryRecord = {
			type: "summary",
			status,
			stoppedBy,
			// The span of the input's timestamps: what the capture covered.
			durationMs: first !== undefined && last !== undefined ? last - first : 0,
			counters,
			...stats.tables(),
		};
		if (failure) {
			summary.error = { code: failure.code, message: failure.message };
			if (failure.fix) summary.error.fix = failure.fix;
			const caseCode: Code | undefined = emptyCase?.code;
			if (caseCode && failure.code === "capture/expect-unmet")
				summary.error.case = caseCode;
		}
		yield summary;
	}

	let used = false;
	return {
		header,
		[Symbol.asyncIterator](): AsyncIterator<DecodeRecord> {
			if (used) {
				throw new TzspSniffError(
					"capture/reused",
					"This decode has already been read; a stream is read once.",
					"Call openDecode() again with the input.",
				);
			}
			used = true;
			const generator = run();
			// A generator that never started never runs its finally: close the
			// input here too, so a caller that stops early releases the file.
			return {
				next: () => generator.next(),
				return: async (value?: unknown) => {
					await reader.close().catch(() => {});
					return generator.return(value);
				},
				throw: async (error?: unknown) => {
					await reader.close().catch(() => {});
					return generator.throw(error);
				},
			};
		},
	};
}

/** A failure to read the input, as a coded error. */
function readFailure(error: unknown): TzspSniffError {
	if (error instanceof TzspSniffError) return error;
	const message = error instanceof Error ? error.message : String(error);
	return new TzspSniffError(
		"decode/read-failed",
		`Reading the input failed: ${message}`,
		"Check that the file is readable and not a directory; the records before this point were decoded.",
		{ cause: error },
	);
}
