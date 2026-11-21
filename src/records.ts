/**
 * The records a capture stream is made of (DESIGN.md, "Stream termination"):
 * one `header`, then `packet`, `record`, `warning` and `tip` as they happen,
 * then one `summary`. Shared by every surface: the CLI prints them as JSONL
 * or renders them as text; a library caller or an adapter gets the same
 * objects.
 *
 * `--detail` decides how much of a packet a record carries, cheapest first:
 * `line` (one tcpdump-like string), `summary` (the fields an agent filters
 * on), `layers` (every dissector's fields) and `full` (the datagram as hex).
 */
import type { Dissection, Layer } from "./dissect.ts";
import type { Code, ErrorCode, TipCode, WarningCode } from "./errors.ts";
import type { FilterSpec } from "./filter.ts";
import type { Peer } from "./listen.ts";
import { type TzspDatagram, type TzspTag, toHex } from "./tzsp.ts";

export const SCHEMA_VERSION = 1;

export const DETAILS = ["line", "summary", "layers", "full"] as const;
export type Detail = (typeof DETAILS)[number];

/** What `listen` and `decode` headers share. */
interface HeaderBase {
	type: "header";
	schemaVersion: typeof SCHEMA_VERSION;
	tool: "tzsp-sniff";
	version: string;
	/** The filters in effect, in canonical form; `{}` keeps every frame. */
	filters: FilterSpec;
	detail: Detail;
	stats: boolean;
}

/** The header of a capture from the network. */
export interface HeaderRecord extends HeaderBase {
	command: "listen";
	/** When the sockets were bound, ISO 8601. */
	time: string;
	bind: string;
	listeners: { port: number; label: string }[];
	/** The limits in effect; none means it runs until interrupted. */
	limits: {
		count?: number;
		durationMs?: number;
		idleMs?: number;
		expect?: number;
	};
	queue: { datagrams: number; bytes: number };
	/** Where every datagram is saved (`--write`), when it is. */
	write?: string;
}

/** The input formats `decode` reads. */
export const INPUT_FORMATS = ["pcapng", "pcap", "hex"] as const;
export type InputFormat = (typeof INPUT_FORMATS)[number];

/** The header of a `decode` stream: a file or stdin, no network. */
export interface DecodeHeaderRecord extends HeaderBase {
	command: "decode";
	/** When decoding started, ISO 8601. */
	time: string;
	/** What was read: its name (a path, `-` for stdin) and format, detected or given. */
	input: { name: string; format: InputFormat };
	/** UDP ports whose datagrams are unwrapped as TZSP in IP, Ethernet or Linux cooked captures. */
	tzspPorts: number[];
	limits: { count?: number; expect?: number };
}

export type AnyHeaderRecord = HeaderRecord | DecodeHeaderRecord;

/** A layer as a record carries it: offsets index the datagram, not the frame. */
export type RecordLayer =
	| Layer
	| {
			protocol: "tzsp";
			offset: number;
			length: number;
			fields: {
				/** The TZSP header and tags; the frame starts here. */
				headerLength: number;
				version: number;
				type: string;
				encapsulation: string;
				tags: TzspTag[];
			};
	  };

/**
 * What a packet or record is made from: a datagram a listener received (a
 * `Capture` is one), or a packet `decode` read from a file. Each field is
 * there only when the source says it: a file RouterOS saved has no listener
 * or peer, a hex line has no time (DESIGN.md, "`decode` input").
 */
export type Entry = EntryBase &
	(
		| {
				/** The TZSP datagram it carried; its bytes are `tzsp.datagram`. */
				tzsp: TzspDatagram;
		  }
		| {
				tzsp?: undefined;
				/** An Ethernet frame with no TZSP around it (a file RouterOS saved). */
				frame: Uint8Array;
		  }
	);

export interface EntryBase {
	/** Position: arrival order for `listen`, order in the input for `decode`; from 1. */
	seq: number;
	/** ms since the epoch: host arrival time, or the file's timestamp. */
	time?: number;
	/** The listener that received it, or the one a file names. */
	listener?: { readonly label: string };
	/** The UDP peer, as received or as a file recorded it. */
	peer?: Peer;
	/** The interface a capture file names (not a TZSP listener's label). */
	interface?: string;
	/** The capture file's comment on the packet, other than its peer. */
	comment?: string;
}

export type TzspEntry = Extract<Entry, { tzsp: TzspDatagram }>;

export interface PacketRecord {
	type: "packet";
	seq: number;
	/** Absent when the input had no time (hex lines). */
	time?: string;
	/** The listener's label (its port number unless one was given); absent when the input names none. */
	listener?: string;
	line: string;
	// summary and up
	peer?: string;
	/** The capture file's interface name (`decode`), such as `ether1 rx`. */
	interface?: string;
	/** The frame's length in bytes. */
	length?: number;
	protocols?: string[];
	/** IP addresses when there is an IP layer, else ARP's, else the MACs. */
	src?: string;
	dst?: string;
	srcPort?: number;
	dstPort?: number;
	vlan?: number[];
	/** TCP flags that are set. */
	flags?: string[];
	problem?: string;
	/** `<protocol>/<check>`, such as `ipv4/total-length`. */
	reason?: string;
	// layers and up
	layers?: RecordLayer[];
	/** The capture file's comment on the packet (`decode`), such as RouterOS's `cpu:0 fp:0`. */
	comment?: string;
	// full
	/**
	 * The bytes the layers' offsets index, hex: the whole TZSP datagram, or
	 * the frame when the input held no TZSP (a file RouterOS saved).
	 */
	datagram?: string;
}

/** A TZSP record that is not a frame: control, unsupported or invalid. */
export interface DatagramRecord {
	type: "record";
	seq: number;
	time?: string;
	listener?: string;
	line: string;
	peer?: string;
	interface?: string;
	/** The datagram's length in bytes. */
	length?: number;
	kind?: "control" | "unsupported" | "invalid";
	problem?: string;
	/** `tzsp/<check>`, such as `tzsp/no-end-tag`; `link/not-tzsp` for a packet in a capture that is not TZSP. */
	reason?: string;
	tzspType?: string;
	tags?: TzspTag[];
	comment?: string;
	datagram?: string;
}

export interface WarningRecord {
	type: "warning";
	code: WarningCode;
	message: string;
	fix?: string;
}

export interface TipRecord {
	type: "tip";
	code: TipCode;
	message: string;
}

export interface Counters {
	/** Every datagram the sockets delivered: the sum of the counters below. */
	datagrams: number;
	/** Frames reported. `--count` and `--expect` count these. */
	packets: number;
	control: number;
	unsupported: number;
	invalid: number;
	/** Frames the filters removed: not reported, not in the tables. */
	filtered: number;
	/** Datagrams dropped because the queue was full. */
	dropped: number;
	/** Datagrams still queued when the capture stopped. */
	unread: number;
	/**
	 * Datagrams read but neither counted above nor reported, because saving
	 * them (`--write`, `--format pcapng`) failed; the capture ended there.
	 */
	unsaved: number;
}

export interface Ranked<T> {
	top: T[];
	/** How many more entries there were, folded into `otherCount`. */
	otherEntries: number;
	/**
	 * True when distinct folded entries passed what is tracked: `otherEntries`
	 * is then a lower bound ("1000 or more"), while `otherCount` stays exact.
	 */
	otherEntriesCapped: boolean;
	/** Packets or datagrams in the folded entries. */
	otherCount: number;
}

/**
 * Protocols, problems and conversations count the packets reported, after
 * filters. Senders count every datagram the capture read, of any kind,
 * filtered frames included; dropped and unread ones are not read.
 */
export interface SummaryTables {
	/** How many packets each protocol appeared in. */
	protocols: Record<string, number>;
	/** Packet problems by `<protocol>/<check>`. */
	problems: Record<string, number>;
	/** `listener` or `peer` is absent when the input did not say it (`decode`). */
	senders: Ranked<{ listener?: string; peer?: string; datagrams: number }>;
	conversations: Ranked<{
		protocol: string;
		a: string;
		b: string;
		packets: number;
		bytes: number;
	}>;
}

export type SummaryStatus = "complete" | "interrupted" | "incomplete" | "error";
/** `end`: `decode` read the whole input. */
export type StopReason =
	| "count"
	| "duration"
	| "idle"
	| "end"
	| "interrupt"
	| "error";

export interface SummaryRecord extends SummaryTables {
	type: "summary";
	/**
	 * `complete`: a limit was met and nothing was dropped. `interrupted`: the
	 * caller stopped it. `incomplete`: datagrams were dropped. `error`: see
	 * `error`. A stream that ends without a summary was cut off.
	 */
	status: SummaryStatus;
	stoppedBy: StopReason;
	durationMs: number;
	counters: Counters;
	/** What `--write` saved: every datagram read, before filters. */
	written?: { datagrams: number; bytes: number };
	error?: { code: ErrorCode; message: string; fix?: string; case?: Code };
}

export type StreamRecord =
	| HeaderRecord
	| DecodeHeaderRecord
	| PacketRecord
	| DatagramRecord
	| WarningRecord
	| TipRecord
	| SummaryRecord;

/**
 * A packet from a live capture: it always has its arrival time and the
 * listener that received it (and, from `summary` detail, its peer).
 */
export type CapturePacketRecord = PacketRecord & {
	time: string;
	listener: string;
};
/** A non-frame record from a live capture, with the same guarantees. */
export type CaptureDatagramRecord = DatagramRecord & {
	time: string;
	listener: string;
};
/** A live capture's summary: every sender row has a listener and a peer. */
export type CaptureSummaryRecord = SummaryRecord & {
	senders: Ranked<{ listener: string; peer: string; datagrams: number }>;
};

/**
 * What a capture yields: `listen`'s header, and packets, records and a
 * summary with the fields a live capture always has.
 */
export type CaptureRecord =
	| HeaderRecord
	| CapturePacketRecord
	| CaptureDatagramRecord
	| WarningRecord
	| TipRecord
	| CaptureSummaryRecord;
/** What a decode yields: its header is `decode`'s. */
export type DecodeRecord = Exclude<StreamRecord, HeaderRecord>;

/**
 * The fields `--fields` can name on a packet or record, each with the least
 * `--detail` that carries it.
 */
export const ENTRY_FIELDS = {
	seq: "line",
	time: "line",
	listener: "line",
	line: "line",
	peer: "summary",
	interface: "summary",
	length: "summary",
	kind: "summary",
	tzspType: "summary",
	protocols: "summary",
	src: "summary",
	srcPort: "summary",
	dst: "summary",
	dstPort: "summary",
	vlan: "summary",
	flags: "summary",
	problem: "summary",
	reason: "summary",
	layers: "layers",
	tags: "layers",
	comment: "layers",
	datagram: "full",
} as const satisfies Record<string, Detail>;

/** The fields `--fields` can name on a summary. */
export const SUMMARY_FIELDS = [
	"status",
	"stoppedBy",
	"durationMs",
	"counters",
	"protocols",
	"problems",
	"senders",
	"conversations",
	"written",
	"error",
] as const;

/**
 * A record with only the named fields, in that order, after `type`
 * (DESIGN.md, "Output for agents"). It shapes the results: packets,
 * records and the summary. A summary keeps its `status`, and its `error`
 * when it has one, so a failed capture still says why. A header, warning or
 * tip is returned whole: they frame the stream, and their codes are what a
 * reader acts on. A field the record does not have is left out.
 */
export function selectFields(
	record: StreamRecord,
	fields: readonly string[],
): Record<string, unknown> {
	if (
		record.type !== "packet" &&
		record.type !== "record" &&
		record.type !== "summary"
	) {
		return record as unknown as Record<string, unknown>;
	}
	const source = record as unknown as Record<string, unknown>;
	const out: Record<string, unknown> = { type: record.type };
	const keep = [...fields];
	if (record.type === "summary") {
		if (!keep.includes("status")) keep.unshift("status");
		if (record.error && !keep.includes("error")) keep.push("error");
	}
	for (const field of keep) {
		if (field !== "type" && Object.hasOwn(source, field))
			out[field] = source[field];
	}
	return out;
}

export const isoTime = (ms: number) => new Date(ms).toISOString();

export const formatPeer = (address: string, port: number) =>
	address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;

type Find<P extends Layer["protocol"]> = Extract<Layer, { protocol: P }>;
const find = <P extends Layer["protocol"]>(d: Dissection, ...protocols: P[]) =>
	d.layers.find((l): l is Find<P> =>
		(protocols as string[]).includes(l.protocol),
	);

/** What a summary needs from a dissection, found once per packet. */
export interface PacketView {
	src?: string;
	dst?: string;
	srcPort?: number;
	dstPort?: number;
	vlan: number[];
	/** The innermost protocol named for conversations: `tcp`, `icmp`, `arp`, `ipv4`, an EtherType … */
	protocol: string;
}

/**
 * What a type/length field names: its EtherType, LLC when it is an 802.3
 * length, or nothing for the reserved 1501 to 1535, which the dissector
 * reports as `malformed/type-length`.
 */
const typeLengthName = (f: { etherType?: string; length?: number }) =>
	f.etherType ?? (f.length !== undefined ? "llc" : undefined);

export function viewPacket(d: Dissection): PacketView {
	const view: PacketView = { vlan: [], protocol: "ethernet" };
	for (const layer of d.layers) {
		if (layer.protocol === "data") continue;
		if (layer.protocol === "vlan" && layer.fields)
			view.vlan.push(layer.fields.id);
		if (!layer.fields) {
			view.protocol = layer.protocol;
			continue;
		}
		switch (layer.protocol) {
			case "ethernet":
				view.src = layer.fields.src;
				view.dst = layer.fields.dst;
				view.protocol = typeLengthName(layer.fields) ?? "ethernet";
				break;
			case "vlan":
				view.protocol = typeLengthName(layer.fields) ?? "vlan";
				break;
			case "arp":
				view.protocol = "arp";
				if (layer.fields.senderIp && layer.fields.targetIp) {
					view.src = layer.fields.senderIp;
					view.dst = layer.fields.targetIp;
				}
				break;
			case "ipv4":
			case "ipv6":
				view.src = layer.fields.src;
				view.dst = layer.fields.dst;
				view.protocol =
					layer.fields.protocolName ?? `ip-proto-${layer.fields.protocol}`;
				break;
			case "udp":
			case "tcp":
				view.srcPort = layer.fields.srcPort;
				view.dstPort = layer.fields.dstPort;
				view.protocol = layer.protocol;
				break;
			default:
				view.protocol = layer.protocol;
		}
	}
	return view;
}

const TCP_LETTERS: Record<string, string> = {
	syn: "S",
	fin: "F",
	rst: "R",
	psh: "P",
	urg: "U",
	ece: "E",
	cwr: "W",
	ack: ".",
};

/**
 * A value as one word of a line: quoted as JSON when empty or when it has
 * spaces, quotes or control characters, with the C1 controls and the line
 * and paragraph separators JSON leaves as they are escaped too, so the
 * value never breaks the line.
 */
const word = (s: string) =>
	s === "" || /[\s"\\\p{Cc}]/u.test(s)
		? JSON.stringify(s).replace(
				/[\u007f-\u009f\u2028\u2029]/g,
				(c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
			)
		: s;

const hostPort = (host: string | undefined, port: number) =>
	host?.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;

/** One tcpdump-like line for a frame, without time or listener. */
export function packetLine(d: Dissection): string {
	const parts: string[] = [];
	const vlans = d.layers.flatMap((l) =>
		l.protocol === "vlan" && l.fields ? [l.fields.id] : [],
	);
	if (vlans.length) parts.push(`vlan ${vlans.join(",")}`);
	const eth = find(d, "ethernet");
	const arp = find(d, "arp");
	const lldp = find(d, "lldp");
	const ip = find(d, "ipv4", "ipv6");
	const icmp = find(d, "icmp", "icmpv6");
	const udp = find(d, "udp");
	const tcp = find(d, "tcp");
	const dhcp = find(d, "dhcp");
	const mndp = find(d, "mndp");

	if (arp?.fields) {
		const f = arp.fields;
		if (f.operation === 1 && f.targetIp) {
			parts.push(`arp who-has ${f.targetIp} tell ${f.senderIp}`);
		} else if (f.operation === 2 && f.senderIp) {
			parts.push(`arp ${f.senderIp} is-at ${f.senderMac}`);
		} else {
			parts.push(`arp ${f.operationName}`);
		}
	} else if (lldp?.fields && eth?.fields) {
		const f = lldp.fields;
		const lldpParts = [`${eth.fields.src} > ${eth.fields.dst} lldp`];
		if (f.chassisId !== undefined)
			lldpParts.push(`chassis ${word(f.chassisId)}`);
		if (f.portId !== undefined) lldpParts.push(`port ${word(f.portId)}`);
		if (f.ttl !== undefined) lldpParts.push(`ttl ${f.ttl}`);
		if (f.systemName !== undefined)
			lldpParts.push(`name ${word(f.systemName)}`);
		parts.push(lldpParts.join(" "));
	} else if (ip?.fields) {
		const f = ip.fields;
		if (tcp?.fields) {
			const t = tcp.fields;
			const letters = t.flags.map((flag) => TCP_LETTERS[flag] ?? "").join("");
			parts.push(
				`${hostPort(f.src, t.srcPort)} > ${hostPort(f.dst, t.dstPort)} tcp [${letters}] seq=${t.seq}` +
					(t.flags.includes("ack") ? ` ack=${t.ack}` : "") +
					` win=${t.window} len=${t.payloadLength}`,
			);
		} else if (udp?.fields && dhcp?.fields) {
			const u = udp.fields;
			const h = dhcp.fields;
			const dhcpParts = [
				`${hostPort(f.src, u.srcPort)} > ${hostPort(f.dst, u.dstPort)} dhcp`,
				h.messageTypeName ??
					(h.messageType !== undefined
						? `type-${h.messageType}`
						: (h.opName ?? `op-${h.op}`)),
				`xid ${h.xid}`,
				`mac ${h.chaddr}`,
			];
			if (h.ciaddr !== "0.0.0.0") dhcpParts.push(`client-ip ${h.ciaddr}`);
			if (h.yiaddr !== "0.0.0.0") dhcpParts.push(`your-ip ${h.yiaddr}`);
			if (h.requestedAddress !== undefined)
				dhcpParts.push(`requested ${h.requestedAddress}`);
			parts.push(dhcpParts.join(" "));
		} else if (udp?.fields && mndp?.fields) {
			const u = udp.fields;
			const m = mndp.fields;
			const mndpParts = [
				`${hostPort(f.src, u.srcPort)} > ${hostPort(f.dst, u.dstPort)} mndp`,
			];
			if (m.request) mndpParts.push("request");
			if (m.identity !== undefined)
				mndpParts.push(`identity ${word(m.identity)}`);
			if (m.macAddress !== undefined) mndpParts.push(`mac ${m.macAddress}`);
			if (m.version !== undefined) mndpParts.push(`version ${word(m.version)}`);
			if (m.board !== undefined) mndpParts.push(`board ${word(m.board)}`);
			if (m.ttlName !== undefined) mndpParts.push(m.ttlName);
			parts.push(mndpParts.join(" "));
		} else if (udp?.fields) {
			const u = udp.fields;
			parts.push(
				`${hostPort(f.src, u.srcPort)} > ${hostPort(f.dst, u.dstPort)} udp len=${u.payloadLength}`,
			);
		} else if (icmp?.fields) {
			const c = icmp.fields;
			let text = `${f.src} > ${f.dst} ${icmp.protocol} ${c.typeName ?? `type=${c.type}`}`;
			if (c.code !== 0 || !c.typeName) text += ` code=${c.code}`;
			if (c.id !== undefined) text += ` id=${c.id} seq=${c.sequence}`;
			if (c.targetAddress) text += ` target=${c.targetAddress}`;
			parts.push(`${text} len=${c.length}`);
		} else {
			const name = f.protocolName ?? `ip-proto-${f.protocol}`;
			const fragment =
				(f.fragmentOffset ?? 0) > 0
					? ` fragment offset=${f.fragmentOffset}`
					: "";
			parts.push(
				`${f.src} > ${f.dst} ${name}${fragment} len=${find(d, "data")?.length ?? 0}`,
			);
		}
	} else if (eth?.fields) {
		const f = eth.fields;
		const last = d.layers.findLast((l) => l.protocol !== "data") ?? eth;
		let what: string = last.protocol;
		const named = (fields: { etherType?: string; length?: number }) =>
			fields.etherType
				? `ethertype ${fields.etherType}`
				: (typeLengthName(fields) ?? last.protocol);
		if (last.protocol === "ethernet") what = named(f);
		// An inner 802.3 length means LLC, as it does untagged.
		else if (last.protocol === "vlan" && last.fields) what = named(last.fields);
		parts.push(`${f.src} > ${f.dst} ${what} len=${d.frame.length}`);
	} else {
		parts.push(`ethernet len=${d.frame.length}`);
	}
	if (d.problem) {
		parts.push(
			`[${d.problem.problem} ${d.problem.protocol}/${d.problem.reason}]`,
		);
	}
	return parts.join(" ");
}

function tzspLayer(t: TzspDatagram): RecordLayer {
	return {
		protocol: "tzsp",
		offset: 0,
		// The whole datagram, so the frame's layers lie inside it.
		length: t.datagram.length,
		fields: {
			headerLength: t.datagram.length - t.payload.length,
			version: t.version,
			type: t.typeName,
			encapsulation: t.encapsulationName,
			tags: t.tags,
		},
	};
}

/** The fields every packet and record starts with, from what the entry has. */
function entryHead(entry: Entry): {
	seq: number;
	time?: string;
	listener?: string;
} {
	const head: { seq: number; time?: string; listener?: string } = {
		seq: entry.seq,
	};
	if (entry.time !== undefined) head.time = isoTime(entry.time);
	if (entry.listener) head.listener = entry.listener.label;
	return head;
}

/** A frame's record at `detail`. */
export function packetRecord(
	entry: Entry,
	d: Dissection,
	detail: Detail,
	line = packetLine(d),
	view?: PacketView,
): PacketRecord {
	const record: PacketRecord = { type: "packet", ...entryHead(entry), line };
	if (detail === "line") return record;
	const v = view ?? viewPacket(d);
	if (entry.peer) record.peer = formatPeer(entry.peer.address, entry.peer.port);
	if (entry.interface !== undefined) record.interface = entry.interface;
	record.length = d.frame.length;
	record.protocols = d.protocols;
	if (v.src !== undefined) record.src = v.src;
	if (v.dst !== undefined) record.dst = v.dst;
	if (v.srcPort !== undefined) record.srcPort = v.srcPort;
	if (v.dstPort !== undefined) record.dstPort = v.dstPort;
	if (v.vlan.length) record.vlan = v.vlan;
	const tcp = find(d, "tcp");
	if (tcp?.fields) record.flags = tcp.fields.flags;
	if (d.problem) {
		record.problem = d.problem.problem;
		record.reason = `${d.problem.protocol}/${d.problem.reason}`;
	}
	if (detail === "summary") return record;
	const t = entry.tzsp;
	if (t) {
		const shift = t.datagram.length - t.payload.length;
		record.layers = [
			tzspLayer(t),
			...d.layers.map((l) => ({ ...l, offset: l.offset + shift })),
		];
	} else {
		record.layers = d.layers.map((l) => ({ ...l }));
	}
	if (entry.comment !== undefined) record.comment = entry.comment;
	if (detail === "layers") return record;
	record.datagram = toHex(t ? t.datagram : entry.frame);
	return record;
}

/** One line for a TZSP record that is not a frame. */
export function datagramLine(entry: TzspEntry): string {
	const t = entry.tzsp;
	if (t.kind === "control") return `tzsp ${t.typeName}`;
	if (t.kind === "unsupported") {
		const what =
			t.reason === "encapsulation"
				? `encapsulation ${t.encapsulationName}`
				: t.typeName;
		return `tzsp ${what} len=${t.datagram.length} [unsupported tzsp/${t.reason}]`;
	}
	if (t.kind === "invalid") {
		return `tzsp len=${t.datagram.length} [${t.problem} tzsp/${t.reason}]`;
	}
	return `tzsp ${t.typeName} len=${t.datagram.length}`;
}

/** A non-frame TZSP record at `detail`. */
export function datagramRecord(
	entry: TzspEntry,
	detail: Detail,
): DatagramRecord {
	const t = entry.tzsp;
	const record: DatagramRecord = {
		type: "record",
		...entryHead(entry),
		line: datagramLine(entry),
	};
	if (detail === "line") return record;
	if (entry.peer) record.peer = formatPeer(entry.peer.address, entry.peer.port);
	if (entry.interface !== undefined) record.interface = entry.interface;
	record.length = t.datagram.length;
	if (t.kind !== "packet") record.kind = t.kind;
	if (t.kind !== "invalid") record.tzspType = t.typeName;
	if (t.problem) {
		record.problem = t.problem;
		record.reason = `tzsp/${t.reason}`;
	}
	if (detail === "summary") return record;
	if (t.tags.length) record.tags = t.tags;
	if (entry.comment !== undefined) record.comment = entry.comment;
	if (detail === "layers") return record;
	record.datagram = toHex(t.datagram);
	return record;
}
