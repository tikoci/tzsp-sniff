// cspell:ignore DSCP ECN QinQ RARP DEI
/**
 * Frame dissectors: Ethernet, 802.1Q and 802.1ad, ARP, IPv4, IPv6, ICMP,
 * ICMPv6, UDP and TCP (DESIGN.md, "Dissectors", order 1; LLDP is next).
 *
 * Pure and bounded, like `parseTzsp`: bytes in, layers out, no I/O, and it
 * never throws. Each layer keeps its span in the frame, so its bytes can be
 * read again; a layer that cannot finish says why with `problem` and
 * `reason`. A child's span lies inside its parent's: an IPv4 total length
 * shorter than the frame trims it (Ethernet padding is not passed up), a
 * longer one is `truncated` and dissection goes on over the bytes there are.
 *
 * Field layouts and numbers are from the RFCs and IANA registries named at
 * each dissector; no Wireshark code is used.
 */

/** What went wrong in a layer (the same three classes as `parseTzsp`). */
export type DissectProblem = "truncated" | "malformed" | "unsupported";

export interface EthernetFields {
	dst: string;
	src: string;
	/** `0x0800` style, when the type/length field is an EtherType (≥ 0x0600). */
	etherType?: string;
	/** An IEEE 802.3 length (≤ 1500): the frame carries LLC, not decoded here. */
	length?: number;
}

export interface VlanFields {
	priority: number;
	dei: boolean;
	id: number;
	/** The inner EtherType, as in {@link EthernetFields}. */
	etherType?: string;
	/** An inner IEEE 802.3 length: LLC follows, not decoded here. */
	length?: number;
}

export interface ArpFields {
	hardwareType: number;
	protocolType: string;
	operation: number;
	/** `request`, `reply`, `rarp-request`, `rarp-reply`, or `op-<n>`. */
	operationName: string;
	/** Present for Ethernet and IPv4 addresses, the only kind decoded. */
	senderMac?: string;
	senderIp?: string;
	targetMac?: string;
	targetIp?: string;
}

export interface Ipv4Fields {
	headerLength: number;
	dscp: number;
	ecn: number;
	totalLength: number;
	id: number;
	dontFragment: boolean;
	moreFragments: boolean;
	/** In bytes (the header field times 8). */
	fragmentOffset: number;
	ttl: number;
	protocol: number;
	/** A name from {@link IP_PROTOCOLS}, when it has one. */
	protocolName?: string;
	src: string;
	dst: string;
	/** Header options, as hex, when the header is longer than 20 bytes. */
	options?: string;
}

export interface Ipv6Extension {
	header: number;
	name: string;
	length: number;
}

export interface Ipv6Fields {
	trafficClass: number;
	flowLabel: number;
	payloadLength: number;
	nextHeader: number;
	hopLimit: number;
	src: string;
	dst: string;
	/** Extension headers walked, in order (at most {@link MAX_IPV6_EXTENSIONS}). */
	extensions: Ipv6Extension[];
	/** The upper-layer protocol after the extension headers. */
	protocol: number;
	protocolName?: string;
	/** From a fragment header, in bytes. */
	fragmentOffset?: number;
	moreFragments?: boolean;
	fragmentId?: number;
}

export interface IcmpFields {
	type: number;
	code: number;
	/** A name from {@link ICMP_TYPES} or {@link ICMPV6_TYPES}, when it has one. */
	typeName?: string;
	/** The ICMP message length: header and body. */
	length: number;
	/** Echo request and reply only. */
	id?: number;
	sequence?: number;
	/** ICMPv6 neighbor solicitation and advertisement only. */
	targetAddress?: string;
}

export interface UdpFields {
	srcPort: number;
	dstPort: number;
	length: number;
	payloadLength: number;
}

export interface TcpFields {
	srcPort: number;
	dstPort: number;
	seq: number;
	ack: number;
	headerLength: number;
	/** Set flags, lowest bit first: fin, syn, rst, psh, ack, urg, ece, cwr. */
	flags: string[];
	window: number;
	urgent: number;
	payloadLength: number;
}

export interface DataFields {
	length: number;
}

interface LayerBase<P extends string, F> {
	protocol: P;
	/** Where the layer starts in the frame. */
	offset: number;
	/** Its span: header and everything it carries, within its parent's span. */
	length: number;
	/** Absent only when the header itself is cut short or unreadable. */
	fields?: F;
	problem?: DissectProblem;
	/** Which check set `problem` (`header`, `total-length`, `version` …). */
	reason?: string;
}

export type EthernetLayer = LayerBase<"ethernet", EthernetFields>;
export type VlanLayer = LayerBase<"vlan", VlanFields>;
export type ArpLayer = LayerBase<"arp", ArpFields>;
export type Ipv4Layer = LayerBase<"ipv4", Ipv4Fields>;
export type Ipv6Layer = LayerBase<"ipv6", Ipv6Fields>;
export type IcmpLayer = LayerBase<"icmp" | "icmpv6", IcmpFields>;
export type UdpLayer = LayerBase<"udp", UdpFields>;
export type TcpLayer = LayerBase<"tcp", TcpFields>;
/** Bytes no dissector here reads: an application payload, a later IP fragment, an unknown EtherType. */
export type DataLayer = LayerBase<"data", DataFields>;

export type Layer =
	| EthernetLayer
	| VlanLayer
	| ArpLayer
	| Ipv4Layer
	| Ipv6Layer
	| IcmpLayer
	| UdpLayer
	| TcpLayer
	| DataLayer;

export interface Dissection {
	/** The input frame itself, not a copy. */
	frame: Uint8Array;
	layers: Layer[];
	/** `layers` protocols in order, such as `["ethernet", "ipv4", "icmp"]`. */
	protocols: string[];
	/** The first layer that has a problem, if any. */
	problem?: { protocol: string; problem: DissectProblem; reason: string };
}

/** The most VLAN tags read from one frame; one more is `unsupported`. */
export const MAX_VLAN_TAGS = 4;
/** The most IPv6 extension headers walked; one more is `unsupported`. */
export const MAX_IPV6_EXTENSIONS = 8;

/**
 * IP protocol numbers with names, from IANA "Assigned Internet Protocol
 * Numbers". Only those a RouterOS capture is likely to show.
 */
export const IP_PROTOCOLS: Record<number, string> = {
	1: "icmp",
	2: "igmp",
	4: "ipip",
	6: "tcp",
	17: "udp",
	41: "ipv6",
	47: "gre",
	50: "esp",
	51: "ah",
	58: "icmpv6",
	89: "ospf",
	103: "pim",
	112: "vrrp",
	132: "sctp",
};

/** ICMP types (IANA "ICMP Type Numbers"). */
export const ICMP_TYPES: Record<number, string> = {
	0: "echo-reply",
	3: "unreachable",
	5: "redirect",
	8: "echo-request",
	9: "router-advertisement",
	10: "router-solicitation",
	11: "time-exceeded",
	12: "parameter-problem",
	13: "timestamp",
	14: "timestamp-reply",
};

/** ICMPv6 types (IANA "ICMPv6 Parameters", RFC 4443 and RFC 4861). */
export const ICMPV6_TYPES: Record<number, string> = {
	1: "unreachable",
	2: "packet-too-big",
	3: "time-exceeded",
	4: "parameter-problem",
	128: "echo-request",
	129: "echo-reply",
	130: "mld-query",
	131: "mld-report",
	132: "mld-done",
	133: "router-solicitation",
	134: "router-advertisement",
	135: "neighbor-solicitation",
	136: "neighbor-advertisement",
	137: "redirect",
	143: "mldv2-report",
};

/**
 * The shortest message of each ICMP type decoded here, in bytes: the 8-byte
 * header of echo and the error messages, and the fixed fields of timestamps
 * (RFC 792). Any other type needs the 4-byte common header only.
 */
const ICMP_MINIMUM: Record<number, number> = {
	0: 8,
	3: 8,
	4: 8,
	5: 8,
	8: 8,
	11: 8,
	12: 8,
	13: 20,
	14: 20,
};

/** As {@link ICMP_MINIMUM}, for ICMPv6 (RFC 4443, and RFC 4861 for neighbor discovery). */
const ICMPV6_MINIMUM: Record<number, number> = {
	1: 8,
	2: 8,
	3: 8,
	4: 8,
	128: 8,
	129: 8,
	133: 8,
	134: 16,
	135: 24,
	136: 24,
	137: 40,
};

/** IPv6 extension headers walked (IANA "IPv6 Extension Header Types"). */
const IPV6_EXTENSIONS: Record<number, string> = {
	0: "hop-by-hop",
	43: "routing",
	44: "fragment",
	51: "ah",
	60: "destination-options",
};

const ARP_OPERATIONS: Record<number, string> = {
	1: "request",
	2: "reply",
	3: "rarp-request",
	4: "rarp-reply",
};

const TCP_FLAGS = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"];

// Readers: callers check bounds first, so `?? 0` never applies in practice;
// it keeps a missed check from becoming a throw.
const u8 = (b: Uint8Array, o: number) => b[o] ?? 0;
const u16 = (b: Uint8Array, o: number) => (u8(b, o) << 8) | u8(b, o + 1);
const u32 = (b: Uint8Array, o: number) =>
	((u16(b, o) << 16) | u16(b, o + 2)) >>> 0;
const hex = (b: Uint8Array, start: number, end: number) => {
	let s = "";
	for (let i = start; i < end; i++) s += u8(b, i).toString(16).padStart(2, "0");
	return s;
};

export const hex16 = (n: number) => `0x${n.toString(16).padStart(4, "0")}`;

export const formatMac = (b: Uint8Array, o = 0) => {
	const parts: string[] = [];
	for (let i = 0; i < 6; i++)
		parts.push(
			u8(b, o + i)
				.toString(16)
				.padStart(2, "0"),
		);
	return parts.join(":");
};

export const formatIpv4 = (b: Uint8Array, o = 0) =>
	`${u8(b, o)}.${u8(b, o + 1)}.${u8(b, o + 2)}.${u8(b, o + 3)}`;

/**
 * An IPv6 address in RFC 5952 form: lowercase, no leading zeros, the longest
 * run of two or more zero groups (the first, on a tie) as `::`, and an
 * IPv4-mapped address with its last 32 bits dotted.
 */
export const formatIpv6 = (b: Uint8Array, o = 0) => {
	const groups: number[] = [];
	for (let i = 0; i < 8; i++) groups.push(u16(b, o + i * 2));
	if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
		return `::ffff:${formatIpv4(b, o + 12)}`;
	}
	let bestStart = -1;
	let bestLength = 1;
	for (let i = 0; i < 8; ) {
		if (groups[i] !== 0) {
			i++;
			continue;
		}
		let j = i;
		while (j < 8 && groups[j] === 0) j++;
		if (j - i > bestLength) {
			bestStart = i;
			bestLength = j - i;
		}
		i = j;
	}
	const text = (gs: number[]) => gs.map((g) => g.toString(16)).join(":");
	if (bestStart < 0) return text(groups);
	return `${text(groups.slice(0, bestStart))}::${text(groups.slice(bestStart + bestLength))}`;
};

/** Upper-layer context an IP layer passes down. */
interface IpContext {
	version: 4 | 6;
	/** The packet is a first fragment: a transport length past its end is expected. */
	fragment: boolean;
	/** Where the IP header says its payload ends, which may be past the captured bytes. */
	declaredEnd: number;
	/** The capture ended before that point (an IP layer marked `truncated`). */
	cut: boolean;
}

class Dissector {
	readonly layers: Layer[] = [];

	readonly b: Uint8Array;

	constructor(b: Uint8Array) {
		this.b = b;
	}

	/** Bytes no dissector reads, as a `data` layer, when there are any. */
	data(start: number, end: number) {
		if (end > start) {
			this.layers.push({
				protocol: "data",
				offset: start,
				length: end - start,
				fields: { length: end - start },
			});
		}
	}

	// IEEE 802.3: destination, source, type/length.
	ethernet(start: number, end: number) {
		const b = this.b;
		if (end - start < 14) {
			this.layers.push({
				protocol: "ethernet",
				offset: start,
				length: end - start,
				problem: "truncated",
				reason: "header",
			});
			return;
		}
		const layer: EthernetLayer = {
			protocol: "ethernet",
			offset: start,
			length: end - start,
			fields: { dst: formatMac(b, start), src: formatMac(b, start + 6) },
		};
		this.layers.push(layer);
		this.typeLength(layer, u16(b, start + 12), start + 14, end, 0);
	}

	/**
	 * What follows a type/length field, in Ethernet or a VLAN tag (IEEE 802.3,
	 * 3.2.6): 0x0600 and up is an EtherType to dispatch on; 1500 and below is
	 * the length of the LLC data that follows, which bounds it (padding after it
	 * is not LLC's); 1501 to 1535 is neither.
	 */
	typeLength(
		layer: EthernetLayer | VlanLayer,
		value: number,
		start: number,
		end: number,
		vlans: number,
	) {
		const fields = layer.fields as { etherType?: string; length?: number };
		if (value <= 1500) {
			fields.length = value;
			if (start + value > end) {
				layer.problem = "truncated";
				layer.reason = "length";
				this.data(start, end);
			} else {
				this.data(start, start + value);
			}
			return;
		}
		if (value < 0x0600) {
			// Neither a length nor an EtherType: no field claims to be either.
			layer.problem = "malformed";
			layer.reason = "type-length";
			return;
		}
		fields.etherType = hex16(value);
		this.etherPayload(start, end, value, vlans);
	}

	etherPayload(start: number, end: number, type: number, vlans: number) {
		switch (type) {
			case 0x8100: // IEEE 802.1Q
			case 0x88a8: // IEEE 802.1ad (QinQ outer tag)
				this.vlan(start, end, vlans);
				return;
			case 0x0800:
				this.ipv4(start, end);
				return;
			case 0x86dd:
				this.ipv6(start, end);
				return;
			case 0x0806:
				this.arp(start, end);
				return;
			default:
				this.data(start, end);
		}
	}

	// IEEE 802.1Q tag after the outer EtherType: TCI (PCP 3, DEI 1, VID 12), inner type.
	vlan(start: number, end: number, vlans: number) {
		if (vlans >= MAX_VLAN_TAGS) {
			this.layers.push({
				protocol: "vlan",
				offset: start,
				length: end - start,
				problem: "unsupported",
				reason: "tag-limit",
			});
			return;
		}
		if (end - start < 4) {
			this.layers.push({
				protocol: "vlan",
				offset: start,
				length: end - start,
				problem: "truncated",
				reason: "header",
			});
			return;
		}
		const tci = u16(this.b, start);
		const layer: VlanLayer = {
			protocol: "vlan",
			offset: start,
			length: end - start,
			fields: {
				priority: tci >> 13,
				dei: (tci & 0x1000) !== 0,
				id: tci & 0x0fff,
			},
		};
		this.layers.push(layer);
		this.typeLength(layer, u16(this.b, start + 2), start + 4, end, vlans + 1);
	}

	// RFC 826. Addresses are decoded for Ethernet (1) and IPv4 (0x0800) only.
	arp(start: number, end: number) {
		const b = this.b;
		if (end - start < 8) {
			this.layers.push({
				protocol: "arp",
				offset: start,
				length: end - start,
				problem: "truncated",
				reason: "header",
			});
			return;
		}
		const hardwareType = u16(b, start);
		const protocolType = u16(b, start + 2);
		const hlen = u8(b, start + 4);
		const plen = u8(b, start + 5);
		const operation = u16(b, start + 6);
		const fields: ArpFields = {
			hardwareType,
			protocolType: hex16(protocolType),
			operation,
			operationName: ARP_OPERATIONS[operation] ?? `op-${operation}`,
		};
		const length = 8 + 2 * hlen + 2 * plen;
		if (
			hardwareType === 1 &&
			protocolType === 0x0800 &&
			(hlen !== 6 || plen !== 4)
		) {
			// Ethernet and IPv4 addresses with any other length contradict the
			// types, whatever was captured after them.
			this.layers.push({
				protocol: "arp",
				offset: start,
				length: Math.min(length, end - start),
				fields,
				problem: "malformed",
				reason: "address-length",
			});
			return;
		}
		if (end - start < length) {
			this.layers.push({
				protocol: "arp",
				offset: start,
				length: end - start,
				fields,
				problem: "truncated",
				reason: "addresses",
			});
			return;
		}
		if (hardwareType !== 1 || protocolType !== 0x0800) {
			this.layers.push({
				protocol: "arp",
				offset: start,
				length,
				fields,
				problem: "unsupported",
				reason: "address-type",
			});
			return;
		}
		fields.senderMac = formatMac(b, start + 8);
		fields.senderIp = formatIpv4(b, start + 14);
		fields.targetMac = formatMac(b, start + 18);
		fields.targetIp = formatIpv4(b, start + 24);
		// The span is the ARP packet; Ethernet padding after it is not ARP's.
		this.layers.push({ protocol: "arp", offset: start, length, fields });
	}

	// RFC 791.
	ipv4(start: number, end: number) {
		const b = this.b;
		const available = end - start;
		const cut = (problem: DissectProblem, reason: string) => {
			this.layers.push({
				protocol: "ipv4",
				offset: start,
				length: available,
				problem,
				reason,
			});
		};
		if (available < 20) return cut("truncated", "header");
		if (u8(b, start) >> 4 !== 4) return cut("malformed", "version");
		const headerLength = (u8(b, start) & 0x0f) * 4;
		if (headerLength < 20) return cut("malformed", "header-length");
		const totalLength = u16(b, start + 2);
		const flagsOffset = u16(b, start + 6);
		const protocol = u8(b, start + 9);
		const fields: Ipv4Fields = {
			headerLength,
			dscp: u8(b, start + 1) >> 2,
			ecn: u8(b, start + 1) & 0x03,
			totalLength,
			id: u16(b, start + 4),
			dontFragment: (flagsOffset & 0x4000) !== 0,
			moreFragments: (flagsOffset & 0x2000) !== 0,
			fragmentOffset: (flagsOffset & 0x1fff) * 8,
			ttl: u8(b, start + 8),
			protocol,
			src: formatIpv4(b, start + 12),
			dst: formatIpv4(b, start + 16),
		};
		const protocolName = IP_PROTOCOLS[protocol];
		if (protocolName) fields.protocolName = protocolName;
		const layer: Ipv4Layer = {
			protocol: "ipv4",
			offset: start,
			length: available,
			fields,
		};
		this.layers.push(layer);
		// A total length shorter than the header contradicts it, however many
		// bytes were captured; that is known from the first 20 bytes.
		if (totalLength < headerLength) {
			layer.problem = "malformed";
			layer.reason = "total-length";
			return;
		}
		if (headerLength > available) {
			layer.problem = "truncated";
			layer.reason = "header";
			return;
		}
		if (headerLength > 20)
			fields.options = hex(b, start + 20, start + headerLength);
		if (totalLength > available) {
			layer.problem = "truncated";
			layer.reason = "total-length";
		} else {
			layer.length = totalLength;
		}
		// Every fragment but the last carries a multiple of 8 bytes (RFC 791,
		// "Fragmentation and Reassembly"). Marked, and the payload still read.
		if (fields.moreFragments && (totalLength - headerLength) % 8 !== 0) {
			layer.problem ??= "malformed";
			layer.reason ??= "fragment-length";
		}
		const payloadEnd = start + layer.length;
		if (fields.fragmentOffset > 0) {
			this.data(start + headerLength, payloadEnd);
			return;
		}
		this.ipPayload(start + headerLength, payloadEnd, protocol, {
			version: 4,
			fragment: fields.moreFragments,
			declaredEnd: start + totalLength,
			cut: totalLength > available,
		});
	}

	// RFC 8200, with extension headers capped at MAX_IPV6_EXTENSIONS.
	ipv6(start: number, end: number) {
		const b = this.b;
		const available = end - start;
		if (available < 40 || u8(b, start) >> 4 !== 6) {
			this.layers.push({
				protocol: "ipv6",
				offset: start,
				length: available,
				problem: available < 40 ? "truncated" : "malformed",
				reason: available < 40 ? "header" : "version",
			});
			return;
		}
		const payloadLength = u16(b, start + 4);
		const nextHeader = u8(b, start + 6);
		const fields: Ipv6Fields = {
			trafficClass: ((u8(b, start) & 0x0f) << 4) | (u8(b, start + 1) >> 4),
			flowLabel: ((u8(b, start + 1) & 0x0f) << 16) | u16(b, start + 2),
			payloadLength,
			nextHeader,
			hopLimit: u8(b, start + 7),
			src: formatIpv6(b, start + 8),
			dst: formatIpv6(b, start + 24),
			extensions: [],
			protocol: nextHeader,
		};
		const layer: Ipv6Layer = {
			protocol: "ipv6",
			offset: start,
			length: available,
			fields,
		};
		this.layers.push(layer);
		if (40 + payloadLength > available) {
			layer.problem = "truncated";
			layer.reason = "payload-length";
		} else {
			layer.length = 40 + payloadLength;
		}
		const payloadEnd = start + layer.length;
		const declaredEnd = start + 40 + payloadLength;
		let offset = start + 40;
		let protocol = nextHeader;
		for (
			let name = IPV6_EXTENSIONS[protocol];
			name;
			name = IPV6_EXTENSIONS[protocol]
		) {
			if (fields.extensions.length === MAX_IPV6_EXTENSIONS) {
				fields.protocol = protocol;
				layer.problem ??= "unsupported";
				layer.reason ??= "extension-limit";
				return;
			}
			const left = payloadEnd - offset;
			let length = 8;
			if (protocol === 51 && left >= 2) {
				length = (u8(b, offset + 1) + 2) * 4;
				// AH has 12 fixed bytes, and in IPv6 its length is a multiple of 8
				// (RFC 4302, 2.2).
				if (length < 12 || length % 8 !== 0) {
					fields.protocol = protocol;
					layer.problem = "malformed";
					layer.reason = "ah-length";
					return;
				}
			} else if (protocol !== 44 && left >= 2) {
				length = (u8(b, offset + 1) + 1) * 8;
			}
			if (offset + length > declaredEnd) {
				// Longer than the payload the IPv6 header declares: a contradiction.
				fields.protocol = protocol;
				layer.problem = "malformed";
				layer.reason = "extension-header";
				return;
			}
			if (length > left) {
				// Within the declared payload, but the capture ends first.
				fields.protocol = protocol;
				layer.problem = "truncated";
				layer.reason = "extension-header";
				return;
			}
			if (protocol === 44) {
				const offsetFlags = u16(b, offset + 2);
				// The offset is the top 13 bits, in 8-byte units, so clearing the
				// low 3 bits (reserved, M) leaves it in bytes (RFC 8200, 4.5).
				fields.fragmentOffset = offsetFlags & 0xfff8;
				fields.moreFragments = (offsetFlags & 1) !== 0;
				fields.fragmentId = u32(b, offset + 4);
				// Every fragment but the last carries a multiple of 8 bytes after
				// the fragment header (RFC 8200, 4.5). Marked, and still read.
				if (fields.moreFragments && (declaredEnd - offset - 8) % 8 !== 0) {
					layer.problem ??= "malformed";
					layer.reason ??= "fragment-length";
				}
			}
			fields.extensions.push({ header: protocol, name, length });
			protocol = u8(b, offset);
			offset += length;
			// After the fragment header of a later fragment, the bytes are that
			// fragment's data, not further headers (RFC 8200, 4.5).
			if ((fields.fragmentOffset ?? 0) > 0) break;
		}
		fields.protocol = protocol;
		const protocolName = IP_PROTOCOLS[protocol];
		if (protocolName) fields.protocolName = protocolName;
		if ((fields.fragmentOffset ?? 0) > 0) {
			this.data(offset, payloadEnd);
			return;
		}
		this.ipPayload(offset, payloadEnd, protocol, {
			version: 6,
			fragment: fields.moreFragments ?? false,
			declaredEnd,
			cut: declaredEnd > end,
		});
	}

	ipPayload(start: number, end: number, protocol: number, ip: IpContext) {
		switch (protocol) {
			case 1:
				this.icmp(start, end, "icmp", ip);
				return;
			case 58:
				this.icmp(start, end, "icmpv6", ip);
				return;
			case 6:
				this.tcp(start, end, ip);
				return;
			case 17:
				this.udp(start, end, ip);
				return;
			default:
				this.data(start, end);
		}
	}

	// RFC 792 and RFC 4443: type, code, checksum, then a body that depends on the type.
	icmp(start: number, end: number, protocol: "icmp" | "icmpv6", ip: IpContext) {
		const b = this.b;
		const length = end - start;
		if (length < 4) {
			this.layers.push({
				protocol,
				offset: start,
				length,
				problem: "truncated",
				reason: "header",
			});
			return;
		}
		const type = u8(b, start);
		const fields: IcmpFields = { type, code: u8(b, start + 1), length };
		const typeName = (protocol === "icmp" ? ICMP_TYPES : ICMPV6_TYPES)[type];
		if (typeName) fields.typeName = typeName;
		const layer: IcmpLayer = { protocol, offset: start, length, fields };
		this.layers.push(layer);
		const minimum =
			(protocol === "icmp" ? ICMP_MINIMUM : ICMPV6_MINIMUM)[type] ?? 4;
		if (length < minimum) {
			// A whole IPv4 first fragment: the message goes on in the next one.
			// IPv6 puts the whole upper-layer header in the first fragment
			// (RFC 8200, 4.5), so there a short message is checked as usual.
			if (ip.version === 4 && ip.fragment && !ip.cut) return;
			layer.problem = "truncated";
			layer.reason = "message";
			return;
		}
		const echo =
			protocol === "icmp"
				? type === 0 || type === 8
				: type === 128 || type === 129;
		if (echo) {
			fields.id = u16(b, start + 4);
			fields.sequence = u16(b, start + 6);
		}
		if (protocol === "icmpv6" && (type === 135 || type === 136)) {
			fields.targetAddress = formatIpv6(b, start + 8);
		}
	}

	// RFC 768.
	udp(start: number, end: number, ip: IpContext) {
		const b = this.b;
		const available = end - start;
		if (available < 8) {
			// Fewer than 8 bytes declared contradicts the header; more declared
			// than captured means the capture ended early.
			this.layers.push({
				protocol: "udp",
				offset: start,
				length: available,
				problem: ip.declaredEnd - start < 8 ? "malformed" : "truncated",
				reason: "header",
			});
			return;
		}
		const length = u16(b, start + 4);
		const fields: UdpFields = {
			srcPort: u16(b, start),
			dstPort: u16(b, start + 2),
			length,
			payloadLength: 0,
		};
		const layer: UdpLayer = {
			protocol: "udp",
			offset: start,
			length: available,
			fields,
		};
		this.layers.push(layer);
		if (length < 8) {
			layer.problem = "malformed";
			layer.reason = "length";
			return;
		}
		if (length <= available) layer.length = length;
		// The first fragment of a datagram holds only part of what `length` counts.
		else if (!ip.fragment) {
			// Past what the IP header declares: a contradiction. Within it, the
			// capture ended early.
			layer.problem =
				start + length > ip.declaredEnd ? "malformed" : "truncated";
			layer.reason = "length";
		}
		fields.payloadLength = layer.length - 8;
		this.data(start + 8, start + layer.length);
	}

	// RFC 9293.
	tcp(start: number, end: number, ip: IpContext) {
		const b = this.b;
		const available = end - start;
		// IPv4 lets a first fragment end inside the TCP header, which goes on
		// in the next fragment: fragment data, not a cut capture. IPv6 does not:
		// its first fragment holds the whole upper-layer header (RFC 8200,
		// 4.5), so there a short header is checked below like any other.
		const splitAllowed = ip.version === 4 && ip.fragment;
		const splitHeader =
			splitAllowed &&
			!ip.cut &&
			(available < 20 || (u8(b, start + 12) >> 4) * 4 > available);
		if (splitHeader) {
			this.data(start, end);
			return;
		}
		/** A header past what the IP header declares contradicts it; within it, the capture ended. */
		const short = (headerEnd: number): DissectProblem =>
			!splitAllowed && headerEnd > ip.declaredEnd ? "malformed" : "truncated";
		if (available < 20) {
			this.layers.push({
				protocol: "tcp",
				offset: start,
				length: available,
				problem: short(start + 20),
				reason: "header",
			});
			return;
		}
		const headerLength = (u8(b, start + 12) >> 4) * 4;
		const flagBits = u8(b, start + 13);
		const fields: TcpFields = {
			srcPort: u16(b, start),
			dstPort: u16(b, start + 2),
			seq: u32(b, start + 4),
			ack: u32(b, start + 8),
			headerLength,
			flags: TCP_FLAGS.filter((_, bit) => (flagBits & (1 << bit)) !== 0),
			window: u16(b, start + 14),
			urgent: u16(b, start + 18),
			payloadLength: 0,
		};
		const layer: TcpLayer = {
			protocol: "tcp",
			offset: start,
			length: available,
			fields,
		};
		this.layers.push(layer);
		if (headerLength < 20) {
			layer.problem = "malformed";
			layer.reason = "header-length";
			return;
		}
		if (headerLength > available) {
			layer.problem = short(start + headerLength);
			layer.reason = "header";
			return;
		}
		fields.payloadLength = available - headerLength;
		this.data(start + headerLength, end);
	}
}

/**
 * Dissect one Ethernet frame (the `payload` of a TZSP `packet` record). Never
 * throws: what it cannot read is marked on the layer where it stopped.
 */
export function dissect(frame: Uint8Array): Dissection {
	const d = new Dissector(frame);
	d.ethernet(0, frame.length);
	const result: Dissection = {
		frame,
		layers: d.layers,
		protocols: d.layers.map((l) => l.protocol),
	};
	const first = d.layers.find((l) => l.problem);
	if (first?.problem) {
		result.problem = {
			protocol: first.protocol,
			problem: first.problem,
			reason: first.reason ?? first.problem,
		};
	}
	return result;
}
