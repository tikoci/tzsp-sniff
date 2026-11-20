// cspell:ignore DSCP ECN
import {
	type DissectProblem,
	type FieldDecls,
	type Frame,
	fieldInfo,
	formatIpv4,
	hex,
	IP_PROTOCOLS,
	type LayerBase,
	type Registration,
	u8,
	u16,
} from "./core.ts";

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

export type Ipv4Layer = LayerBase<"ipv4", Ipv4Fields>;

// RFC 791.
function ipv4(f: Frame, start: number, end: number) {
	const b = f.b;
	const available = end - start;
	const cut = (problem: DissectProblem, reason: string) => {
		f.layers.push({
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
	f.layers.push(layer);
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
		f.data(start + headerLength, payloadEnd);
		return;
	}
	f.ipPayload(start + headerLength, payloadEnd, protocol, {
		version: 4,
		fragment: fields.moreFragments,
		declaredEnd: start + totalLength,
		cut: totalLength > available,
	});
}

const FIELDS: FieldDecls<Ipv4Fields> = {
	headerLength: { type: "number", description: "Header length, in bytes." },
	dscp: { type: "number", description: "Differentiated services code point." },
	ecn: {
		type: "number",
		description: "Explicit congestion notification bits.",
	},
	totalLength: {
		type: "number",
		description: "Total length the header declares, header and payload.",
	},
	id: { type: "number", description: "Identification, shared by fragments." },
	dontFragment: { type: "boolean", description: "The DF flag." },
	moreFragments: { type: "boolean", description: "The MF flag." },
	fragmentOffset: {
		type: "number",
		description: "Fragment offset, in bytes (the header field times 8).",
	},
	ttl: { type: "number", description: "Time to live." },
	protocol: {
		type: "number",
		description: "The payload's IP protocol number.",
	},
	protocolName: {
		type: "string",
		optional: true,
		description: "The IP protocol's name (tcp, udp, ospf …), when it has one.",
	},
	src: { type: "string", description: "Source address." },
	dst: { type: "string", description: "Destination address." },
	options: {
		type: "string",
		optional: true,
		description:
			"Header options, as hex, when the header is longer than 20 bytes.",
	},
};

export const IPV4: Registration = {
	protocol: "ipv4",
	name: "IPv4",
	reference: "RFC 791",
	matches: [{ etherType: 0x0800, dissect: ipv4 }],
	fields: fieldInfo(FIELDS),
};
