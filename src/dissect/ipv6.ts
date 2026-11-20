import {
	type FieldDecls,
	type Frame,
	fieldInfo,
	formatIpv6,
	IP_PROTOCOLS,
	type LayerBase,
	type Registration,
	u8,
	u16,
	u32,
} from "./core.ts";

/** The most IPv6 extension headers walked; one more is `unsupported`. */
export const MAX_IPV6_EXTENSIONS = 8;

/** IPv6 extension headers walked (IANA "IPv6 Extension Header Types"). */
const IPV6_EXTENSIONS: Record<number, string> = {
	0: "hop-by-hop",
	43: "routing",
	44: "fragment",
	51: "ah",
	60: "destination-options",
};

export interface Ipv6Extension {
	/** Its own type, the next-header value that named it (0 for hop-by-hop). */
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
	/**
	 * The last next-header value reached: the upper-layer protocol, 59 when
	 * no next header follows, or an extension header's type when the walk
	 * stopped there (a problem, or a later fragment, whose fragment header's
	 * next header is given).
	 */
	protocol: number;
	protocolName?: string;
	/** From a fragment header, in bytes. */
	fragmentOffset?: number;
	moreFragments?: boolean;
	fragmentId?: number;
}

export type Ipv6Layer = LayerBase<"ipv6", Ipv6Fields>;

// RFC 8200, with extension headers capped at MAX_IPV6_EXTENSIONS.
function ipv6(f: Frame, start: number, end: number) {
	const b = f.b;
	const available = end - start;
	if (available < 40 || u8(b, start) >> 4 !== 6) {
		f.layers.push({
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
	f.layers.push(layer);
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
		f.data(offset, payloadEnd);
		return;
	}
	f.ipPayload(offset, payloadEnd, protocol, {
		version: 6,
		fragment: fields.moreFragments ?? false,
		declaredEnd,
		cut: declaredEnd > end,
	});
}

const FIELDS: FieldDecls<Ipv6Fields> = {
	trafficClass: { type: "number", description: "Traffic class." },
	flowLabel: { type: "number", description: "Flow label." },
	payloadLength: {
		type: "number",
		description:
			"Payload length the header declares, extension headers included.",
	},
	nextHeader: {
		type: "number",
		description: "The fixed header's next header.",
	},
	hopLimit: { type: "number", description: "Hop limit." },
	src: { type: "string", description: "Source address." },
	dst: { type: "string", description: "Destination address." },
	extensions: {
		type: "object[]",
		description: `Extension headers walked, in order (at most ${MAX_IPV6_EXTENSIONS}).`,
		items: {
			header: {
				type: "number",
				description:
					"Its own type: the next-header value that named it, such as 0 for hop-by-hop.",
			},
			name: {
				type: "string",
				description:
					"hop-by-hop, routing, fragment, ah or destination-options.",
			},
			length: { type: "number", description: "Its length, in bytes." },
		},
	},
	protocol: {
		type: "number",
		description:
			"The last next-header value reached: the upper-layer protocol, 59 when no next header follows, or an extension header's type when the walk stopped there (a problem, or a later fragment, whose fragment header's next header is given).",
	},
	protocolName: {
		type: "string",
		optional: true,
		description:
			"protocol's name, when it has one; absent when the walk stopped at a problem.",
	},
	fragmentOffset: {
		type: "number",
		optional: true,
		description: "From a fragment header: the offset, in bytes.",
	},
	moreFragments: {
		type: "boolean",
		optional: true,
		description: "From a fragment header: the M flag.",
	},
	fragmentId: {
		type: "number",
		optional: true,
		description: "From a fragment header: the identification.",
	},
};

export const IPV6: Registration = {
	protocol: "ipv6",
	name: "IPv6",
	reference: "RFC 8200",
	matches: [{ etherType: 0x86dd, dissect: ipv6 }],
	fields: fieldInfo(FIELDS),
};
