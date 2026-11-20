import {
	type FieldDecls,
	type Frame,
	fieldInfo,
	type IpContext,
	type LayerBase,
	type Registration,
	u16,
} from "./core.ts";

export interface UdpFields {
	srcPort: number;
	dstPort: number;
	length: number;
	payloadLength: number;
}

export type UdpLayer = LayerBase<"udp", UdpFields>;

// RFC 768.
function udp(f: Frame, start: number, end: number, ip: IpContext) {
	const b = f.b;
	const available = end - start;
	if (available < 8) {
		// Fewer than 8 bytes declared contradicts the header; more declared
		// than captured means the capture ended early.
		f.layers.push({
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
	f.layers.push(layer);
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
		layer.problem = start + length > ip.declaredEnd ? "malformed" : "truncated";
		layer.reason = "length";
	}
	fields.payloadLength = layer.length - 8;
	f.data(start + 8, start + layer.length);
}

const FIELDS: FieldDecls<UdpFields> = {
	srcPort: { type: "number", description: "Source port." },
	dstPort: { type: "number", description: "Destination port." },
	length: {
		type: "number",
		description: "Length the header declares, header included.",
	},
	payloadLength: {
		type: "number",
		description: "Payload bytes in this packet.",
	},
};

export const UDP: Registration = {
	protocol: "udp",
	name: "UDP",
	reference: "RFC 768",
	matches: [{ ipProtocol: 17, dissect: udp }],
	fields: fieldInfo(FIELDS),
};
