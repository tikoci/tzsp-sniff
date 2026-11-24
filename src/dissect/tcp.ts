import {
	type DissectProblem,
	type FieldDecls,
	type Frame,
	fieldInfo,
	type IpContext,
	type LayerBase,
	type Registration,
	u8,
	u16,
	u32,
} from "./core.ts";

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

export type TcpLayer = LayerBase<"tcp", TcpFields>;

const TCP_FLAGS = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"];

// RFC 9293.
function tcp(f: Frame, start: number, end: number, ip: IpContext) {
	const b = f.b;
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
		f.data(start, end);
		return;
	}
	/** A header past what the IP header declares contradicts it; within it, the capture ended. */
	const short = (headerEnd: number): DissectProblem =>
		!splitAllowed && headerEnd > ip.declaredEnd ? "malformed" : "truncated";
	if (available < 20) {
		f.layers.push({
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
	f.layers.push(layer);
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
	f.portPayload(
		"tcp",
		start + headerLength,
		end,
		[fields.srcPort, fields.dstPort],
		ip,
		!ip.cut,
	);
}

const FIELDS: FieldDecls<TcpFields> = {
	srcPort: { type: "number", description: "Source port." },
	dstPort: { type: "number", description: "Destination port." },
	seq: { type: "number", description: "Sequence number." },
	ack: { type: "number", description: "Acknowledgment number." },
	headerLength: { type: "number", description: "Header length, in bytes." },
	flags: {
		type: "string[]",
		description: `Set flags, lowest bit first: ${TCP_FLAGS.join(", ")}.`,
	},
	window: { type: "number", description: "Window size." },
	urgent: { type: "number", description: "Urgent pointer." },
	payloadLength: {
		type: "number",
		description: "Payload bytes in this segment.",
	},
};

export const TCP: Registration = {
	protocol: "tcp",
	name: "TCP",
	reference: "RFC 9293",
	matches: [{ ipProtocol: 6, dissect: tcp }],
	fields: fieldInfo(FIELDS),
};
