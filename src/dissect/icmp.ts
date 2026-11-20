import {
	type FieldDecls,
	type Frame,
	fieldInfo,
	formatIpv6,
	type IpContext,
	type LayerBase,
	type Registration,
	u8,
	u16,
} from "./core.ts";

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

export type IcmpLayer = LayerBase<"icmp" | "icmpv6", IcmpFields>;

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

// RFC 792 and RFC 4443: type, code, checksum, then a body that depends on the type.
function icmp(
	f: Frame,
	start: number,
	end: number,
	protocol: "icmp" | "icmpv6",
	ip: IpContext,
) {
	const b = f.b;
	const length = end - start;
	if (length < 4) {
		f.layers.push({
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
	f.layers.push(layer);
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

/** ICMP's fields; ICMPv6 adds the neighbor discovery target. */
const ICMP_FIELDS: FieldDecls<Omit<IcmpFields, "targetAddress">> = {
	type: { type: "number", description: "Message type." },
	code: { type: "number", description: "Message code." },
	typeName: {
		type: "string",
		optional: true,
		description:
			"The type's name (echo-request, unreachable …), when it has one.",
	},
	length: {
		type: "number",
		description: "The message length: header and body.",
	},
	id: {
		type: "number",
		optional: true,
		description: "Echo request and reply: identifier.",
	},
	sequence: {
		type: "number",
		optional: true,
		description: "Echo request and reply: sequence number.",
	},
};

const ICMPV6_FIELDS: FieldDecls<IcmpFields> = {
	...ICMP_FIELDS,
	targetAddress: {
		type: "string",
		optional: true,
		description: "Neighbor solicitation and advertisement: the target address.",
	},
};

export const ICMP: Registration = {
	protocol: "icmp",
	name: "ICMP",
	reference: "RFC 792",
	matches: [
		{
			ipProtocol: 1,
			dissect: (f: Frame, start: number, end: number, ip: IpContext) =>
				icmp(f, start, end, "icmp", ip),
		},
	],
	fields: fieldInfo(ICMP_FIELDS),
};

export const ICMPV6: Registration = {
	protocol: "icmpv6",
	name: "ICMPv6",
	reference: "RFC 4443, RFC 4861",
	matches: [
		{
			ipProtocol: 58,
			dissect: (f: Frame, start: number, end: number, ip: IpContext) =>
				icmp(f, start, end, "icmpv6", ip),
		},
	],
	fields: fieldInfo(ICMPV6_FIELDS),
};
