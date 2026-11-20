// cspell:ignore RARP
import {
	type FieldDecls,
	type Frame,
	fieldInfo,
	formatIpv4,
	formatMac,
	hex16,
	type LayerBase,
	type Registration,
	u8,
	u16,
} from "./core.ts";

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

export type ArpLayer = LayerBase<"arp", ArpFields>;

const ARP_OPERATIONS: Record<number, string> = {
	1: "request",
	2: "reply",
	3: "rarp-request",
	4: "rarp-reply",
};

// RFC 826. Addresses are decoded for Ethernet (1) and IPv4 (0x0800) only.
function arp(f: Frame, start: number, end: number) {
	const b = f.b;
	if (end - start < 8) {
		f.layers.push({
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
		f.layers.push({
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
		f.layers.push({
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
		f.layers.push({
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
	f.layers.push({ protocol: "arp", offset: start, length, fields });
}

const ADDRESS =
	"Present for Ethernet and IPv4 addresses, the only kind decoded.";
const FIELDS: FieldDecls<ArpFields> = {
	hardwareType: {
		type: "number",
		description: "Hardware type: 1 is Ethernet.",
	},
	protocolType: {
		type: "string",
		description: "Protocol type, as an EtherType such as 0x0800.",
	},
	operation: { type: "number", description: "Operation code." },
	operationName: {
		type: "string",
		description: "request, reply, rarp-request, rarp-reply, or op-<n>.",
	},
	senderMac: {
		type: "string",
		optional: true,
		description: `Sender MAC address. ${ADDRESS}`,
	},
	senderIp: {
		type: "string",
		optional: true,
		description: `Sender IPv4 address. ${ADDRESS}`,
	},
	targetMac: {
		type: "string",
		optional: true,
		description: `Target MAC address. ${ADDRESS}`,
	},
	targetIp: {
		type: "string",
		optional: true,
		description: `Target IPv4 address. ${ADDRESS}`,
	},
};

export const ARP: Registration = {
	protocol: "arp",
	name: "ARP",
	reference: "RFC 826",
	matches: [{ etherType: 0x0806, dissect: arp }],
	fields: fieldInfo(FIELDS),
};
