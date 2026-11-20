/**
 * LLDP (IEEE 802.1AB), on EtherType 0x88cc: the LLDPDU's TLVs, the basic
 * ones decoded into named fields and the rest kept as type, length and hex.
 *
 * TLV types, subtypes, capability bits and the organizationally specific
 * subtypes named here are from IEEE 802.1AB (clause 8), IEEE 802.1Q
 * (Annex D), IEEE 802.3 (clause 79) and ANSI/TIA-1057 (LLDP-MED), checked
 * against Wireshark's epan/dissectors/packet-lldp.c at commit ffc784d8541a
 * (numbers only; no code is used). Address families are IANA "Address
 * Family Numbers".
 */
import {
	type FieldDecls,
	type Frame,
	fieldInfo,
	formatIpv4,
	formatIpv6,
	formatMac,
	hex,
	type LayerBase,
	type Registration,
	u8,
	u16,
	u32,
} from "./core.ts";

/** The most TLVs read, End included; one more is `unsupported` (`tlv-limit`). */
export const MAX_LLDP_TLVS = 64;

export interface LldpManagementAddress {
	/** The address family (IANA "Address Family Numbers"). */
	family: number;
	/** `ipv4`, `ipv6` or `mac`, when the family is one of those. */
	familyName?: string;
	/** As text for IPv4, IPv6 and MAC, else hex. */
	address: string;
	interfaceNumbering: number;
	/** `unknown`, `ifIndex` or `system-port-number`. */
	interfaceNumberingName?: string;
	interfaceNumber: number;
	/** The object identifier, dotted, when the TLV carries one. */
	oid?: string;
}

export interface LldpOtherTlv {
	type: number;
	/** The TLV's length field: the bytes of its value. */
	length: number;
	/** The value as hex; for an organizationally specific TLV, what follows its OUI and subtype. */
	value: string;
	/** An organizationally specific TLV's OUI, as `00-12-bb`. */
	oui?: string;
	ouiName?: string;
	subtype?: number;
	subtypeName?: string;
}

export interface LldpFields {
	/** The chassis id subtype's name, such as `mac-address`, or `subtype-<n>`. */
	chassisIdSubtype?: string;
	chassisId?: string;
	portIdSubtype?: string;
	portId?: string;
	/** Seconds the information stays valid; 0 says the sender is shutting down. */
	ttl?: number;
	portDescription?: string;
	systemName?: string;
	systemDescription?: string;
	/** The capabilities the system has, by name. */
	capabilities?: string[];
	/** The capabilities enabled, by name. */
	enabledCapabilities?: string[];
	managementAddresses: LldpManagementAddress[];
	/** Every TLV not decoded above, in order, a second of a type read once among them. */
	otherTlvs: LldpOtherTlv[];
}

export type LldpLayer = LayerBase<"lldp", LldpFields>;

const CHASSIS_ID_SUBTYPES: Record<number, string> = {
	1: "chassis-component",
	2: "interface-alias",
	3: "port-component",
	4: "mac-address",
	5: "network-address",
	6: "interface-name",
	7: "locally-assigned",
};

const PORT_ID_SUBTYPES: Record<number, string> = {
	1: "interface-alias",
	2: "port-component",
	3: "mac-address",
	4: "network-address",
	5: "interface-name",
	6: "agent-circuit-id",
	7: "locally-assigned",
};

/** Subtypes whose id is an alphanumeric string (802.1AB 8.5.2, 8.5.3). */
const TEXT_SUBTYPES = new Set([
	"chassis-component",
	"interface-alias",
	"port-component",
	"interface-name",
	"locally-assigned",
]);

/** System capabilities, by bit from the least significant (802.1AB 8.5.8.1). */
const CAPABILITIES = [
	"other",
	"repeater",
	"bridge",
	"wlan-access-point",
	"router",
	"telephone",
	"docsis-cable-device",
	"station-only",
	"c-vlan-component",
	"s-vlan-component",
	"two-port-mac-relay",
];

const FAMILIES: Record<number, string> = { 1: "ipv4", 2: "ipv6", 6: "mac" };

const INTERFACE_NUMBERING: Record<number, string> = {
	1: "unknown",
	2: "ifIndex",
	3: "system-port-number",
};

const ORGANIZATIONS: Record<
	string,
	{ name: string; subtypes: Record<number, string> }
> = {
	"00-80-c2": {
		name: "ieee-802.1",
		subtypes: {
			1: "port-vlan-id",
			2: "port-and-protocol-vlan-id",
			3: "vlan-name",
			4: "protocol-identity",
			5: "vid-usage-digest",
			6: "management-vid",
			7: "link-aggregation",
		},
	},
	"00-12-0f": {
		name: "ieee-802.3",
		subtypes: {
			1: "mac-phy-config-status",
			2: "power-via-mdi",
			3: "link-aggregation",
			4: "max-frame-size",
			5: "eee",
			7: "additional-ethernet-capabilities",
		},
	},
	"00-12-bb": {
		name: "tia-lldp-med",
		subtypes: {
			1: "capabilities",
			2: "network-policy",
			3: "location-identification",
			4: "extended-power-via-mdi",
			5: "hardware-revision",
			6: "firmware-revision",
			7: "software-revision",
			8: "serial-number",
			9: "manufacturer-name",
			10: "model-name",
			11: "asset-id",
		},
	},
};

const UTF8 = new TextDecoder("utf-8", { fatal: true });
const LENIENT = new TextDecoder("utf-8");

/**
 * The bytes from `start` to `end` as a plain Uint8Array over the same
 * memory: `subarray` would build the caller's subclass, whose constructor
 * may not take what `subarray` passes.
 */
const view = (b: Uint8Array, start: number, end: number) =>
	new Uint8Array(b.buffer, b.byteOffset + start, end - start);

/** Text, or `undefined` when the bytes are not UTF-8 (the caller marks it). */
function text(b: Uint8Array, start: number, end: number): string | undefined {
	try {
		return UTF8.decode(view(b, start, end));
	} catch {
		return undefined;
	}
}

/** Address lengths by family: IPv4 4, IPv6 16, MAC 6 bytes. */
const ADDRESS_LENGTHS: Record<number, number> = { 1: 4, 2: 16, 6: 6 };

/** An address of `n` bytes fits its family: the family's length, or at least one byte for another. */
const addressFits = (family: number, n: number) =>
	n === (ADDRESS_LENGTHS[family] ?? Math.max(n, 1));

/** An address that fits its family: IPv4, IPv6 or MAC as text, any other family as hex. */
function address(
	b: Uint8Array,
	family: number,
	start: number,
	end: number,
): string {
	if (family === 1) return formatIpv4(b, start);
	if (family === 2) return formatIpv6(b, start);
	if (family === 6) return formatMac(b, start);
	return hex(b, start, end);
}

/**
 * A BER-encoded object identifier, dotted (ITU-T X.690, 8.19); `undefined`
 * when it does not parse. Arcs are BigInt: one may pass 2^53, and the OID
 * is at most 128 bytes, so the arcs stay small.
 */
function oid(b: Uint8Array, start: number, end: number): string | undefined {
	const arcs: bigint[] = [];
	let value = BigInt(0);
	let pending = false;
	for (let i = start; i < end; i++) {
		const byte = u8(b, i);
		if (!pending && byte === 0x80) return undefined; // a leading 0x80 pads
		value = value * BigInt(128) + BigInt(byte & 0x7f);
		pending = (byte & 0x80) !== 0;
		if (!pending) {
			arcs.push(value);
			value = BigInt(0);
		}
	}
	const first = arcs[0];
	if (pending || first === undefined) return undefined;
	const x = first < BigInt(40) ? 0 : first < BigInt(80) ? 1 : 2;
	return [x, first - BigInt(40 * x), ...arcs.slice(1)].join(".");
}

const names = (bits: number) =>
	[...Array(16).keys()]
		.filter((i) => (bits >> i) & 1)
		.map((i) => CAPABILITIES[i] ?? `bit-${i + 1}`);

/**
 * TLV types read once. Chassis id, port id and TTL "shall" appear exactly
 * once, so a second is `malformed` (`repeated`); the others "should not"
 * appear more than once (802.1AB-2005, each TLV's clause), so a second is
 * only kept raw (maintainer, 2026-11-20, #26).
 */
const ONCE = new Set([1, 2, 3, 4, 5, 6, 7]);
const MANDATORY = new Set([1, 2, 3]);

/** Is `length` one this TLV type can have (802.1AB 8.5)? */
function lengthFits(type: number, length: number): boolean {
	switch (type) {
		case 0:
			return length === 0;
		case 1:
		case 2:
			return length >= 2 && length <= 256;
		case 3:
			return length === 2;
		case 4:
		case 5:
		case 6:
			return length <= 255;
		case 7:
			return length === 4;
		case 8:
			return length >= 9 && length <= 167;
		case 127:
			return length >= 4;
		default:
			return true;
	}
}

// IEEE 802.1AB-2016, clause 8.
function lldp(f: Frame, start: number, end: number) {
	const b = f.b;
	const fields: LldpFields = { managementAddresses: [], otherTlvs: [] };
	const layer: LldpLayer = {
		protocol: "lldp",
		offset: start,
		length: end - start,
		fields,
	};
	f.layers.push(layer);
	const mark = (problem: "truncated" | "malformed", reason: string) => {
		layer.problem ??= problem;
		layer.reason ??= reason;
	};
	const raw = (type: number, length: number, value: number) => {
		fields.otherTlvs.push({
			type,
			length,
			value: hex(b, value, value + length),
		});
	};
	const seen = new Set<number>();
	let offset = start;
	for (let index = 0; ; index++) {
		if (end - offset < 2) {
			// The bytes ran out before End: a TLV header cut short, or none.
			mark("truncated", offset === end ? "end" : "tlv");
			return;
		}
		if (index === MAX_LLDP_TLVS) {
			layer.length = offset - start;
			layer.problem ??= "unsupported";
			layer.reason ??= "tlv-limit";
			return;
		}
		const header = u16(b, offset);
		const type = header >> 9;
		const length = header & 0x1ff;
		const value = offset + 2;
		if (value + length > end) {
			mark("truncated", "tlv");
			return;
		}
		offset = value + length;
		// Chassis id, port id and TTL come first, in that order (8.2).
		if (index < 3 && type !== index + 1) mark("malformed", "order");
		if (type === 0) {
			if (length !== 0) {
				mark("malformed", "tlv-length");
				raw(type, length, value);
			}
			// What follows End is not LLDP's, as Ethernet padding is not.
			layer.length = offset - start;
			return;
		}
		if (!lengthFits(type, length)) {
			mark("malformed", "tlv-length");
			raw(type, length, value);
			continue;
		}
		if (ONCE.has(type)) {
			if (seen.has(type)) {
				if (MANDATORY.has(type)) mark("malformed", "repeated");
				raw(type, length, value);
				continue;
			}
			seen.add(type);
		}
		switch (type) {
			case 1:
			case 2: {
				const table = type === 1 ? CHASSIS_ID_SUBTYPES : PORT_ID_SUBTYPES;
				const code = u8(b, value);
				const subtype = table[code] ?? `subtype-${code}`;
				// A MAC is 6 bytes; a network address is its family and an
				// address of that family's length (8.5.2.3, 8.5.3.3).
				const family = u8(b, value + 1);
				if (
					(subtype === "mac-address" && length !== 7) ||
					(subtype === "network-address" &&
						(length < 3 || !addressFits(family, length - 2)))
				) {
					mark("malformed", "tlv-length");
					raw(type, length, value);
					break;
				}
				let id: string;
				if (subtype === "mac-address") {
					id = formatMac(b, value + 1);
				} else if (subtype === "network-address") {
					id = address(b, family, value + 2, offset);
				} else if (TEXT_SUBTYPES.has(subtype)) {
					const t = text(b, value + 1, offset);
					if (t === undefined) mark("malformed", "text");
					id = t ?? LENIENT.decode(view(b, value + 1, offset));
				} else {
					id = hex(b, value + 1, offset);
				}
				if (type === 1) {
					fields.chassisIdSubtype = subtype;
					fields.chassisId = id;
				} else {
					fields.portIdSubtype = subtype;
					fields.portId = id;
				}
				break;
			}
			case 3:
				fields.ttl = u16(b, value);
				break;
			case 4:
			case 5:
			case 6: {
				const t = text(b, value, offset);
				if (t === undefined) mark("malformed", "text");
				const s = t ?? LENIENT.decode(view(b, value, offset));
				if (type === 4) fields.portDescription = s;
				else if (type === 5) fields.systemName = s;
				else fields.systemDescription = s;
				break;
			}
			case 7: {
				const system = u16(b, value);
				const enabled = u16(b, value + 2);
				// A capability enabled but not supported: the TLV "shall be
				// discarded" (802.1AB-2009, 8.5.8.3), so it is kept raw.
				if ((enabled & ~system) !== 0) {
					mark("malformed", "capabilities");
					raw(type, length, value);
					break;
				}
				fields.capabilities = names(system);
				fields.enabledCapabilities = names(enabled);
				break;
			}
			case 8: {
				// Address string length (subtype and address), subtype,
				// address, interface numbering, interface number, OID length,
				// OID (8.5.9).
				const addressLength = u8(b, value);
				const after = value + 1 + addressLength;
				// The OID length is read only once it lies inside the TLV.
				const oidLength = after + 6 <= offset ? u8(b, after + 5) : -1;
				if (
					addressLength < 2 ||
					addressLength > 32 ||
					!addressFits(u8(b, value + 1), addressLength - 1) ||
					oidLength < 0 ||
					oidLength > 128 ||
					after + 6 + oidLength !== offset
				) {
					mark("malformed", "tlv-length");
					raw(type, length, value);
					break;
				}
				const family = u8(b, value + 1);
				const numbering = u8(b, after);
				const entry: LldpManagementAddress = {
					family,
					address: address(b, family, value + 2, after),
					interfaceNumbering: numbering,
					interfaceNumber: u32(b, after + 1),
				};
				const familyName = FAMILIES[family];
				if (familyName) entry.familyName = familyName;
				const numberingName = INTERFACE_NUMBERING[numbering];
				if (numberingName) entry.interfaceNumberingName = numberingName;
				// With unknown numbering the number "shall be set to zero"
				// (802.1AB-2009, 8.5.9.6).
				if (numbering === 1 && entry.interfaceNumber !== 0)
					mark("malformed", "interface-number");
				if (oidLength > 0) {
					const dotted = oid(b, after + 6, offset);
					if (dotted === undefined) mark("malformed", "oid");
					else entry.oid = dotted;
				}
				fields.managementAddresses.push(entry);
				break;
			}
			case 127: {
				const oui = [0, 1, 2]
					.map((i) =>
						u8(b, value + i)
							.toString(16)
							.padStart(2, "0"),
					)
					.join("-");
				const subtype = u8(b, value + 3);
				const tlv: LldpOtherTlv = {
					type,
					length,
					value: hex(b, value + 4, offset),
					oui,
					subtype,
				};
				const org = ORGANIZATIONS[oui];
				if (org) {
					tlv.ouiName = org.name;
					const name = org.subtypes[subtype];
					if (name) tlv.subtypeName = name;
				}
				fields.otherTlvs.push(tlv);
				break;
			}
			default:
				raw(type, length, value);
		}
	}
}

const FIELDS: FieldDecls<LldpFields> = {
	chassisIdSubtype: {
		type: "string",
		optional: true,
		description:
			"The chassis id's subtype: chassis-component, interface-alias, port-component, mac-address, network-address, interface-name, locally-assigned, or subtype-<n>. Absent, with the chassis id, when the LLDPDU has no readable chassis id TLV; a problem says why.",
	},
	chassisId: {
		type: "string",
		optional: true,
		description:
			"The chassis id: a MAC address, an address (IPv4, IPv6 or MAC as text, another family as hex) or text, by subtype; hex for other subtypes. A MAC or address of the wrong length is malformed (tlv-length) and kept raw instead.",
	},
	portIdSubtype: {
		type: "string",
		optional: true,
		description:
			"The port id's subtype: interface-alias, port-component, mac-address, network-address, interface-name, agent-circuit-id, locally-assigned, or subtype-<n>. Absent, with the port id, when the LLDPDU has no readable port id TLV; a problem says why.",
	},
	portId: {
		type: "string",
		optional: true,
		description:
			"The port id, as the chassis id is read; an agent circuit id is hex.",
	},
	ttl: {
		type: "number",
		optional: true,
		description:
			"Time to live, in seconds; 0 when the sender is shutting down. Absent when the LLDPDU has no readable TTL TLV; a problem says why.",
	},
	portDescription: {
		type: "string",
		optional: true,
		description: "The port description, when sent.",
	},
	systemName: {
		type: "string",
		optional: true,
		description: "The system name, when sent.",
	},
	systemDescription: {
		type: "string",
		optional: true,
		description: "The system description, when sent.",
	},
	capabilities: {
		type: "string[]",
		optional: true,
		description:
			"The system's capabilities, when sent and consistent (a capability enabled but not supported is malformed/capabilities, and the TLV kept raw): other, repeater, bridge, wlan-access-point, router, telephone, docsis-cable-device, station-only, c-vlan-component, s-vlan-component, two-port-mac-relay, or bit-<n>.",
	},
	enabledCapabilities: {
		type: "string[]",
		optional: true,
		description:
			"The capabilities enabled, named as capabilities; present with it.",
	},
	managementAddresses: {
		type: "object[]",
		description:
			"Each management address TLV that reads whole, in order; one whose lengths do not fit is malformed (tlv-length) and kept raw in otherTlvs instead.",
		items: {
			family: {
				type: "number",
				description: "The address family (IANA Address Family Numbers).",
			},
			familyName: {
				type: "string",
				optional: true,
				description: "ipv4, ipv6 or mac, for those families.",
			},
			address: {
				type: "string",
				description:
					"The address: IPv4, IPv6 or MAC as text, another family as hex. An address whose length does not fit its family is malformed (tlv-length), and the TLV kept raw.",
			},
			interfaceNumbering: {
				type: "number",
				description: "How the interface is numbered.",
			},
			interfaceNumberingName: {
				type: "string",
				optional: true,
				description: "unknown, ifIndex or system-port-number.",
			},
			interfaceNumber: {
				type: "number",
				description:
					"The interface number; 0 with unknown numbering, which is malformed (interface-number) otherwise.",
			},
			oid: {
				type: "string",
				optional: true,
				description: "The object identifier, dotted, when one is sent.",
			},
		},
	},
	otherTlvs: {
		type: "object[]",
		description:
			"Every TLV not decoded into the fields above, in order: organizationally specific ones, reserved types, a second of a type read once, and one whose length is wrong for its type.",
		items: {
			type: { type: "number", description: "The TLV type." },
			length: {
				type: "number",
				description: "The TLV's length: the bytes of its value.",
			},
			value: {
				type: "string",
				description:
					"The value as hex; for an organizationally specific TLV, what follows its OUI and subtype.",
			},
			oui: {
				type: "string",
				optional: true,
				description: "An organizationally specific TLV's OUI, as 00-12-bb.",
			},
			ouiName: {
				type: "string",
				optional: true,
				description: "ieee-802.1, ieee-802.3 or tia-lldp-med, for those OUIs.",
			},
			subtype: {
				type: "number",
				optional: true,
				description: "An organizationally specific TLV's subtype.",
			},
			subtypeName: {
				type: "string",
				optional: true,
				description:
					"The subtype's name, for the OUIs and subtypes named, such as max-frame-size.",
			},
		},
	},
};

export const LLDP: Registration = {
	protocol: "lldp",
	name: "LLDP",
	reference: "IEEE 802.1AB",
	matches: [{ etherType: 0x88cc, dissect: lldp }],
	fields: fieldInfo(FIELDS),
};
