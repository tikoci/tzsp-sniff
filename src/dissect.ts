/**
 * Frame dissectors: Ethernet, 802.1Q and 802.1ad, ARP, IPv4, IPv6, ICMP,
 * ICMPv6, UDP, TCP and LLDP (DESIGN.md, "Dissectors", order 1), DHCPv4,
 * the first reached by UDP port, and MNDP, the first read with a table
 * generated from m2ir.
 *
 * Pure and bounded, like `parseTzsp`: bytes in, layers out, no I/O, and it
 * never throws. Each layer keeps its span in the frame, so its bytes can be
 * read again; a layer that cannot finish says why with `problem` and
 * `reason`. A child's span lies inside its parent's: an IPv4 total length
 * shorter than the frame trims it (Ethernet padding is not passed up), a
 * longer one is `truncated` and dissection goes on over the bytes there are.
 *
 * Each protocol is a module under `src/dissect/` that registers how it is
 * reached and its fields (`src/dissect/registry.ts`); dispatch from one
 * layer to the next goes through that registry, and `dissectors()` lists it.
 * Field layouts and numbers are from the RFCs and IANA registries named at
 * each dissector, and MNDP's from m2ir's YAML (src/dissect/mndp-table.ts,
 * generated); no Wireshark code is used.
 */
import { DISPATCH } from "./dissect/registry.ts";
import { type DissectProblem, Frame, type Layer } from "./dissect/core.ts";

export type { ArpFields, ArpLayer } from "./dissect/arp.ts";
export {
	type DhcpFields,
	type DhcpLayer,
	type DhcpOtherOption,
	MAX_DHCP_OPTIONS,
} from "./dissect/dhcp.ts";
export {
	type DataFields,
	type DataLayer,
	type DissectProblem,
	type FieldConfidence,
	type FieldInfo,
	type FieldType,
	formatIpv4,
	formatIpv6,
	formatMac,
	hex16,
	IP_PROTOCOLS,
	type Layer,
} from "./dissect/core.ts";
export type { EthernetFields, EthernetLayer } from "./dissect/ethernet.ts";
export {
	ICMP_TYPES,
	ICMPV6_TYPES,
	type IcmpFields,
	type IcmpLayer,
} from "./dissect/icmp.ts";
export type { Ipv4Fields, Ipv4Layer } from "./dissect/ipv4.ts";
export {
	type Ipv6Extension,
	type Ipv6Fields,
	type Ipv6Layer,
	MAX_IPV6_EXTENSIONS,
} from "./dissect/ipv6.ts";
export {
	type LldpFields,
	type LldpLayer,
	type LldpManagementAddress,
	type LldpOtherTlv,
	MAX_LLDP_TLVS,
} from "./dissect/lldp.ts";
export {
	type M2irFacts,
	type M2irFieldFacts,
	type M2irValueFacts,
	m2irFacts,
} from "./dissect/m2ir.ts";
export {
	MAX_MNDP_TLVS,
	type MndpFields,
	type MndpLayer,
	type MndpOtherTlv,
	type MndpTlvFields,
} from "./dissect/mndp.ts";
export {
	type DissectorInfo,
	type DissectorMatch,
	dissectors,
} from "./dissect/registry.ts";
export type { TcpFields, TcpLayer } from "./dissect/tcp.ts";
export type { UdpFields, UdpLayer } from "./dissect/udp.ts";
export {
	MAX_VLAN_TAGS,
	type VlanFields,
	type VlanLayer,
} from "./dissect/vlan.ts";

export interface Dissection {
	/** The input frame itself, not a copy. */
	frame: Uint8Array;
	layers: Layer[];
	/** `layers` protocols in order, such as `["ethernet", "ipv4", "icmp"]`. */
	protocols: string[];
	/** The first layer that has a problem, if any. */
	problem?: { protocol: string; problem: DissectProblem; reason: string };
}

/**
 * Dissect one Ethernet frame (the `payload` of a TZSP `packet` record). Never
 * throws: what it cannot read is marked on the layer where it stopped.
 */
export function dissect(frame: Uint8Array): Dissection {
	const f = new Frame(frame, DISPATCH);
	const ethernet = DISPATCH.link.get("ethernet");
	if (ethernet) ethernet(f, 0, frame.length);
	else f.data(0, frame.length);
	return finish(frame, f);
}

/**
 * Dissect bytes that start at the layer an EtherType names, with no
 * Ethernet header: a raw IP or Linux cooked capture, for `decode` to find
 * UDP to the TZSP port in. Not exported from the package.
 */
export function dissectFrom(bytes: Uint8Array, etherType: number): Dissection {
	const f = new Frame(bytes, DISPATCH);
	f.etherPayload(0, bytes.length, etherType, 0);
	return finish(bytes, f);
}

function finish(frame: Uint8Array, f: Frame): Dissection {
	const result: Dissection = {
		frame,
		layers: f.layers,
		protocols: f.layers.map((l) => l.protocol),
	};
	const first = f.layers.find((l) => l.problem);
	if (first?.problem) {
		result.problem = {
			protocol: first.protocol,
			problem: first.problem,
			reason: first.reason ?? first.problem,
		};
	}
	return result;
}
