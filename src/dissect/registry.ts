/**
 * The dissector registry: every registration, in the order `dissectors()`
 * lists them, and the dispatch tables built from their matches. Adding a
 * dissector is a module and a line here; `test/unit/registry.test.ts` holds
 * the list, the dispatch and the fields records carry in step.
 */
import { ARP } from "./arp.ts";
import type {
	Dispatch,
	EtherDissect,
	FieldInfo,
	IpDissect,
	LinkDissect,
	PortDissect,
	Registration,
} from "./core.ts";
import { hex16 } from "./core.ts";
import { DHCP } from "./dhcp.ts";
import { ETHERNET } from "./ethernet.ts";
import { ICMP, ICMPV6 } from "./icmp.ts";
import { IPV4 } from "./ipv4.ts";
import { IPV6 } from "./ipv6.ts";
import { LLDP } from "./lldp.ts";
import { TCP } from "./tcp.ts";
import { UDP } from "./udp.ts";
import { VLAN } from "./vlan.ts";

/** Every dissector, outermost first. */
export const REGISTRATIONS: readonly Registration[] = [
	ETHERNET,
	VLAN,
	ARP,
	LLDP,
	IPV4,
	IPV6,
	ICMP,
	ICMPV6,
	UDP,
	TCP,
	DHCP,
];

/**
 * The dispatch tables for `registrations`. A match claimed twice keeps the
 * first and is named in `duplicates`, which a test holds empty.
 */
export function buildDispatch(registrations: readonly Registration[]): {
	dispatch: Dispatch;
	duplicates: string[];
} {
	const link = new Map<string, LinkDissect>();
	const etherType = new Map<number, EtherDissect>();
	const ipProtocol = new Map<number, IpDissect>();
	const udpPort = new Map<number, PortDissect>();
	const tcpPort = new Map<number, PortDissect>();
	const duplicates: string[] = [];
	const add = <K, V>(map: Map<K, V>, key: K, value: V, label: string) => {
		if (map.has(key)) duplicates.push(label);
		else map.set(key, value);
	};
	for (const r of registrations) {
		for (const m of r.matches) {
			if ("link" in m) add(link, m.link, m.dissect, `link ${m.link}`);
			else if ("etherType" in m)
				add(
					etherType,
					m.etherType,
					m.dissect,
					`etherType ${hex16(m.etherType)}`,
				);
			else if ("ipProtocol" in m)
				add(ipProtocol, m.ipProtocol, m.dissect, `ipProtocol ${m.ipProtocol}`);
			else if ("udpPort" in m)
				add(udpPort, m.udpPort, m.dissect, `udpPort ${m.udpPort}`);
			else add(tcpPort, m.tcpPort, m.dissect, `tcpPort ${m.tcpPort}`);
		}
	}
	return {
		dispatch: { link, etherType, ipProtocol, udpPort, tcpPort },
		duplicates,
	};
}

export const DISPATCH: Dispatch = buildDispatch(REGISTRATIONS).dispatch;

/** How a dissector is reached, as `dissectors()` lists it. */
export type DissectorMatch =
	/** The frame itself, for this link type (TZSP encapsulation 1, a pcap or pcapng Ethernet link). */
	| { by: "link"; value: "ethernet" }
	/** An EtherType in an Ethernet header or a VLAN tag, as `0x0800`. */
	| { by: "etherType"; value: string }
	/** An IP protocol number in an IPv4 header or after IPv6's extension headers. */
	| { by: "ipProtocol"; value: number }
	/**
	 * A UDP port, either the source or the destination; when both ports have
	 * a dissector, the lower port's is the one used.
	 */
	| { by: "udpPort"; value: number }
	/** A TCP port, as `udpPort`. No dissector here is reached this way yet. */
	| { by: "tcpPort"; value: number };

/** One protocol this package decodes (DESIGN.md, "Library"). */
export interface DissectorInfo {
	/** The layer's `protocol` in records, and the name `--proto` takes. */
	protocol: string;
	/** Its name for people. */
	name: string;
	/** Where its layout comes from. */
	reference: string;
	matches: DissectorMatch[];
	/**
	 * The layer's fields, as records carry them at `--detail layers`. A field
	 * not `optional` is in every layer that has `fields` (an item's field, in
	 * every item of its list); a layer lacks `fields` only when the fixed
	 * part of its header is cut short or unreadable.
	 */
	fields: FieldInfo[];
}

const copyFields = (fields: readonly FieldInfo[]): FieldInfo[] =>
	fields.map((f) => ({
		...f,
		...(f.items ? { items: copyFields(f.items) } : {}),
	}));

/** Every protocol this package decodes: how each is matched, and its fields. A new copy each call. */
export function dissectors(): DissectorInfo[] {
	return REGISTRATIONS.map((r) => ({
		protocol: r.protocol,
		name: r.name,
		reference: r.reference,
		matches: r.matches.map((m): DissectorMatch => {
			if ("link" in m) return { by: "link", value: m.link };
			if ("etherType" in m)
				return { by: "etherType", value: hex16(m.etherType) };
			if ("ipProtocol" in m) return { by: "ipProtocol", value: m.ipProtocol };
			if ("udpPort" in m) return { by: "udpPort", value: m.udpPort };
			return { by: "tcpPort", value: m.tcpPort };
		}),
		fields: copyFields(r.fields),
	}));
}
