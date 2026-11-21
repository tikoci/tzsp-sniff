/**
 * What every dissector shares: the layer shape, byte readers and address
 * formats, the field declarations `dissectors()` lists, and `Frame`, the
 * state of one dissection, which dispatches from one layer to the next
 * through the registry (`registry.ts`).
 *
 * A dissector is a module under `src/dissect/` that exports one
 * `Registration` per protocol: how it is reached (a link type, EtherType,
 * IP protocol, or UDP or TCP port), the function that reads it, and its fields, declared against
 * the fields interface so the compiler holds the two in step (DESIGN.md,
 * "Decided: a dissector registry").
 */
import type { ArpLayer } from "./arp.ts";
import type { DhcpLayer } from "./dhcp.ts";
import type { EthernetLayer } from "./ethernet.ts";
import type { IcmpLayer } from "./icmp.ts";
import type { Ipv4Layer } from "./ipv4.ts";
import type { Ipv6Layer } from "./ipv6.ts";
import type { LldpLayer } from "./lldp.ts";
import type { MndpLayer } from "./mndp.ts";
import type { TcpLayer } from "./tcp.ts";
import type { UdpLayer } from "./udp.ts";
import type { VlanLayer } from "./vlan.ts";

/** What went wrong in a layer (the same three classes as `parseTzsp`). */
export type DissectProblem = "truncated" | "malformed" | "unsupported";

export interface LayerBase<P extends string, F> {
	protocol: P;
	/** Where the layer starts in the frame. */
	offset: number;
	/** Its span: header and everything it carries, within its parent's span. */
	length: number;
	/** Absent only when the fixed part of the header is cut short or unreadable. */
	fields?: F;
	problem?: DissectProblem;
	/** Which check set `problem` (`header`, `total-length`, `version` …). */
	reason?: string;
}

export interface DataFields {
	length: number;
}

/** Bytes no dissector here reads: an application payload, a later IP fragment, an unknown EtherType. */
export type DataLayer = LayerBase<"data", DataFields>;

export type Layer =
	| EthernetLayer
	| VlanLayer
	| ArpLayer
	| LldpLayer
	| Ipv4Layer
	| Ipv6Layer
	| IcmpLayer
	| UdpLayer
	| TcpLayer
	| DhcpLayer
	| MndpLayer
	| DataLayer;

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

// Readers: callers check bounds first, so `?? 0` never applies in practice;
// it keeps a missed check from becoming a throw.
export const u8 = (b: Uint8Array, o: number) => b[o] ?? 0;
export const u16 = (b: Uint8Array, o: number) => (u8(b, o) << 8) | u8(b, o + 1);
export const u32 = (b: Uint8Array, o: number) =>
	((u16(b, o) << 16) | u16(b, o + 2)) >>> 0;
export const hex = (b: Uint8Array, start: number, end: number) => {
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
export interface IpContext {
	version: 4 | 6;
	/** The packet is a first fragment: a transport length past its end is expected. */
	fragment: boolean;
	/** Where the IP header says its payload ends, which may be past the captured bytes. */
	declaredEnd: number;
	/** The capture ended before that point (an IP layer marked `truncated`). */
	cut: boolean;
}

/** A field's JSON type, as `dissectors()` lists it. */
export type FieldType =
	| "string"
	| "number"
	| "boolean"
	| "string[]"
	| "object[]";

/**
 * How sure the source of a generated table is of a field (m2ir's
 * `confidence`): `documented` by a vendor manual or an independent
 * implementation, or `observed-only`, seen on the wire but not documented.
 * m2ir's other labels (`inferred`, `guessed`, `superseded`) are never used
 * for a field: what they label stays raw (DESIGN.md, "Tables from m2ir").
 */
export type FieldConfidence = "documented" | "observed-only";

/** One field of a layer, as `dissectors()` lists it. */
export interface FieldInfo {
	name: string;
	type: FieldType;
	/**
	 * May be absent from a layer's `fields` (or an `object[]` item); the
	 * description says when. A field not optional is in every layer that has
	 * `fields` or, for an `object[]` field's item, in every item of the list.
	 * A layer has no `fields` when the fixed part of its header is cut short
	 * or unreadable; one whose options are cut short keeps them.
	 */
	optional: boolean;
	description: string;
	/** An `object[]` field's own fields. */
	items?: FieldInfo[];
	/**
	 * For a field from a generated table: how sure its source is. Absent for
	 * a field read from a standard (an RFC or IEEE document).
	 */
	confidence?: FieldConfidence;
	/**
	 * For a field from a generated table: the RouterOS versions it was seen
	 * on, oldest first. Not seen elsewhere is not the same as not sent.
	 */
	versionsSeen?: string[];
	/** The first RouterOS version seen sending it, when older ones did not. */
	since?: string;
}

/** Where a generated field comes from, as `FieldInfo` carries it. */
export interface FieldSource {
	confidence?: FieldConfidence;
	versionsSeen?: readonly string[];
	since?: string;
}

// `null` has no JSON type here (records leave a field out instead), so a
// field that may be null has no declaration.
type FieldDecl<T> = null extends T
	? never
	: { description: string } & FieldSource &
			([NonNullable<T>] extends [string]
				? { type: "string" }
				: [NonNullable<T>] extends [number]
					? { type: "number" }
					: [NonNullable<T>] extends [boolean]
						? { type: "boolean" }
						: [NonNullable<T>] extends [string[]]
							? { type: "string[]" }
							: [NonNullable<T>] extends [(infer E)[]]
								? // A list of lists, or of objects some of which are lists.
									[Extract<E, readonly unknown[]>] extends [never]
									? [E] extends [object]
										? { type: "object[]"; items: FieldDecls<E> }
										: never
									: never
								: never) &
			(undefined extends T ? { optional: true } : { optional?: never });

/**
 * A declaration for every field of `F`, keyed by its name: a field missing
 * here, a wrong type or a wrong `optional` does not compile, nor does a
 * list of anything but strings or objects. A key not in `F` is caught by
 * TypeScript's excess-property check, which applies to an object literal
 * written in place, not to one spread in or passed as a variable; the
 * runtime test in test/unit/dissect.test.ts catches that case, since no
 * vector produces such a field.
 */
export type FieldDecls<F> = { [K in keyof F]-?: FieldDecl<F[K]> };

interface LooseDecl extends FieldSource {
	description: string;
	type: FieldType;
	optional?: boolean;
	items?: Record<string, LooseDecl>;
}

/** The declarations as `dissectors()` lists them, in declaration order. */
export function fieldInfo<F>(decls: FieldDecls<F>): FieldInfo[] {
	const list = (d: Record<string, LooseDecl>): FieldInfo[] =>
		Object.entries(d).map(([name, f]) => ({
			name,
			type: f.type,
			optional: f.optional === true,
			description: f.description,
			...(f.items ? { items: list(f.items) } : {}),
			...(f.confidence ? { confidence: f.confidence } : {}),
			...(f.versionsSeen ? { versionsSeen: [...f.versionsSeen] } : {}),
			...(f.since ? { since: f.since } : {}),
		}));
	return list(decls as unknown as Record<string, LooseDecl>);
}

/** Reads a layer that starts at `start` of the frame and ends by `end`. */
export type LinkDissect = (f: Frame, start: number, end: number) => void;
/** As {@link LinkDissect}, under `vlans` tags already read. */
export type EtherDissect = (
	f: Frame,
	start: number,
	end: number,
	vlans: number,
) => void;
/** As {@link LinkDissect}, inside an IP packet. */
export type IpDissect = (
	f: Frame,
	start: number,
	end: number,
	ip: IpContext,
) => void;

/**
 * As {@link IpDissect}, for a UDP or TCP payload: from `start` to `end` is
 * the payload, never empty, and `ip` is the packet's (never a fragment).
 */
export type PortDissect = (
	f: Frame,
	start: number,
	end: number,
	ip: IpContext,
) => void;

/** How a dissector is reached, and the function that reads it there. */
export type Match =
	| { link: "ethernet"; dissect: LinkDissect }
	| { etherType: number; dissect: EtherDissect }
	| { ipProtocol: number; dissect: IpDissect }
	| { udpPort: number; dissect: PortDissect }
	| { tcpPort: number; dissect: PortDissect };

/** One protocol: what `dissectors()` lists, and how dispatch reaches it. */
export interface Registration {
	/** The layer's `protocol` in records, and the name `--proto` takes. */
	protocol: string;
	/** Its name for people, such as `IPv4`. */
	name: string;
	/** Where its layout comes from, such as `RFC 791`. */
	reference: string;
	matches: readonly Match[];
	fields: FieldInfo[];
}

/** Dispatch tables, from `registry.ts`. */
export interface Dispatch {
	link: ReadonlyMap<string, LinkDissect>;
	etherType: ReadonlyMap<number, EtherDissect>;
	ipProtocol: ReadonlyMap<number, IpDissect>;
	udpPort: ReadonlyMap<number, PortDissect>;
	tcpPort: ReadonlyMap<number, PortDissect>;
}

/** One dissection in progress: the bytes, the layers so far, and the way on. */
export class Frame {
	readonly layers: Layer[] = [];

	readonly b: Uint8Array;

	readonly dispatch: Dispatch;

	constructor(b: Uint8Array, dispatch: Dispatch) {
		this.b = b;
		this.dispatch = dispatch;
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

	/** The dissector the registry has for this EtherType, or a `data` layer. */
	etherPayload(start: number, end: number, type: number, vlans: number) {
		const next = this.dispatch.etherType.get(type);
		if (next) next(this, start, end, vlans);
		else this.data(start, end);
	}

	/** The dissector the registry has for this IP protocol, or a `data` layer. */
	ipPayload(start: number, end: number, protocol: number, ip: IpContext) {
		const next = this.dispatch.ipProtocol.get(protocol);
		if (next) next(this, start, end, ip);
		else this.data(start, end);
	}

	/**
	 * The dissector the registry has for a UDP datagram's or TCP segment's
	 * ports, the lower port first, or a `data` layer (DESIGN.md, "Decided:
	 * port matches"). The lower port first gives a request and its reply the
	 * same dissector, and a well-known port is lower than an ephemeral one.
	 * The dissector takes the bytes: none declines in 0.1.0. A first IP
	 * fragment's payload is cut short, so it stays `data`; an empty payload
	 * gets no layer.
	 */
	portPayload(
		transport: "udp" | "tcp",
		start: number,
		end: number,
		ports: readonly [number, number],
		ip: IpContext,
	) {
		if (end <= start) return;
		const table =
			transport === "udp" ? this.dispatch.udpPort : this.dispatch.tcpPort;
		const [a, b] = ports;
		const low = Math.min(a, b);
		const high = Math.max(a, b);
		const next = ip.fragment
			? undefined
			: (table.get(low) ?? (high === low ? undefined : table.get(high)));
		if (next) next(this, start, end, ip);
		else this.data(start, end);
	}
}
