/**
 * Packet filters (DESIGN.md, "Filters"): simple and flag-shaped rather than
 * BPF. A spec names terms; repeating a term's values ORs them, different
 * terms AND, and `not` holds terms that exclude.
 *
 * A packet without a term's field (no ports on an ARP frame, a later IP
 * fragment, a header cut short) does not match a positive term, and is not
 * excluded by a negated one: a negated term is the plain negation of the
 * positive one, and "has no such field" is never a match.
 *
 * Pure: no I/O, and a spec is checked once, when the filter is created, so
 * matching never throws. Each spec key mirrors a CLI flag: `srcPortMatch` is
 * `--src-port-match`, and `not.host` is `--not-host`.
 */
import { isIP } from "node:net";
import {
	type Dissection,
	dissect,
	formatIpv4,
	formatIpv6,
	hex16,
	IP_PROTOCOLS,
} from "./dissect.ts";
import { TzspSniffError } from "./errors.ts";
import type { Capture } from "./listen.ts";
import { formatPeer } from "./records.ts";

/** Every filter term, in the order help and the header list them. */
export const FILTER_KEYS = [
	"proto",
	"host",
	"srcHost",
	"dstHost",
	"net",
	"srcNet",
	"dstNet",
	"portMatch",
	"srcPortMatch",
	"dstPortMatch",
	"mac",
	"srcMac",
	"dstMac",
	"etherType",
	"sender",
] as const;
export type FilterKey = (typeof FILTER_KEYS)[number];

export interface FilterTerms {
	/** A protocol in the packet's chain, or the one its IP header names. */
	proto?: readonly string[];
	/** An IPv4 or IPv6 address, as either endpoint (IP, or ARP's sender and target). */
	host?: readonly string[];
	srcHost?: readonly string[];
	dstHost?: readonly string[];
	/** A prefix such as `10.0.0.0/8` or `2001:db8::/32`; a bare address is one host. */
	net?: readonly string[];
	srcNet?: readonly string[];
	dstNet?: readonly string[];
	/** A UDP or TCP port, as either endpoint. */
	portMatch?: readonly (number | string)[];
	srcPortMatch?: readonly (number | string)[];
	dstPortMatch?: readonly (number | string)[];
	/** An Ethernet address, as the frame's source or destination. */
	mac?: readonly string[];
	srcMac?: readonly string[];
	dstMac?: readonly string[];
	/** An EtherType such as `0x0800`, in the Ethernet header or any VLAN tag. */
	etherType?: readonly string[];
	/**
	 * The listener label, or the outer UDP peer as an address or
	 * `address:port`: who sent the datagram, never a field inside the packet.
	 */
	sender?: readonly string[];
}

export interface FilterSpec extends FilterTerms {
	/** Terms that exclude: a packet matching any value of any of them is removed. */
	not?: FilterTerms;
}

/**
 * Whether a captured frame passes. Pass the dissection when there is one,
 * to save dissecting again. A capture that is not a frame (a control,
 * unsupported or invalid TZSP record) has none of a frame's fields.
 */
export interface PacketFilter {
	(capture: Capture, dissection?: Dissection): boolean;
	/** The spec, checked and in canonical form: what the header shows. */
	readonly spec: FilterSpec;
	/** The spec as CLI flags, such as `["--proto tcp", "--not-host 10.0.0.1"]`. */
	readonly flags: string[];
}

/** `srcPortMatch` → `src-port-match`. */
export const filterFlag = (key: FilterKey) =>
	key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);

/**
 * Protocol names `proto` accepts: every layer the dissector produces, and
 * every IP protocol it names (DESIGN.md, "Filters": `proto` matches the
 * chain; the IP header's protocol counts, so `ospf` works before an OSPF
 * dissector exists).
 */
export const FILTER_PROTOCOLS: readonly string[] = [
	...new Set([
		"ethernet",
		"vlan",
		"arp",
		"ipv4",
		"ipv6",
		"icmp",
		"icmpv6",
		"udp",
		"tcp",
		...Object.values(IP_PROTOCOLS),
	]),
];

/** The spec as CLI flags, positives first, in {@link FILTER_KEYS} order. */
export function filterFlags(spec: FilterSpec): string[] {
	const out: string[] = [];
	for (const [prefix, terms] of [
		["", spec],
		["not-", spec.not ?? {}],
	] as const) {
		for (const key of FILTER_KEYS) {
			for (const value of terms[key] ?? [])
				out.push(`--${prefix}${filterFlag(key)} ${value}`);
		}
	}
	return out;
}

// --- addresses -------------------------------------------------------------

/** An IP address's bytes, or undefined when `text` is not one. */
function parseIp(text: string): Uint8Array | undefined {
	const family = isIP(text);
	if (family === 4) return Uint8Array.from(text.split("."), Number);
	if (family !== 6 || text.includes("%")) return undefined;
	let s = text;
	// A trailing dotted IPv4 part becomes two groups.
	const lastColon = s.lastIndexOf(":");
	const tail = s.slice(lastColon + 1);
	if (tail.includes(".")) {
		const [a = 0, b = 0, c = 0, d = 0] = tail.split(".").map(Number);
		s = `${s.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
	}
	const groups = (part: string) =>
		part === "" ? [] : part.split(":").map((g) => Number.parseInt(g, 16));
	const at = s.indexOf("::");
	let all: number[];
	if (at < 0) all = groups(s);
	else {
		const head = groups(s.slice(0, at));
		const rest = groups(s.slice(at + 2));
		all = [
			...head,
			...new Array<number>(8 - head.length - rest.length).fill(0),
			...rest,
		];
	}
	const bytes = new Uint8Array(16);
	all.forEach((g, i) => {
		bytes[i * 2] = g >> 8;
		bytes[i * 2 + 1] = g & 0xff;
	});
	return bytes;
}

const formatIp = (b: Uint8Array) =>
	b.length === 4 ? formatIpv4(b) : formatIpv6(b);

/**
 * A peer address as a comparable key: an IPv4-mapped IPv6 address (how a
 * socket bound to `::` reports an IPv4 peer) is the IPv4 address. A zone
 * index is dropped.
 */
function peerKey(text: string): string | undefined {
	let b = parseIp(text.split("%")[0] as string);
	if (
		b?.length === 16 &&
		b.subarray(0, 10).every((x) => x === 0) &&
		b[10] === 0xff &&
		b[11] === 0xff
	) {
		b = b.subarray(12);
	}
	return b ? b.join(".") : undefined;
}

interface Net {
	bytes: Uint8Array;
	prefix: number;
}

const inNet = (address: string, net: Net) => {
	const b = parseIp(address);
	if (!b || b.length !== net.bytes.length) return false;
	const whole = net.prefix >> 3;
	for (let i = 0; i < whole; i++) if (b[i] !== net.bytes[i]) return false;
	const bits = net.prefix & 7;
	if (bits === 0) return true;
	const mask = (0xff << (8 - bits)) & 0xff;
	return ((b[whole] as number) & mask) === net.bytes[whole];
};

// --- values ----------------------------------------------------------------

/** One checked value: its canonical text and how to match it. */
interface Value {
	text: string;
	port?: number;
	net?: Net;
	sender?: { label: string; ip?: string; port?: number };
}

const invalid = (flag: string, value: unknown, what: string, fix: string) =>
	new TzspSniffError(
		"filter/invalid-value",
		`--${flag} ${JSON.stringify(value)} is not ${what}.`,
		fix,
	);

const LABEL = /^[A-Za-z0-9._-]+$/;

function checkValue(key: FilterKey, flag: string, raw: unknown): Value {
	const isPort = /portMatch$/i.test(key);
	if (typeof raw !== "string" && !(isPort && typeof raw === "number")) {
		throw invalid(
			flag,
			raw,
			isPort ? "a port number" : "a string",
			`Give each value of ${key} as ${isPort ? "a number or " : ""}a string.`,
		);
	}
	const text = String(raw).trim();
	switch (key) {
		case "proto": {
			const name = text.toLowerCase();
			if (!FILTER_PROTOCOLS.includes(name)) {
				throw invalid(
					flag,
					raw,
					"a protocol this tool names",
					`Use one of ${FILTER_PROTOCOLS.join(", ")}.`,
				);
			}
			return { text: name };
		}
		case "host":
		case "srcHost":
		case "dstHost": {
			const b = parseIp(text);
			if (!b) {
				throw invalid(
					flag,
					raw,
					"an IPv4 or IPv6 address",
					`Give it as --${flag} 10.0.2.15 or --${flag} 2001:db8::1; for a prefix, use --${flag.replace("host", "net")}.`,
				);
			}
			return { text: formatIp(b) };
		}
		case "net":
		case "srcNet":
		case "dstNet": {
			const [address = "", length, ...extra] = text.split("/");
			const b = parseIp(address);
			const max = b ? b.length * 8 : 0;
			const prefix = length === undefined ? max : Number(length);
			if (
				!b ||
				extra.length > 0 ||
				(length !== undefined && !/^[0-9]{1,3}$/.test(length)) ||
				prefix > max
			) {
				throw invalid(
					flag,
					raw,
					"an address prefix",
					`Give it as --${flag} 10.0.0.0/8 or --${flag} 2001:db8::/32.`,
				);
			}
			const bytes = b.slice();
			for (let bit = prefix; bit < max; bit++) {
				const i = bit >> 3;
				bytes[i] = (bytes[i] as number) & ~(0x80 >> (bit & 7));
			}
			return {
				text: `${formatIp(bytes)}/${prefix}`,
				net: { bytes, prefix },
			};
		}
		case "portMatch":
		case "srcPortMatch":
		case "dstPortMatch": {
			const port = Number(text);
			if (!/^[0-9]{1,5}$/.test(text) || port > 65535) {
				throw invalid(
					flag,
					raw,
					"a port from 0 to 65535",
					`Give it as --${flag} 443.`,
				);
			}
			return { text: String(port), port };
		}
		case "mac":
		case "srcMac":
		case "dstMac": {
			const m =
				/^([0-9a-f]{2})([:-]?)([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})$/i.exec(
					text,
				);
			if (!m) {
				throw invalid(
					flag,
					raw,
					"an Ethernet address",
					`Give it as --${flag} 02:00:00:00:00:0a.`,
				);
			}
			const parts = [m[1], m[3], m[4], m[5], m[6], m[7]] as string[];
			return { text: parts.join(":").toLowerCase() };
		}
		case "etherType": {
			const value = /^0x[0-9a-f]{1,4}$/i.test(text)
				? Number.parseInt(text.slice(2), 16)
				: -1;
			if (value < 0x0600) {
				throw invalid(
					flag,
					raw,
					"an EtherType (0x0600 to 0xffff, in hex)",
					`Give it as --${flag} 0x0800; a frame with an 802.3 length has no EtherType.`,
				);
			}
			return { text: hex16(value) };
		}
		case "sender": {
			const b = parseIp(text);
			if (b) {
				const canonical = formatIp(b);
				return {
					text: canonical,
					sender: { label: text, ip: peerKey(canonical) as string },
				};
			}
			const m = /^(?:\[([^\]]+)\]|([0-9.]+)):([0-9]{1,5})$/.exec(text);
			const host = m ? parseIp((m[1] ?? m[2]) as string) : undefined;
			const port = Number(m?.[3]);
			if (host && (m?.[1] !== undefined) === (host.length === 16)) {
				if (port <= 65535) {
					const canonical = formatIp(host);
					return {
						text: formatPeer(canonical, port),
						sender: { label: text, ip: peerKey(canonical) as string, port },
					};
				}
			}
			if (LABEL.test(text)) return { text, sender: { label: text } };
			throw invalid(
				flag,
				raw,
				"a listener label or a peer address",
				`Give a label from --port <port>=<label>, an address such as --${flag} 10.0.2.15, or an address and port such as --${flag} 10.0.2.15:37008.`,
			);
		}
	}
}

type Checked = Partial<Record<FilterKey, Value[]>>;

function checkTerms(terms: unknown, prefix: string, where: string): Checked {
	if (typeof terms !== "object" || terms === null || Array.isArray(terms)) {
		throw new TzspSniffError(
			"filter/invalid-value",
			`The filter ${where || "spec"} must be an object of terms.`,
			"Give it as { proto: ['tcp'], not: { host: ['10.0.0.1'] } }.",
		);
	}
	const checked: Checked = {};
	for (const [key, values] of Object.entries(terms)) {
		if (key === "not" && prefix === "") continue;
		if (!(FILTER_KEYS as readonly string[]).includes(key)) {
			throw new TzspSniffError(
				"filter/invalid-value",
				`"${where}${key}" is not a filter term.`,
				`Terms are ${FILTER_KEYS.join(", ")}${prefix === "" ? ", and not: { … } for the excluding ones" : ""}.`,
			);
		}
		if (values === undefined) continue;
		const filterKey = key as FilterKey;
		const flag = `${prefix}${filterFlag(filterKey)}`;
		if (!Array.isArray(values)) {
			throw new TzspSniffError(
				"filter/invalid-value",
				`The filter term ${where}${key} must be a list of values.`,
				`Give it as ${key}: [ … ]; its values are ORed.`,
			);
		}
		const seen = new Map<string, Value>();
		for (const raw of values) {
			const value = checkValue(filterKey, flag, raw);
			if (!seen.has(value.text)) seen.set(value.text, value);
		}
		// An empty list means the term is not set.
		if (seen.size) checked[filterKey] = [...seen.values()];
	}
	return checked;
}

const toTerms = (checked: Checked): FilterTerms => {
	const terms: Record<string, (string | number)[]> = {};
	for (const key of FILTER_KEYS) {
		const values = checked[key];
		if (values)
			terms[key] = values.map((v) => (v.port !== undefined ? v.port : v.text));
	}
	return terms as FilterTerms;
};

// --- matching --------------------------------------------------------------

/** What the terms read from one packet, found once. */
interface Facts {
	capture: Capture;
	protocols: Set<string>;
	etherTypes: string[];
	srcMac?: string;
	dstMac?: string;
	srcHosts: string[];
	dstHosts: string[];
	srcPorts: number[];
	dstPorts: number[];
}

function factsOf(capture: Capture, d: Dissection | undefined): Facts {
	const facts: Facts = {
		capture,
		protocols: new Set(),
		etherTypes: [],
		srcHosts: [],
		dstHosts: [],
		srcPorts: [],
		dstPorts: [],
	};
	for (const layer of d?.layers ?? []) {
		if (layer.protocol !== "data") facts.protocols.add(layer.protocol);
		if (!layer.fields) continue;
		switch (layer.protocol) {
			case "ethernet":
				facts.srcMac ??= layer.fields.src;
				facts.dstMac ??= layer.fields.dst;
				if (layer.fields.etherType)
					facts.etherTypes.push(layer.fields.etherType);
				break;
			case "vlan":
				if (layer.fields.etherType)
					facts.etherTypes.push(layer.fields.etherType);
				break;
			case "arp":
				if (layer.fields.senderIp) facts.srcHosts.push(layer.fields.senderIp);
				if (layer.fields.targetIp) facts.dstHosts.push(layer.fields.targetIp);
				break;
			case "ipv4":
			case "ipv6":
				facts.srcHosts.push(layer.fields.src);
				facts.dstHosts.push(layer.fields.dst);
				if (layer.fields.protocolName)
					facts.protocols.add(layer.fields.protocolName);
				break;
			case "udp":
			case "tcp":
				facts.srcPorts.push(layer.fields.srcPort);
				facts.dstPorts.push(layer.fields.dstPort);
				break;
		}
	}
	return facts;
}

type Side = "either" | "src" | "dst";
const sideOf = (key: FilterKey): Side =>
	key.startsWith("src") ? "src" : key.startsWith("dst") ? "dst" : "either";

function pick<T>(src: T[], dst: T[], side: Side): T[] {
	if (side === "src") return src;
	if (side === "dst") return dst;
	return [...src, ...dst];
}

function matchValue(key: FilterKey, v: Value, f: Facts): boolean {
	const side = sideOf(key);
	switch (key) {
		case "proto":
			return f.protocols.has(v.text);
		case "host":
		case "srcHost":
		case "dstHost":
			return pick(f.srcHosts, f.dstHosts, side).includes(v.text);
		case "net":
		case "srcNet":
		case "dstNet":
			return pick(f.srcHosts, f.dstHosts, side).some((a) =>
				inNet(a, v.net as Net),
			);
		case "portMatch":
		case "srcPortMatch":
		case "dstPortMatch":
			return pick(f.srcPorts, f.dstPorts, side).includes(v.port as number);
		case "mac":
		case "srcMac":
		case "dstMac": {
			const macs: string[] = [];
			if (side !== "dst" && f.srcMac) macs.push(f.srcMac);
			if (side !== "src" && f.dstMac) macs.push(f.dstMac);
			return macs.includes(v.text);
		}
		case "etherType":
			return f.etherTypes.includes(v.text);
		case "sender": {
			const s = v.sender as NonNullable<Value["sender"]>;
			const { listener, peer } = f.capture;
			if (listener.label === s.label) return true;
			if (s.ip === undefined || peerKey(peer.address) !== s.ip) return false;
			return s.port === undefined || s.port === peer.port;
		}
	}
}

const matchTerm = (key: FilterKey, values: Value[], f: Facts) =>
	values.some((v) => matchValue(key, v, f));

/**
 * Check a spec and return its filter. An unknown term or a value it cannot
 * read throws `filter/invalid-value`, naming the flag; matching never throws.
 */
export function createFilter(spec: FilterSpec = {}): PacketFilter {
	const positive = checkTerms(spec, "", "");
	const negative =
		spec.not === undefined ? {} : checkTerms(spec.not, "not-", "not.");
	const positiveTerms = Object.entries(positive) as [FilterKey, Value[]][];
	const negativeTerms = Object.entries(negative) as [FilterKey, Value[]][];
	const canonical: FilterSpec = toTerms(positive);
	if (negativeTerms.length) canonical.not = toTerms(negative);

	const filter = (capture: Capture, dissection?: Dissection) => {
		if (!positiveTerms.length && !negativeTerms.length) return true;
		let d = dissection;
		if (!d && capture.tzsp.kind === "packet") d = dissect(capture.tzsp.payload);
		const facts = factsOf(capture, d);
		for (const [key, values] of positiveTerms)
			if (!matchTerm(key, values, facts)) return false;
		for (const [key, values] of negativeTerms)
			if (matchTerm(key, values, facts)) return false;
		return true;
	};
	return Object.assign(filter, {
		spec: canonical,
		flags: filterFlags(canonical),
	});
}
