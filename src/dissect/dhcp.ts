/**
 * DHCPv4 (RFC 2131, options RFC 2132), on UDP 67 and 68: the fixed BOOTP
 * header, the magic cookie and the options, the common ones decoded into
 * named fields and the rest kept as code, length and hex.
 *
 * Option codes, names and message types are from RFC 2132, RFC 3203
 * (FORCERENEW), RFC 4388 (leasequery) and IANA "Dynamic Host Configuration
 * Protocol (DHCP) and Bootstrap Protocol (BOOTP) Parameters". A repeated
 * option is joined before it is decoded, as RFC 3396 section 7 has a
 * receiver do (maintainer, 2026-11-21, #29). What RouterOS sends is in
 * test/lab/dhcp/REPORT.md.
 */
import {
	type FieldDecls,
	type Frame,
	fieldInfo,
	formatIpv4,
	formatMac,
	hex,
	type LayerBase,
	type Registration,
	u8,
	u16,
	u32,
} from "./core.ts";

/** The most options read, pad and End not counted; one more is `unsupported` (`option-limit`). */
export const MAX_DHCP_OPTIONS = 64;

/** The fixed header before the magic cookie: op to file (RFC 2131, figure 1). */
const HEADER = 236;
const COOKIE = 0x63825363;

export interface DhcpOtherOption {
	code: number;
	/** The option's name, for the codes named here, such as `relay-agent-information`. */
	name?: string;
	/** The bytes of its value: every instance's, joined, when it is repeated. */
	length: number;
	/** The value as hex. */
	value: string;
}

export interface DhcpFields {
	/** 1 for a request (client to server), 2 for a reply. */
	op: number;
	/** `request` or `reply`. */
	opName?: string;
	/** The hardware type (ARP's `hrd`): 1 is Ethernet. */
	hardwareType: number;
	hardwareLength: number;
	hops: number;
	/** The transaction id, as `0x18152c13`. */
	xid: string;
	secs: number;
	/** The flags field; only its top bit, broadcast, is defined. */
	flags: number;
	broadcast: boolean;
	ciaddr: string;
	yiaddr: string;
	siaddr: string;
	giaddr: string;
	/** A MAC for Ethernet (type 1, length 6); else the hardware length's bytes as hex. */
	chaddr: string;
	/** `sname`, up to its first zero byte, when set and not overloaded. */
	serverName?: string;
	/** `file`, as `serverName`. */
	bootFile?: string;
	/** `sname` as hex when option overload says it holds options. */
	serverNameHex?: string;
	/** `file` as hex, as `serverNameHex`. */
	bootFileHex?: string;
	messageType?: number;
	/** `discover`, `offer`, `request` … for the types named. */
	messageTypeName?: string;
	subnetMask?: string;
	routers?: string[];
	dnsServers?: string[];
	hostname?: string;
	domainName?: string;
	requestedAddress?: string;
	/** Seconds. */
	leaseTime?: number;
	/** Option 52: 1 `file` holds options, 2 `sname`, 3 both. */
	overload?: number;
	serverId?: string;
	/** Each code requested, by name, in order (`subnet-mask`, `router` … or `option-<n>`). */
	parameterRequestList?: string[];
	maxMessageSize?: number;
	/** Seconds. */
	renewalTime?: number;
	/** Seconds. */
	rebindingTime?: number;
	vendorClassId?: string;
	/** As hex: the type byte, then the id (RouterOS sends 01 and the MAC). */
	clientId?: string;
	/** Every option not decoded above, in the order first seen. */
	otherOptions: DhcpOtherOption[];
}

export type DhcpLayer = LayerBase<"dhcp", DhcpFields>;

/** RFC 2132 9.6, RFC 3203, RFC 4388 (IANA "DHCP Message Type 53 Values"). */
const MESSAGE_TYPES: Record<number, string> = {
	1: "discover",
	2: "offer",
	3: "request",
	4: "decline",
	5: "ack",
	6: "nak",
	7: "release",
	8: "inform",
	9: "forcerenew",
	10: "leasequery",
	11: "leaseunassigned",
	12: "leaseunknown",
	13: "leaseactive",
};

/** Option names, from IANA's registry, for the codes a RouterOS network is likely to show. */
const OPTION_NAMES: Record<number, string> = {
	1: "subnet-mask",
	2: "time-offset",
	3: "router",
	4: "time-server",
	5: "name-server",
	6: "domain-server",
	7: "log-server",
	12: "hostname",
	15: "domain-name",
	17: "root-path",
	19: "forward-on-off",
	23: "default-ip-ttl",
	26: "mtu-interface",
	28: "broadcast-address",
	31: "router-discovery",
	33: "static-route",
	35: "arp-timeout",
	40: "nis-domain",
	41: "nis-servers",
	42: "ntp-servers",
	43: "vendor-specific",
	44: "netbios-name-server",
	45: "netbios-dist-server",
	46: "netbios-node-type",
	47: "netbios-scope",
	50: "address-request",
	51: "address-time",
	52: "overload",
	53: "message-type",
	54: "server-id",
	55: "parameter-list",
	56: "message",
	57: "max-message-size",
	58: "renewal-time",
	59: "rebinding-time",
	60: "class-id",
	61: "client-id",
	66: "server-name",
	67: "bootfile-name",
	69: "smtp-server",
	77: "user-class",
	81: "client-fqdn",
	82: "relay-agent-information",
	100: "pcode",
	101: "tcode",
	108: "ipv6-only-preferred",
	114: "captive-portal",
	116: "auto-config",
	119: "domain-search",
	121: "classless-static-route",
	138: "capwap-ac-v4",
	150: "tftp-server-address",
	249: "ms-classless-static-route",
	252: "wpad",
};

// `ignoreBOM` keeps a leading byte-order mark as a character: stripped, two
// different values (an opaque vendor class id) would read the same.
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const LENIENT = new TextDecoder("utf-8", { ignoreBOM: true });

/** A plain Uint8Array over `b`'s memory (see lldp.ts: `subarray` would build a subclass). */
const view = (b: Uint8Array, start: number, end: number) =>
	new Uint8Array(b.buffer, b.byteOffset + start, end - start);

const optionName = (code: number) => OPTION_NAMES[code] ?? `option-${code}`;

/** The options decoded into fields, and whether a value of `n` bytes fits each. */
const DECODED: Record<number, (n: number) => boolean> = {
	1: (n) => n === 4,
	3: (n) => n >= 4 && n % 4 === 0,
	6: (n) => n >= 4 && n % 4 === 0,
	12: (n) => n >= 1,
	15: (n) => n >= 1,
	50: (n) => n === 4,
	51: (n) => n === 4,
	52: (n) => n === 1,
	53: (n) => n === 1,
	54: (n) => n === 4,
	55: (n) => n >= 1,
	57: (n) => n === 2,
	58: (n) => n === 4,
	59: (n) => n === 4,
	60: (n) => n >= 1,
	// RFC 2132 9.14: "The minimum length is 2."
	61: (n) => n >= 2,
};

// RFC 2131, section 2 and figure 1; options RFC 2132.
function dhcp(f: Frame, start: number, end: number) {
	const b = f.b;
	const available = end - start;
	if (available < HEADER) {
		f.layers.push({
			protocol: "dhcp",
			offset: start,
			length: available,
			problem: "truncated",
			reason: "header",
		});
		return;
	}
	const op = u8(b, start);
	const hardwareType = u8(b, start + 1);
	const hardwareLength = u8(b, start + 2);
	const flags = u16(b, start + 10);
	const ethernet = hardwareType === 1 && hardwareLength === 6;
	const fields: DhcpFields = {
		op,
		hardwareType,
		hardwareLength,
		hops: u8(b, start + 3),
		xid: `0x${hex(b, start + 4, start + 8)}`,
		secs: u16(b, start + 8),
		flags,
		broadcast: (flags & 0x8000) !== 0,
		ciaddr: formatIpv4(b, start + 12),
		yiaddr: formatIpv4(b, start + 16),
		siaddr: formatIpv4(b, start + 20),
		giaddr: formatIpv4(b, start + 24),
		chaddr: ethernet
			? formatMac(b, start + 28)
			: hex(b, start + 28, start + 28 + Math.min(hardwareLength, 16)),
		otherOptions: [],
	};
	if (op === 1) fields.opName = "request";
	else if (op === 2) fields.opName = "reply";
	const layer: DhcpLayer = {
		protocol: "dhcp",
		offset: start,
		// The options field runs to the end of the datagram: padding after
		// End is DHCP's, not a next layer's.
		length: available,
		fields,
	};
	f.layers.push(layer);
	const mark = (
		problem: "truncated" | "malformed" | "unsupported",
		reason: string,
	) => {
		layer.problem ??= problem;
		layer.reason ??= reason;
	};
	/** Text, read leniently and marked `malformed` (`text`) when it is not UTF-8. */
	const text = (from: number, to: number): string => {
		try {
			return UTF8.decode(view(b, from, to));
		} catch {
			mark("malformed", "text");
			return LENIENT.decode(view(b, from, to));
		}
	};
	// chaddr is 16 bytes (RFC 2131, figure 1). Marked once whatever stopped
	// the reading (a cut cookie or option, no End, the cap) is marked, so
	// that cause is the one reported.
	const hardwareLengthCheck = () => {
		if (hardwareLength > 16) mark("malformed", "hardware-length");
	};

	if (available < HEADER + 4) {
		mark("truncated", "cookie");
		hardwareLengthCheck();
		named(start + 44, start + 108, start + 236);
		return;
	}
	if (u32(b, start + HEADER) !== COOKIE) {
		mark("malformed", "cookie");
		hardwareLengthCheck();
		named(start + 44, start + 108, start + 236);
		return;
	}

	// Each code's value pieces in the order seen; a repeated option is the
	// pieces joined (RFC 3396, 7).
	const values = new Map<number, Uint8Array[]>();
	let count = 0;
	let offset = start + HEADER + 4;
	let ended = false;
	/** An option whose last piece runs past the datagram: what was joined of it is incomplete. */
	let cut: number | undefined;
	while (offset < end) {
		const code = u8(b, offset);
		if (code === 0) {
			offset++;
			continue;
		}
		if (code === 255) {
			// What follows End is padding, never options.
			ended = true;
			break;
		}
		if (count === MAX_DHCP_OPTIONS) {
			mark("unsupported", "option-limit");
			break;
		}
		if (offset + 2 > end || offset + 2 + u8(b, offset + 1) > end) {
			mark("truncated", "option");
			// Even a lone code byte starts another piece of that option.
			cut = code;
			break;
		}
		const length = u8(b, offset + 1);
		const pieces = values.get(code) ?? [];
		pieces.push(view(b, offset + 2, offset + 2 + length));
		values.set(code, pieces);
		count++;
		offset += 2 + length;
	}
	if (!ended && layer.problem === undefined) mark("truncated", "end");
	hardwareLengthCheck();

	for (const [code, pieces] of values) {
		const v = join(pieces);
		const fits = DECODED[code];
		// Earlier pieces of an option whose next piece is cut (RFC 3396): not
		// read as the option, which is incomplete, and kept raw.
		if (!fits || code === cut) {
			other(code, v);
			continue;
		}
		if (!fits(v.length)) {
			mark("malformed", "option-length");
			other(code, v);
			continue;
		}
		decode(code, v);
	}
	const overloaded = fields.overload ?? 0;
	// RFC 2131 4.1: with overload, the field or fields it names hold
	// options. Those are kept as hex and not read (maintainer, 2026-11-21,
	// #29).
	if (fields.overload !== undefined) mark("unsupported", "overload");
	named(start + 44, start + 108, start + 236, overloaded);

	/** `sname` and `file`: text when set, hex when overload says they hold options. */
	function named(sname: number, file: number, stop: number, overload = 0) {
		const field = (from: number, to: number, holdsOptions: boolean) => {
			if (holdsOptions) return { hex: hex(b, from, to) };
			if (u8(b, from) === 0) return {};
			let zero = from;
			while (zero < to && u8(b, zero) !== 0) zero++;
			return { text: text(from, zero) };
		};
		const s = field(sname, file, (overload & 2) !== 0);
		if (s.text !== undefined) fields.serverName = s.text;
		if (s.hex !== undefined) fields.serverNameHex = s.hex;
		const fl = field(file, stop, (overload & 1) !== 0);
		if (fl.text !== undefined) fields.bootFile = fl.text;
		if (fl.hex !== undefined) fields.bootFileHex = fl.hex;
	}

	function other(code: number, v: Uint8Array) {
		const option: DhcpOtherOption = {
			code,
			length: v.length,
			value: hex(v, 0, v.length),
		};
		const name = OPTION_NAMES[code];
		if (name) option.name = name;
		fields.otherOptions.push(option);
	}

	function decode(code: number, v: Uint8Array) {
		const addresses = () => {
			const list: string[] = [];
			for (let i = 0; i < v.length; i += 4) list.push(formatIpv4(v, i));
			return list;
		};
		/** NVT ASCII text, its trailing zero bytes deleted, as RFC 2132 section 2 has a receiver do. */
		const textOf = () => {
			let stop = v.length;
			while (stop > 0 && v[stop - 1] === 0) stop--;
			const t = view(v, 0, stop);
			try {
				return UTF8.decode(t);
			} catch {
				mark("malformed", "text");
				return LENIENT.decode(t);
			}
		};
		switch (code) {
			case 1:
				fields.subnetMask = formatIpv4(v);
				break;
			case 3:
				fields.routers = addresses();
				break;
			case 6:
				fields.dnsServers = addresses();
				break;
			case 12:
				fields.hostname = textOf();
				break;
			case 15:
				fields.domainName = textOf();
				break;
			case 50:
				fields.requestedAddress = formatIpv4(v);
				break;
			case 51:
				fields.leaseTime = u32(v, 0);
				break;
			case 52: {
				// RFC 2132 9.3: 1 file, 2 sname, 3 both; any other value names
				// neither, so it is kept raw and sname and file are read as text.
				const value = u8(v, 0);
				if (value >= 1 && value <= 3) fields.overload = value;
				else {
					mark("malformed", "option-value");
					other(code, v);
				}
				break;
			}
			case 53: {
				const type = u8(v, 0);
				fields.messageType = type;
				const name = MESSAGE_TYPES[type];
				if (name) fields.messageTypeName = name;
				break;
			}
			case 54:
				fields.serverId = formatIpv4(v);
				break;
			case 55:
				fields.parameterRequestList = [...v].map(optionName);
				break;
			case 57:
				fields.maxMessageSize = u16(v, 0);
				break;
			case 58:
				fields.renewalTime = u32(v, 0);
				break;
			case 59:
				fields.rebindingTime = u32(v, 0);
				break;
			case 60: {
				// Opaque by RFC 2132 9.13: text when it is UTF-8, else kept raw
				// with no problem, since nothing requires text.
				try {
					fields.vendorClassId = UTF8.decode(v);
				} catch {
					other(code, v);
				}
				break;
			}
			case 61:
				fields.clientId = hex(v, 0, v.length);
				break;
		}
	}
}

function join(pieces: readonly Uint8Array[]): Uint8Array {
	if (pieces.length === 1) return pieces[0] as Uint8Array;
	const out = new Uint8Array(pieces.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of pieces) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}

const address = (what: string) => ({
	type: "string" as const,
	description: `${what}, dotted.`,
});
const option = (code: number, what: string) =>
	`Option ${code}, ${what}, when sent with the right length; a wrong length is malformed (option-length) and the option kept in otherOptions.`;

const FIELDS: FieldDecls<DhcpFields> = {
	op: { type: "number", description: "1 for a request, 2 for a reply." },
	opName: {
		type: "string",
		optional: true,
		description: "request or reply, for op 1 and 2.",
	},
	hardwareType: {
		type: "number",
		description: "The hardware type (ARP's hardware types): 1 is Ethernet.",
	},
	hardwareLength: {
		type: "number",
		description:
			"The hardware address length; over 16 is malformed (hardware-length).",
	},
	hops: { type: "number", description: "Relay hops so far." },
	xid: { type: "string", description: "The transaction id, as 0x18152c13." },
	secs: {
		type: "number",
		description: "Seconds since the client began acquiring or renewing.",
	},
	flags: {
		type: "number",
		description: "The flags field; only its top bit, broadcast, is defined.",
	},
	broadcast: {
		type: "boolean",
		description: "The broadcast flag: the client asks for broadcast replies.",
	},
	ciaddr: address("The client's address, when it has one (ciaddr)"),
	yiaddr: address("The address the server offers or assigns (yiaddr)"),
	siaddr: address("The next server, for booting (siaddr)"),
	giaddr: address("The relay agent's address (giaddr)"),
	chaddr: {
		type: "string",
		description:
			"The client's hardware address: a MAC for Ethernet (type 1, length 6), else the hardware length's bytes (at most 16) as hex.",
	},
	serverName: {
		type: "string",
		optional: true,
		description:
			"The server host name (sname), up to its first zero byte, when set; absent when overload says sname holds options.",
	},
	bootFile: {
		type: "string",
		optional: true,
		description:
			"The boot file name (file), as serverName; absent when overload says file holds options.",
	},
	serverNameHex: {
		type: "string",
		optional: true,
		description:
			"sname as hex, when option 52 says it holds options; they are not read (unsupported/overload).",
	},
	bootFileHex: {
		type: "string",
		optional: true,
		description: "file as hex, as serverNameHex.",
	},
	messageType: {
		type: "number",
		optional: true,
		description: option(53, "the DHCP message type"),
	},
	messageTypeName: {
		type: "string",
		optional: true,
		description: `The message type's name: ${Object.values(MESSAGE_TYPES).join(", ")}. Absent for other values.`,
	},
	subnetMask: {
		type: "string",
		optional: true,
		description: option(1, "the subnet mask, dotted"),
	},
	routers: {
		type: "string[]",
		optional: true,
		description: option(3, "the routers, dotted"),
	},
	dnsServers: {
		type: "string[]",
		optional: true,
		description: option(6, "the DNS servers, dotted"),
	},
	hostname: {
		type: "string",
		optional: true,
		description: `${option(12, "the host name")} Trailing zero bytes are deleted (RFC 2132, 2). Not UTF-8 is malformed (text), read with replacement characters. An option whose last piece is cut short (RFC 3396) is truncated (option) and kept in otherOptions.`,
	},
	domainName: {
		type: "string",
		optional: true,
		description: `${option(15, "the domain name")} Trailing zero bytes are deleted; not UTF-8 is malformed (text).`,
	},
	requestedAddress: {
		type: "string",
		optional: true,
		description: option(50, "the address the client asks for, dotted"),
	},
	leaseTime: {
		type: "number",
		optional: true,
		description: option(51, "the lease time in seconds"),
	},
	overload: {
		type: "number",
		optional: true,
		description: `${option(52, "option overload: 1 file holds options, 2 sname, 3 both")} The options there are not read: unsupported (overload). Another value names no field: malformed (option-value), kept in otherOptions.`,
	},
	serverId: {
		type: "string",
		optional: true,
		description: option(54, "the server identifier, dotted"),
	},
	parameterRequestList: {
		type: "string[]",
		optional: true,
		description: `${option(55, "the parameter request list")} Each code by its IANA name (subnet-mask, router, domain-server …), or option-<n>.`,
	},
	maxMessageSize: {
		type: "number",
		optional: true,
		description: option(57, "the largest DHCP message the client accepts"),
	},
	renewalTime: {
		type: "number",
		optional: true,
		description: option(58, "the renewal (T1) time in seconds"),
	},
	rebindingTime: {
		type: "number",
		optional: true,
		description: option(59, "the rebinding (T2) time in seconds"),
	},
	vendorClassId: {
		type: "string",
		optional: true,
		description: `${option(60, "the vendor class identifier")} Opaque by RFC 2132: one that is not UTF-8 is kept in otherOptions, with no problem. A leading byte-order mark is kept as U+FEFF.`,
	},
	clientId: {
		type: "string",
		optional: true,
		description: `${option(61, "the client identifier, as hex: its type byte, then the id")} RouterOS sends 01 and the MAC.`,
	},
	otherOptions: {
		type: "object[]",
		description:
			"Every option not decoded into the fields above, in the order first seen: other codes, and a decoded code whose length is wrong. Pad and End are not listed.",
		items: {
			code: { type: "number", description: "The option code." },
			name: {
				type: "string",
				optional: true,
				description:
					"Its IANA name, for the codes named, such as relay-agent-information.",
			},
			length: {
				type: "number",
				description:
					"The bytes of its value: every instance's, joined, when it is repeated (RFC 3396).",
			},
			value: { type: "string", description: "The value as hex." },
		},
	},
};

export const DHCP: Registration = {
	protocol: "dhcp",
	name: "DHCPv4",
	reference: "RFC 2131",
	matches: [
		{ udpPort: 67, dissect: dhcp },
		{ udpPort: 68, dissect: dhcp },
	],
	fields: fieldInfo(FIELDS),
};
