// cspell:ignore Zmen epan ppp fddi fcs wlan encap undecrypted -- TZSP and Wireshark names, this file only
/**
 * TZSP (TaZmen Sniffer Protocol) datagram parser. Pure: bytes in, a record out,
 * no I/O, and it never throws, so one bad datagram cannot stop a capture.
 *
 * Layout (Wireshark epan/dissectors/packet-tzsp.c, read at commit e0929ac4,
 * 2026-11-18; numbers only, no code taken):
 *
 *   [0]     version        u8, 1
 *   [1]     type           u8, 0 = received packet (what RouterOS sends)
 *   [2..3]  encapsulation  u16 big-endian, 1 = Ethernet
 *   [4..]   tags           0 = pad (1 byte), 1 = end (1 byte), else tag, length, value
 *   [..]    payload        the captured frame, after the end tag
 *
 * RouterOS: `/tool/sniffer` streaming on 7.26beta5 x86 CHR sends `01 00 00 01 01`,
 * version 1, received, Ethernet, the end tag alone (tikoci/quickchr
 * examples/cmr/FINDINGS.md, "Wire"). Whether mangle `sniff-id` adds a tag is not
 * yet grounded (BACKLOG.md).
 */

/** TZSP packet types (packet-tzsp.c). */
export const TZSP_TYPES = {
	0: "received",
	1: "transmit",
	3: "config",
	4: "keepalive",
	5: "port-opener",
} as const satisfies Record<number, string>;

/** TZSP encapsulations (packet-tzsp.c). */
export const TZSP_ENCAPSULATIONS = {
	1: "ethernet",
	2: "token-ring",
	3: "slip",
	4: "ppp",
	5: "fddi",
	7: "raw-ip",
	18: "ieee-802.11",
	119: "ieee-802.11-prism",
	126: "ieee-802.11-radiotap",
	127: "ieee-802.11-avs",
} as const satisfies Record<number, string>;

/** TZSP tags (packet-tzsp.c): generic header options, then 802.11 radio options. */
export const TZSP_TAGS = {
	0: "pad",
	1: "end",
	10: "signal",
	11: "noise",
	12: "rate",
	13: "radio-time",
	14: "message-type",
	15: "contention-free",
	16: "undecrypted",
	17: "fcs-error",
	18: "channel",
	30: "wlan-station-stats",
	31: "wlan-packet-stats",
	40: "packet-id",
	41: "original-length",
	60: "sensor-mac",
	80: "device-name",
	81: "capture-location",
	82: "time-stamp",
	83: "info",
	84: "capture-id",
} as const satisfies Record<number, string>;

/** The default TZSP port, 0x9090: RouterOS's and Wireshark's, not IANA registered. */
export const TZSP_PORT = 37008;

export interface TzspTag {
	tag: number;
	/** A name from {@link TZSP_TAGS}, or `tag-<n>` for one nobody has named. */
	name: string;
	/** The value bytes, hex. Pad and end tags have none. */
	hex: string;
}

export type TzspProblem =
	| "too-short" // fewer than 4 header bytes
	| "bad-version" // version is not 1
	| "no-end-tag" // the tag list runs off the end
	| "truncated-tag"; // a tag's length runs past the datagram

export interface TzspDatagram {
	version: number;
	type: number;
	/** A name from {@link TZSP_TYPES}, or `type-<n>`. */
	typeName: string;
	encapsulation: number;
	/** A name from {@link TZSP_ENCAPSULATIONS}, or `encap-<n>`. */
	encapsulationName: string;
	/** Every tag except pad and end, in order. */
	tags: TzspTag[];
	/** The captured frame. Empty when there is a problem, or for keepalives. */
	payload: Uint8Array;
	/** Set when the datagram could not be parsed to its payload. */
	problem?: TzspProblem;
}

const name = (table: Record<number, string>, value: number, prefix: string) =>
	table[value] ?? `${prefix}-${value}`;

export const toHex = (bytes: Uint8Array): string =>
	Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** Parse one TZSP datagram (a UDP payload). Never throws; see `problem`. */
export function parseTzsp(datagram: Uint8Array): TzspDatagram {
	const empty = new Uint8Array(0);
	const version = datagram[0] ?? 0;
	const type = datagram[1] ?? 0;
	const encapsulation =
		datagram.length >= 4
			? ((datagram[2] as number) << 8) | (datagram[3] as number)
			: 0;
	const result: TzspDatagram = {
		version,
		type,
		typeName: name(TZSP_TYPES, type, "type"),
		encapsulation,
		encapsulationName: name(TZSP_ENCAPSULATIONS, encapsulation, "encap"),
		tags: [],
		payload: empty,
	};
	if (datagram.length < 4) return { ...result, problem: "too-short" };
	if (version !== 1) return { ...result, problem: "bad-version" };

	let offset = 4;
	while (offset < datagram.length) {
		const tag = datagram[offset] as number;
		if (tag === 1) {
			result.payload = datagram.subarray(offset + 1);
			return result;
		}
		if (tag === 0) {
			offset += 1;
			continue;
		}
		const length = datagram[offset + 1];
		if (length === undefined || offset + 2 + length > datagram.length) {
			return { ...result, problem: "truncated-tag" };
		}
		const value = datagram.subarray(offset + 2, offset + 2 + length);
		result.tags.push({
			tag,
			name: name(TZSP_TAGS, tag, "tag"),
			hex: toHex(value),
		});
		offset += 2 + length;
	}
	return { ...result, problem: "no-end-tag" };
}
