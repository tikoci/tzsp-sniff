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
 * The tags and payload follow every type except keepalive (4) and port-opener
 * (5): `dissect_tzsp` reads options and the encapsulated frame only when the
 * type is neither (packet-tzsp.c e0929ac4, the `TZSP_NULL`/`TZSP_PORT` check).
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

/**
 * The most tags (other than pad and end) one datagram may carry before the
 * parser stops reading it (DESIGN.md, "Dissectors": caps on work per packet).
 * Wireshark has no such cap; RouterOS has been seen to send none at all.
 */
export const TZSP_MAX_TAGS = 64;

/**
 * What a record is, so a caller can count records apart and dissect only
 * frames (DESIGN.md, "Decided: dispatch on record type and encapsulation").
 *
 * - `packet`: type 0 (received) with encapsulation 1 (Ethernet). `payload` is
 *   an Ethernet frame, the only record to dissect.
 * - `control`: a keepalive (4) or port-opener (5). No tags, no payload.
 * - `unsupported`: valid TZSP, but another type or encapsulation, or more
 *   tags than {@link TZSP_MAX_TAGS}; never dissected as a frame.
 * - `invalid`: the datagram is truncated or malformed.
 */
export type TzspKind = "packet" | "control" | "unsupported" | "invalid";

/**
 * What went wrong, in the three classes every parser in this package uses
 * (DESIGN.md, "Requirement, bytes in and records out"):
 *
 * - `truncated`: the bytes end early.
 * - `malformed`: a field contradicts the format.
 * - `unsupported`: valid, not decoded here.
 */
export type TzspProblem = "truncated" | "malformed" | "unsupported";

/** Which check made a record `invalid`. */
export type TzspInvalidReason =
	| "too-short" // truncated: fewer than 4 header bytes
	| "bad-version" // malformed: version is not 1
	| "no-end-tag" // truncated: the tag list runs off the end
	| "truncated-tag"; // truncated: a tag's length byte or value runs past the end

/** Which check made a record `unsupported`. */
export type TzspUnsupportedReason =
	| "record-type" // a type other than received, keepalive or port-opener
	| "encapsulation" // a received record that is not Ethernet
	| "tag-limit"; // more than TZSP_MAX_TAGS tags; the rest is not read

/** Which check set `problem`, finer than {@link TzspProblem}. */
export type TzspReason = TzspInvalidReason | TzspUnsupportedReason;

/** The fields every record has, whatever its kind. */
export interface TzspRecordBase {
	/**
	 * The complete datagram: the input array itself, not a copy, so it shares
	 * memory with the caller's buffer. Kept whatever the kind or problem, so
	 * no bytes are lost; copy it to keep it past a reused buffer.
	 */
	datagram: Uint8Array;
	version: number;
	type: number;
	/** A name from {@link TZSP_TYPES}, or `type-<n>`. */
	typeName: string;
	encapsulation: number;
	/** A name from {@link TZSP_ENCAPSULATIONS}, or `encap-<n>`. */
	encapsulationName: string;
	/** Every tag except pad and end, in order; those read before a problem, if any. */
	tags: TzspTag[];
	/**
	 * The inner frame after the end tag, a view into `datagram`'s memory. Set
	 * whenever the end tag was reached: for a `packet`, and for an `unsupported`
	 * record of another type or encapsulation. Empty otherwise.
	 */
	payload: Uint8Array;
}

/**
 * One parsed datagram. `kind` decides the rest: `packet` and `control` have
 * no `problem` or `reason`; `unsupported` and `invalid` always have both, in
 * the pairs below. Dispatch on `kind`, not on whether `payload` is empty.
 */
export type TzspDatagram =
	| (TzspRecordBase & {
			kind: "packet" | "control";
			problem?: never;
			reason?: never;
	  })
	| (TzspRecordBase & {
			kind: "unsupported";
			problem: "unsupported";
			reason: TzspUnsupportedReason;
	  })
	| (TzspRecordBase & {
			kind: "invalid";
			problem: "truncated";
			reason: Exclude<TzspInvalidReason, "bad-version">;
	  })
	| (TzspRecordBase & {
			kind: "invalid";
			problem: "malformed";
			reason: "bad-version";
	  });

const name = (table: Record<number, string>, value: number, prefix: string) =>
	table[value] ?? `${prefix}-${value}`;

export const toHex = (bytes: Uint8Array): string =>
	Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * A plain `Uint8Array` over `bytes[start..end)`, sharing its memory. Built with
 * the base constructor rather than `subarray()`, which calls a subclass's
 * constructor and can throw for a valid `Uint8Array` subclass.
 */
const view = (bytes: Uint8Array, start: number, end: number) =>
	new Uint8Array(bytes.buffer, bytes.byteOffset + start, end - start);

/**
 * Parse one TZSP datagram (a UDP payload). Never throws: a datagram it cannot
 * read comes back with `kind`, `problem` and `reason` set, and its bytes in
 * `datagram`.
 */
export function parseTzsp(datagram: Uint8Array): TzspDatagram {
	const version = datagram[0] ?? 0;
	const type = datagram[1] ?? 0;
	const encapsulation =
		datagram.length >= 4
			? ((datagram[2] as number) << 8) | (datagram[3] as number)
			: 0;
	const base: TzspRecordBase = {
		datagram,
		version,
		type,
		typeName: name(TZSP_TYPES, type, "type"),
		encapsulation,
		encapsulationName: name(TZSP_ENCAPSULATIONS, encapsulation, "encap"),
		tags: [],
		payload: new Uint8Array(0),
	};
	const truncated = (
		reason: Exclude<TzspInvalidReason, "bad-version">,
	): TzspDatagram => ({
		...base,
		kind: "invalid",
		problem: "truncated",
		reason,
	});
	const unsupported = (reason: TzspUnsupportedReason): TzspDatagram => ({
		...base,
		kind: "unsupported",
		problem: "unsupported",
		reason,
	});

	if (datagram.length < 4) return truncated("too-short");
	if (version !== 1) {
		return {
			...base,
			kind: "invalid",
			problem: "malformed",
			reason: "bad-version",
		};
	}
	// packet-tzsp.c (e0929ac4, dissect_tzsp) reads no tags or encapsulated
	// frame for keepalive and port-opener; bytes after the header stay in
	// `datagram` and are not read.
	if (type === 4 || type === 5) return { ...base, kind: "control" };

	// Every other type has the tag list (same check), so its structure is
	// validated before the type or encapsulation is judged.
	let offset = 4;
	while (offset < datagram.length) {
		const tag = datagram[offset] as number;
		if (tag === 1) {
			base.payload = view(datagram, offset + 1, datagram.length);
			if (type !== 0) return unsupported("record-type");
			if (encapsulation !== 1) return unsupported("encapsulation");
			return { ...base, kind: "packet" };
		}
		if (tag === 0) {
			offset += 1;
			continue;
		}
		if (base.tags.length === TZSP_MAX_TAGS) return unsupported("tag-limit");
		const length = datagram[offset + 1];
		if (length === undefined || offset + 2 + length > datagram.length) {
			return truncated("truncated-tag");
		}
		base.tags.push({
			tag,
			name: name(TZSP_TAGS, tag, "tag"),
			hex: toHex(view(datagram, offset + 2, offset + 2 + length)),
		});
		offset += 2 + length;
	}
	return truncated("no-end-tag");
}
