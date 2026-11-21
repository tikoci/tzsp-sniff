/**
 * MNDP, the MikroTik Neighbor Discovery Protocol, on UDP 5678: a 4-byte
 * header, then TLVs (a big-endian type and length, then the value) to the
 * end of the datagram.
 *
 * The TLV names, value encodings, lengths and named values are not written
 * here: they come from `mndp-table.ts`, generated from m2ir's
 * physical/mndp.yaml and profiles/mndp/profile.yaml by scripts/m2ir.ts
 * (DESIGN.md, "Tables from m2ir, not by hand"). This file reads a datagram
 * with that table. What RouterOS sends is in test/lab/mndp/REPORT.md.
 */
import {
	type FieldDecls,
	type Frame,
	fieldInfo,
	type IpContext,
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
import {
	M2IR_COMMIT,
	MNDP_HEADER_ORDERS,
	MNDP_HEADER_CONFIDENCE,
	MNDP_PORT,
	MNDP_REQUEST,
	MNDP_REQUEST_CONFIDENCE,
	MNDP_TLV_FIELDS,
	MNDP_TLVS,
	type MndpTlvFields,
	type MndpTlvSpec,
} from "./mndp-table.ts";

export type { MndpTlvFields } from "./mndp-table.ts";

/** The most TLVs read; bytes after the last are `unsupported` (`tlv-limit`). RouterOS sent 13 to 17 in the lab (test/lab/mndp/REPORT.md). */
export const MAX_MNDP_TLVS = 64;

export interface MndpOtherTlv {
	type: number;
	/** m2ir's name, for a type the table names (a repeat, or a wrong length). */
	name?: string;
	length: number;
	/** The value as hex. */
	value: string;
}

export interface MndpFields extends MndpTlvFields {
	/** The 4-byte header as hex, in the order sent. */
	header: string;
	/** The header read little-endian: the announcement counter from x86_64, arm and arm64 senders. */
	counterLe: number;
	/** The header read big-endian: the announcement counter from a mipsbe sender. */
	counterBe: number;
	/** The datagram asks routers to announce now, by m2ir's request rule. */
	request: boolean;
	/** Every TLV not read into a field above, in the order sent. */
	otherTlvs: MndpOtherTlv[];
}

export type MndpLayer = LayerBase<"mndp", MndpFields>;

const BY_TYPE = new Map<number, MndpTlvSpec>(MNDP_TLVS.map((s) => [s.type, s]));

// As LLDP and DHCP: UTF-8 checked, a leading byte-order mark kept.
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const LENIENT = new TextDecoder("utf-8", { ignoreBOM: true });

/** A plain Uint8Array over `b`'s memory (see lldp.ts). */
const view = (b: Uint8Array, start: number, end: number) =>
	new Uint8Array(b.buffer, b.byteOffset + start, end - start);

const u32le = (b: Uint8Array, o: number) =>
	(u8(b, o) |
		(u8(b, o + 1) << 8) |
		(u8(b, o + 2) << 16) |
		(u8(b, o + 3) << 24)) >>>
	0;

// m2ir physical/mndp.yaml: a 4-byte header, then u16be type, u16be length
// and the value, repeated to the end of the UDP payload.
function mndp(
	f: Frame,
	start: number,
	end: number,
	_ip: IpContext,
	complete: boolean,
) {
	const b = f.b;
	const available = end - start;
	if (available < 4) {
		f.layers.push({
			protocol: "mndp",
			offset: start,
			length: available,
			problem: "truncated",
			reason: "header",
		});
		return;
	}
	// The layer runs to the end of the datagram: every byte is MNDP's.
	const layer: MndpLayer = {
		protocol: "mndp",
		offset: start,
		length: available,
	};
	f.layers.push(layer);
	const mark = (
		problem: "truncated" | "malformed" | "unsupported",
		reason: string,
	) => {
		layer.problem ??= problem;
		layer.reason ??= reason;
	};
	const counterBe = u32(b, start);
	const tlvs: MndpTlvFields = {};
	const set = tlvs as Record<string, unknown>;
	const otherTlvs: MndpOtherTlv[] = [];
	/** Types read into a field: a second one of a type that does not repeat is kept raw. */
	const read = new Set<number>();
	/** Each type's value lengths, for the request rule. */
	const lengths = new Map<number, number[]>();

	let offset = start + 4;
	let count = 0;
	// The TLVs end exactly at the datagram's end (m2ir framing-rule). Where
	// the capture ended inside the datagram, its end is not known.
	let framed = complete;
	while (offset < end) {
		if (count === MAX_MNDP_TLVS) {
			mark("unsupported", "tlv-limit");
			framed = false;
			break;
		}
		if (offset + 4 > end || offset + 4 + u16(b, offset + 2) > end) {
			mark("truncated", "tlv");
			framed = false;
			break;
		}
		const type = u16(b, offset);
		const length = u16(b, offset + 2);
		const value = view(b, offset + 4, offset + 4 + length);
		lengths.set(type, [...(lengths.get(type) ?? []), length]);
		tlv(type, value);
		count++;
		offset += 4 + length;
	}

	const request =
		framed &&
		(MNDP_REQUEST.headers.includes(counterBe) ||
			MNDP_REQUEST.tlvs.some((r) =>
				(lengths.get(r.type) ?? []).some((n) => r.lengths.includes(n)),
			));
	layer.fields = {
		header: hex(b, start, start + 4),
		counterLe: u32le(b, start),
		counterBe,
		request,
		...tlvs,
		otherTlvs,
	};

	function other(type: number, value: Uint8Array, spec?: MndpTlvSpec) {
		const o: MndpOtherTlv = {
			type,
			length: value.length,
			value: hex(value, 0, value.length),
		};
		if (spec) o.name = spec.name;
		otherTlvs.push(o);
	}

	function tlv(type: number, value: Uint8Array) {
		const spec = BY_TYPE.get(type);
		if (!spec) return other(type, value);
		// A wrong length is malformed whether or not the type came before.
		if (spec.length !== "any" && value.length !== spec.length) {
			mark("malformed", "tlv-length");
			return other(type, value, spec);
		}
		if (!spec.repeat && read.has(type)) return other(type, value, spec);
		read.add(type);
		const field = spec.field;
		switch (spec.encoding) {
			case "empty":
				set[field] = true;
				break;
			case "u8": {
				const n = u8(value, 0);
				set[field] = n;
				const name = spec.values?.find((v) => v.value === n)?.name;
				if (name !== undefined) set[`${field}Name`] = name;
				break;
			}
			case "bitmask-u8": {
				const n = u8(value, 0);
				set[field] = n;
				const names: string[] = [];
				for (let bit = 1; bit < 0x100; bit <<= 1) {
					if ((n & bit) === 0) continue;
					names.push(
						spec.bits?.find((x) => x.mask === bit)?.name ??
							`bit-0x${bit.toString(16).padStart(2, "0")}`,
					);
				}
				set[`${field}Flags`] = names;
				break;
			}
			case "u32le":
				set[field] = u32le(value, 0);
				break;
			case "mac48":
				set[field] = formatMac(value);
				break;
			case "ipv4":
				set[field] = formatIpv4(value);
				break;
			case "ipv6":
				put(formatIpv6(value));
				break;
			case "text":
				put(text(value));
				break;
			case "bytes":
				put(hex(value, 0, value.length));
				break;
		}

		/** A string field, or one more item of a repeated one. */
		function put(s: string) {
			if (!spec?.repeat) set[field] = s;
			else
				set[field] = [
					...(Object.hasOwn(set, field) ? (set[field] as string[]) : []),
					s,
				];
		}
	}

	function text(value: Uint8Array): string {
		try {
			return UTF8.decode(value);
		} catch {
			mark("malformed", "text");
			return LENIENT.decode(value);
		}
	}
}

const FIELDS: FieldDecls<MndpFields> = {
	header: {
		type: "string",
		description: `The 4-byte header as hex, in the order sent. It is an announcement counter in the sender's CPU byte order (m2ir: ${MNDP_HEADER_ORDERS}), which a receiver cannot know; zero on a request and on a router's first announcement after boot. A datagram under 4 bytes is truncated (header) and has no fields.`,
		confidence: MNDP_HEADER_CONFIDENCE,
	},
	counterLe: {
		type: "number",
		description:
			"The header read little-endian: the announcement counter, when the sender is x86_64, arm or arm64.",
		confidence: MNDP_HEADER_CONFIDENCE,
	},
	counterBe: {
		type: "number",
		description:
			"The header read big-endian: the announcement counter, when the sender is mipsbe.",
		confidence: MNDP_HEADER_CONFIDENCE,
	},
	request: {
		type: "boolean",
		description: `The datagram asks every router on the segment to announce now, by m2ir's request rule: its TLVs end at its end, and its header is zero or it carries an empty TLV 6. A router's first announcement after boot has a zero header, so it is a request too. False when a TLV runs past the datagram, the TLV limit stops the reading, or the capture ended inside the datagram (its end is then unknown).`,
		confidence: MNDP_REQUEST_CONFIDENCE,
	},
	...MNDP_TLV_FIELDS,
	otherTlvs: {
		type: "object[]",
		description: `Every TLV not read into a field, in the order sent: a type the m2ir table does not name, a second one of a type that does not repeat, and one whose length is wrong for its type (malformed, tlv-length). A TLV past the datagram is truncated (tlv) and not listed. Reading stops after ${MAX_MNDP_TLVS} TLVs: bytes after the last make the layer unsupported (tlv-limit), unless an earlier TLV already gave it a problem (the first is the one reported); exactly ${MAX_MNDP_TLVS} TLVs are read in full.`,
		items: {
			type: { type: "number", description: "The TLV type." },
			name: {
				type: "string",
				optional: true,
				description: "m2ir's name, for a type the table names.",
			},
			length: { type: "number", description: "The value's length in bytes." },
			value: { type: "string", description: "The value as hex." },
		},
	},
};

export const MNDP: Registration = {
	protocol: "mndp",
	name: "MNDP",
	reference: `m2ir profiles/mndp/profile.yaml at ${M2IR_COMMIT.slice(0, 7)}`,
	matches: [{ udpPort: MNDP_PORT, dissect: mndp }],
	fields: fieldInfo(FIELDS),
};
