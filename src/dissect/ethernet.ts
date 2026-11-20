import {
	type FieldDecls,
	type Frame,
	fieldInfo,
	formatMac,
	type LayerBase,
	type Registration,
	u16,
} from "./core.ts";

export interface EthernetFields {
	dst: string;
	src: string;
	/** `0x0800` style, when the type/length field is an EtherType (≥ 0x0600). */
	etherType?: string;
	/** An IEEE 802.3 length (≤ 1500): the frame carries LLC, not decoded here. */
	length?: number;
}

export type EthernetLayer = LayerBase<"ethernet", EthernetFields>;

// IEEE 802.3: destination, source, type/length.
function ethernet(f: Frame, start: number, end: number) {
	const b = f.b;
	if (end - start < 14) {
		f.layers.push({
			protocol: "ethernet",
			offset: start,
			length: end - start,
			problem: "truncated",
			reason: "header",
		});
		return;
	}
	const layer: EthernetLayer = {
		protocol: "ethernet",
		offset: start,
		length: end - start,
		fields: { dst: formatMac(b, start), src: formatMac(b, start + 6) },
	};
	f.layers.push(layer);
	f.typeLength(layer, u16(b, start + 12), start + 14, end, 0);
}

const FIELDS: FieldDecls<EthernetFields> = {
	dst: { type: "string", description: "Destination MAC address." },
	src: { type: "string", description: "Source MAC address." },
	etherType: {
		type: "string",
		optional: true,
		description:
			"The EtherType, as 0x0800, when the type/length field is one (0x0600 and up).",
	},
	length: {
		type: "number",
		optional: true,
		description:
			"An IEEE 802.3 length (1500 and below): LLC follows, not decoded here.",
	},
};

export const ETHERNET: Registration = {
	protocol: "ethernet",
	name: "Ethernet II and IEEE 802.3",
	reference: "IEEE 802.3",
	matches: [{ link: "ethernet", dissect: ethernet }],
	fields: fieldInfo(FIELDS),
};
