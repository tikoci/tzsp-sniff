// cspell:ignore QinQ DEI
import {
	type FieldDecls,
	type Frame,
	fieldInfo,
	type LayerBase,
	type Registration,
	u16,
} from "./core.ts";

/** The most VLAN tags read from one frame; one more is `unsupported`. */
export const MAX_VLAN_TAGS = 4;

export interface VlanFields {
	priority: number;
	dei: boolean;
	id: number;
	/** The inner EtherType, as in {@link EthernetFields}. */
	etherType?: string;
	/** An inner IEEE 802.3 length: LLC follows, not decoded here. */
	length?: number;
}

export type VlanLayer = LayerBase<"vlan", VlanFields>;

// IEEE 802.1Q tag after the outer EtherType: TCI (PCP 3, DEI 1, VID 12), inner type.
function vlan(f: Frame, start: number, end: number, vlans: number) {
	if (vlans >= MAX_VLAN_TAGS) {
		f.layers.push({
			protocol: "vlan",
			offset: start,
			length: end - start,
			problem: "unsupported",
			reason: "tag-limit",
		});
		return;
	}
	if (end - start < 4) {
		f.layers.push({
			protocol: "vlan",
			offset: start,
			length: end - start,
			problem: "truncated",
			reason: "header",
		});
		return;
	}
	const tci = u16(f.b, start);
	const layer: VlanLayer = {
		protocol: "vlan",
		offset: start,
		length: end - start,
		fields: {
			priority: tci >> 13,
			dei: (tci & 0x1000) !== 0,
			id: tci & 0x0fff,
		},
	};
	f.layers.push(layer);
	f.typeLength(layer, u16(f.b, start + 2), start + 4, end, vlans + 1);
}

const FIELDS: FieldDecls<VlanFields> = {
	priority: {
		type: "number",
		description: "Priority code point (PCP), 0 to 7.",
	},
	dei: { type: "boolean", description: "Drop eligible indicator (DEI)." },
	id: { type: "number", description: "VLAN id, 0 to 4095." },
	etherType: {
		type: "string",
		optional: true,
		description: "The inner EtherType, as 0x0800, when the tag carries one.",
	},
	length: {
		type: "number",
		optional: true,
		description: "An inner IEEE 802.3 length: LLC follows, not decoded here.",
	},
};

export const VLAN: Registration = {
	protocol: "vlan",
	name: "IEEE 802.1Q VLAN tag, and the 802.1ad outer tag",
	reference: "IEEE 802.1Q",
	matches: [
		{ etherType: 0x8100, dissect: vlan },
		{ etherType: 0x88a8, dissect: vlan },
	],
	fields: fieldInfo(FIELDS),
};
