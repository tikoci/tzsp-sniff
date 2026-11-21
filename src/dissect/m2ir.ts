/**
 * m2ir's facts behind the fields generated from it: the RouterOS versions
 * each was seen on, since when, and each named value's and bit's own scope
 * (DESIGN.md, "Decided: MNDP from the m2ir table"). `dissectors()` carries
 * only a field's `confidence`; this is the rest, for a caller who asks.
 * m2ir is the source of truth: this is its snapshot in vendor/m2ir.
 */
import type { FieldConfidence } from "./core.ts";
import {
	M2IR_COMMIT,
	M2IR_REPOSITORY,
	MNDP_M2IR_FACTS,
	MNDP_M2IR_FILES,
	MNDP_UNNAMED,
	MNDP_VERSIONS_OBSERVED,
} from "./mndp-table.ts";

/** A named value of an enum, or a named bit of a bitmask (`value` is its mask). */
export interface M2irValueFacts {
	value: number;
	name: string;
	confidence: FieldConfidence;
	versionsSeen: string[];
}

/** m2ir's scope for one field a protocol's layer has. */
export interface M2irFieldFacts {
	/** The field, as records and `dissectors()` name it. */
	field: string;
	/** The TLV it is read from; absent for a field read from the header. */
	tlv?: number;
	/** m2ir's name for it. */
	name: string;
	confidence: FieldConfidence;
	/**
	 * The RouterOS versions m2ir saw it on, oldest first. Not seen elsewhere
	 * is not the same as not sent: m2ir lists what its samples covered.
	 */
	versionsSeen: string[];
	/** Whose versions those are: the senders', or the routers that answered it. */
	versionsSeenOf: "sender" | "receiver";
	/** The first version m2ir saw sending it, when older ones did not. */
	since?: string;
	/** The release whose changelog adds it. */
	introduced?: string;
	/** An enum's named values, each with its own scope. */
	values?: M2irValueFacts[];
	/** A bitmask's named bits, each with its own scope. */
	bits?: M2irValueFacts[];
}

/** m2ir's facts for one protocol generated from it. */
export interface M2irFacts {
	/** The layer's `protocol`, as `dissectors()` lists it. */
	protocol: string;
	/** The m2ir repository and commit the table is generated from. */
	repository: string;
	commit: string;
	/** The m2ir files read. */
	files: string[];
	/** Every RouterOS version m2ir observed the protocol on. */
	versionsObserved: string[];
	fields: M2irFieldFacts[];
	/** Entries m2ir has that are left unnamed for their confidence, so their bytes stay raw. */
	unnamed: string[];
}

const copyValues = (vs: readonly M2irValueFacts[]) =>
	vs.map((v) => ({ ...v, versionsSeen: [...v.versionsSeen] }));

/** m2ir's facts for each protocol generated from it. A new copy each call. */
export function m2irFacts(): M2irFacts[] {
	return [
		{
			protocol: "mndp",
			repository: M2IR_REPOSITORY,
			commit: M2IR_COMMIT,
			files: [...MNDP_M2IR_FILES],
			versionsObserved: [...MNDP_VERSIONS_OBSERVED],
			fields: MNDP_M2IR_FACTS.map((f) => ({
				...f,
				versionsSeen: [...f.versionsSeen],
				...(f.values ? { values: copyValues(f.values) } : {}),
				...(f.bits ? { bits: copyValues(f.bits) } : {}),
			})),
			unnamed: [...MNDP_UNNAMED],
		},
	];
}
