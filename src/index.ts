/**
 * @tikoci/tzsp-sniff library entry point. The library never prints or exits
 * (tikoci-cli-mcp); a CLI, when it exists, is an adapter over these exports.
 */
export {
	parseTzsp,
	TZSP_ENCAPSULATIONS,
	TZSP_PORT,
	TZSP_TAGS,
	TZSP_TYPES,
	TZSP_MAX_TAGS,
	type TzspDatagram,
	type TzspInvalidReason,
	type TzspKind,
	type TzspProblem,
	type TzspReason,
	type TzspRecordBase,
	type TzspTag,
	type TzspUnsupportedReason,
	toHex,
} from "./tzsp.ts";
