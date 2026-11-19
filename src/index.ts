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
	type TzspDatagram,
	type TzspProblem,
	type TzspTag,
	toHex,
} from "./tzsp.ts";
