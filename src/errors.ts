/**
 * Every error, warning and tip code this package emits, in one registry
 * (tikoci-cli-mcp, "Errors"). `test/unit/codes.test.ts` fails on a code used
 * in `src/` that is not here, and on one here that nothing uses. A code that
 * shipped keeps its meaning.
 */
export const CODES = {
	"listen/invalid-option": {
		kind: "error",
		summary: "A listen() option is out of range or contradicts another.",
	},
	"listen/bind-failed": {
		kind: "error",
		summary: "A listener could not bind its UDP port; no socket stays open.",
	},
	"listen/socket-error": {
		kind: "error",
		summary: "A bound UDP socket failed; the capture ended.",
	},
	"summary/invalid-option": {
		kind: "error",
		summary: "A summarize() option is not a whole number of 0 or more.",
	},
	"capture/expect-unmet": {
		kind: "error",
		summary: "Fewer packets were reported than --expect asked for.",
	},
	"capture/reused": {
		kind: "error",
		summary: "A capture stream was iterated a second time; it is read once.",
	},
	"filter/invalid-value": {
		kind: "error",
		summary: "A filter term is unknown, or a value is not one it accepts.",
	},
	"output/stalled": {
		kind: "error",
		summary:
			"stdout took no data for too long; the capture ended rather than wait.",
	},
	"output/failed": {
		kind: "error",
		summary: "Writing to stdout failed (not a reader that went away).",
	},
	"write/invalid-option": {
		kind: "error",
		summary:
			"A pcapng writer option is out of range, or the writer was used out of order.",
	},
	"write/exists": {
		kind: "error",
		summary:
			"The --write file already exists; it is replaced only with --overwrite.",
	},
	"write/failed": {
		kind: "error",
		summary:
			"Creating, writing or closing the capture file failed; the capture ended.",
	},
	"write/stalled": {
		kind: "error",
		summary:
			"The capture file's sink took no data for too long; the capture ended rather than wait.",
	},
	"cli/unknown-command": {
		kind: "error",
		summary: "The first argument is not a command.",
	},
	"cli/unknown-flag": {
		kind: "error",
		summary: "A flag the command does not have.",
	},
	"cli/missing-value": {
		kind: "error",
		summary: "A flag that takes a value was given none.",
	},
	"cli/invalid-value": {
		kind: "error",
		summary: "A flag's value is not one it accepts.",
	},
	"cli/repeated-flag": {
		kind: "error",
		summary: "A flag that takes one value was given two different ones.",
	},
	"cli/flag-conflict": {
		kind: "error",
		summary: "Two flags that cannot be used together.",
	},
	"cli/unexpected-argument": {
		kind: "error",
		summary: "A positional argument the command does not take.",
	},
	"cli/write-to-output": {
		kind: "error",
		summary:
			"--write names the file stdout or stderr already goes to; the two would overwrite each other.",
	},
	"cli/binary-to-terminal": {
		kind: "error",
		summary: "--format pcapng would write binary to a terminal.",
	},
	"capture/dropped": {
		kind: "warning",
		summary:
			"The queue between the sockets and the output was full; datagrams were dropped.",
	},
	"capture/no-datagrams": {
		kind: "warning",
		summary: "Nothing arrived on any listener.",
	},
	"capture/unread": {
		kind: "warning",
		summary: "Datagrams arrived, but the capture stopped before reading any.",
	},
	"capture/no-frames": {
		kind: "warning",
		summary:
			"Only control, unsupported or invalid TZSP records arrived; no frames.",
	},
	"capture/all-filtered": {
		kind: "warning",
		summary: "Frames arrived, and the filters removed every one of them.",
	},
	"tip/default-duration": {
		kind: "tip",
		summary:
			"No limit was given, so listen stopped after the default duration.",
	},
} as const satisfies Record<
	string,
	{ kind: "error" | "warning" | "tip"; summary: string }
>;

export type Code = keyof typeof CODES;
type CodeOfKind<K> = {
	[C in Code]: (typeof CODES)[C]["kind"] extends K ? C : never;
}[Code];
export type ErrorCode = CodeOfKind<"error">;
export type WarningCode = CodeOfKind<"warning">;
export type TipCode = CodeOfKind<"tip">;

/**
 * The one error class the library throws. `message` says what failed, `fix`
 * the next step; a system error behind it rides in `cause`.
 */
export class TzspSniffError extends Error {
	readonly code: ErrorCode;
	readonly fix: string | undefined;

	constructor(
		code: ErrorCode,
		message: string,
		fix?: string,
		options?: ErrorOptions,
	) {
		super(message, options);
		this.name = "TzspSniffError";
		this.code = code;
		this.fix = fix;
	}
}
