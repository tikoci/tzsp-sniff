/**
 * The CLI over the capture core. It owns argument parsing, rendering and the
 * exit code; it never touches `process` itself, so tests run it in process
 * with their own sinks and signal (`bin.ts` wires the real ones).
 *
 * Exit codes: 0 done (also an empty capture, which carries a warning), 1 the
 * capture failed or `--expect` was not met, 2 a usage error, 130 interrupted
 * before the sockets were bound (no header, no summary; `bin.ts` also exits
 * 130 on a second Ctrl-C). 130 is the shell's code for SIGINT, so a caller
 * cannot mistake a capture that never started for an empty one.
 */
import { isIP } from "node:net";
import {
	type CaptureOptions,
	type CaptureStream,
	openCapture,
} from "../capture.ts";
import { TzspSniffError } from "../errors.ts";
import { fileSink } from "../file.ts";
import {
	createFilter,
	type FilterSpec,
	type FilterTerms,
	senderAddress,
} from "../filter.ts";
import type { ListenerSpec } from "../listen.ts";
import { pcapngWriter } from "../pcapng.ts";
import {
	DETAILS,
	type Detail,
	ENTRY_FIELDS,
	SUMMARY_FIELDS,
	selectFields,
	type TipRecord,
} from "../records.ts";
import { TZSP_PORT } from "../tzsp.ts";
import { VERSION } from "../version.ts";
import {
	COMMANDS,
	FIELD_NAMES,
	FLAGS,
	type FlagSpec,
	type ParsedArgs,
	parseArgs,
	wantsHelp,
} from "./flags.ts";
import {
	entryText,
	errorText,
	fieldsText,
	headerText,
	noticeText,
	summaryText,
} from "./text.ts";

/** Where output goes. `write` resolves once the data is accepted, and rejects when the reader is gone. */
export interface Sink {
	write(data: string | Uint8Array): Promise<void>;
}

export interface Io {
	stdout: Sink;
	stderr: Sink;
	/** stdout is a terminal: `--format pcapng` is refused there. */
	stdoutTerminal?: boolean;
	/** Interrupt: ends the capture as `interrupted`, with the summary written. */
	signal?: AbortSignal;
}

/** The stdout reader went away (a closed pipe): stop quietly. */
export class OutputClosedError extends Error {
	constructor(options?: ErrorOptions) {
		super("stdout was closed", options);
		this.name = "OutputClosedError";
	}
}

export const DEFAULT_DURATION_MS = 10_000;
/** A listener label on the command line: --port's, and so --sender's. */
const LABEL = /^[A-Za-z0-9._-]+$/;
/**
 * No `json`: a capture is a stream, and a document would hold every record
 * until the end (DESIGN.md, "Decided: JSONL, no `--format json`").
 */
const FORMATS = ["text", "jsonl", "pcapng"] as const;
type Format = (typeof FORMATS)[number];

export function helpText(): string {
	const lines = (flags: FlagSpec[]) =>
		flags.map((f) => {
			const left = `  --${f.name}${f.value ? ` ${f.value}` : ""}`;
			return `${left}\n      ${f.help}`;
		});
	const negated = FLAGS.filter((f) => f.negated);
	return [
		"tzsp-sniff: receive the TZSP streams RouterOS sends (/tool/sniffer streaming,",
		"mangle action=sniff-tzsp) on a plain UDP port, with no root, and decode them.",
		"",
		"Usage: tzsp-sniff [listen] [flags]",
		"",
		"Commands:",
		...Object.entries(COMMANDS).map(
			([name, text]) => `  ${name.padEnd(8)}${text}`,
		),
		"",
		"Flags:",
		...lines(FLAGS.filter((f) => !f.filter)),
		"",
		"Filters keep packets. Repeat a flag, or give a comma list, to OR its values;",
		"different flags AND. They apply to frames, not to control or invalid TZSP",
		"records, and removed frames are counted as filtered in the summary.",
		...lines(FLAGS.filter((f) => f.filter && !f.negated)),
		"  --not-<filter> <value>",
		`      Each filter has a --not- form that removes the packets it would keep: ${negated.map((f) => `--${f.name}`).join(", ")}. A packet without the field (no ports on an ARP frame, a later IP fragment, a header cut short) matches no filter and is not removed by a --not- one.`,
		"",
		"Output: stdout is the result. In text format the start line, warnings, tips and",
		"the summary go to stderr, except that with --stats the summary is the result.",
		"Every JSONL stream starts with a header record and ends with one summary",
		"record; a stream without a summary was cut off. jq reads it as it is, and",
		"`jq -s .` makes it one array.",
		"",
		"Exit: 0 done (also when nothing arrived: a warning says why), 1 the capture",
		"failed or --expect was not met, 2 a usage error, 130 interrupted before the",
		"capture started, or a second Ctrl-C (no summary).",
		"",
		"Examples:",
		"  tzsp-sniff --count 10",
		"  tzsp-sniff --duration 30s --stats",
		"  tzsp-sniff --proto tcp --not-port-match 22 --format jsonl --fields seq,src,dst,flags",
		"  tzsp-sniff --port 37008=router-a --port 37009=router-b --format jsonl --follow",
		"  tzsp-sniff --duration 30s --write capture.pcapng --stats",
		"  tzsp-sniff --proto icmp --format pcapng --follow | tshark -r -",
		"",
		"On the router (RouterOS 7), toward this host:",
		`  /tool/sniffer/set streaming-enabled=yes streaming-server=<this host>:${TZSP_PORT}`,
		"  /tool/sniffer/start",
		"A quickchr CHR reaches the host at 10.0.2.2. With filter-stream=no (the",
		"default) and a sniffer filter that matches UDP, the sniffer also captures its",
		"own stream; set filter-stream=yes, or filter on this side.",
		"",
	].join("\n");
}

const invalid = (flag: string, message: string, fix: string) =>
	new TzspSniffError("cli/invalid-value", `--${flag} ${message}`, fix);

function positiveInt(flag: string, text: string): number {
	if (
		!/^[0-9]+$/.test(text) ||
		Number(text) < 1 ||
		!Number.isSafeInteger(Number(text))
	) {
		throw invalid(
			flag,
			`must be a whole number above 0, not ${JSON.stringify(text)}.`,
			`Give it as --${flag} 10.`,
		);
	}
	return Number(text);
}

const UNITS: Record<string, number> = {
	ms: 1,
	s: 1000,
	m: 60_000,
	h: 3_600_000,
};

function duration(flag: string, text: string): number {
	const m = /^([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)?$/.exec(text);
	const ms = m ? Math.round(Number(m[1]) * (UNITS[m[2] ?? "s"] ?? 1000)) : 0;
	if (!m || ms < 1 || ms > 2_147_483_647) {
		throw invalid(
			flag,
			`must be a time such as 30s, 500ms, 2m or 1h, not ${JSON.stringify(text)}.`,
			`Give it as --${flag} 30s; a bare number is seconds.`,
		);
	}
	return ms;
}

function choice<T extends string>(
	flag: string,
	text: string,
	choices: readonly T[],
): T {
	if (!(choices as readonly string[]).includes(text)) {
		throw invalid(
			flag,
			`must be one of ${choices.join(", ")}, not ${JSON.stringify(text)}.`,
			`Give it as --${flag} ${choices[0]}.`,
		);
	}
	return text as T;
}

function ports(texts: readonly string[] | undefined): ListenerSpec[] {
	if (!texts) return [{ port: TZSP_PORT }];
	const specs: ListenerSpec[] = [];
	const seen = new Set<string>();
	for (const text of texts) {
		const m = new RegExp(
			`^([0-9]{1,5})(?:=(${LABEL.source.slice(1, -1)}))?$`,
		).exec(text);
		const port = Number(m?.[1]);
		if (!m || port > 65535) {
			throw invalid(
				"port",
				`must be a UDP port, optionally with =<label> (letters, digits, . _ -), not ${JSON.stringify(text)}.`,
				"Give it as --port 37008 or --port 37008=router-a.",
			);
		}
		for (const key of [
			port === 0 ? "" : `port ${port}`,
			m[2] ? `label ${m[2]}` : "",
		]) {
			if (key && seen.has(key)) {
				throw invalid(
					"port",
					`gives ${key} twice.`,
					"Give each port and each label once: one port per router.",
				);
			}
			seen.add(key);
		}
		specs.push(m[2] ? { port, label: m[2] } : { port });
	}
	return specs;
}

interface Plan {
	options: CaptureOptions;
	format: Format;
	tips: TipRecord[];
	/** `--fields`, when given. */
	fields?: string[];
	/** `--write`, when given. */
	write?: { path: string; overwrite: boolean };
}

/** Values of a repeatable flag, each split on commas. */
const listOf = (texts: readonly string[] | undefined) =>
	(texts ?? []).flatMap((t) => t.split(",")).map((t) => t.trim());

/** The filter spec the filter flags give; createFilter checks it. */
function filterSpec(args: ParsedArgs): FilterSpec {
	const spec: FilterSpec = {};
	const not: FilterTerms = {};
	for (const flag of FLAGS) {
		if (!flag.filter || !args.flags.has(flag.name)) continue;
		const values = listOf(args.flags.get(flag.name));
		(flag.negated ? not : spec)[flag.filter] = values;
	}
	if (Object.keys(not).length) spec.not = not;
	return spec;
}

/**
 * `--fields`, checked: each name must be a field the output can carry, and
 * without --detail the detail is raised to the least that carries them.
 */
function checkFields(
	text: string,
	format: Format,
	stats: boolean,
	detail: Detail,
	detailGiven: boolean,
): { fields: string[]; detail: Detail } {
	const fields = [...new Set(listOf([text]))];
	// The fields of the records --fields shapes in this output: with --stats
	// the summary; in text, packet and record lines (the summary is on stderr,
	// unshaped); in jsonl, both.
	const entry = Object.keys(ENTRY_FIELDS);
	const known: readonly string[] = [
		"type",
		...(stats ? SUMMARY_FIELDS : format === "text" ? entry : FIELD_NAMES),
	];
	const unknown = fields.filter((f) => !known.includes(f));
	if (unknown.length || !fields.length) {
		const where = stats
			? "a --stats summary"
			: format === "text"
				? "a text packet or record line"
				: "any record";
		const summaryOnly =
			!stats &&
			format === "text" &&
			unknown.some((f) => FIELD_NAMES.includes(f));
		// --stats prints only the summary: it suits a list of summary fields,
		// and jsonl keeps a list that mixes in packet ones.
		const entryNamed = fields.some((f) => f !== "type" && entry.includes(f));
		const recovery = entryNamed
			? " Summary fields next to packet fields need --format jsonl."
			: " Summary fields need --stats or --format jsonl.";
		throw invalid(
			"fields",
			unknown.length
				? `names ${unknown.map((f) => JSON.stringify(f)).join(", ")}, which ${where} does not have.`
				: "needs at least one field.",
			`Fields here: ${known.slice(1).join(", ")}.${summaryOnly ? recovery : ""}`,
		);
	}
	const rank = (d: Detail) => DETAILS.indexOf(d);
	let needed: Detail = DETAILS[0];
	let neededBy = "";
	for (const field of fields) {
		const d = (ENTRY_FIELDS as Record<string, Detail | undefined>)[field];
		if (d && rank(d) > rank(needed)) {
			needed = d;
			neededBy = field;
		}
	}
	if (rank(needed) <= rank(detail)) return { fields, detail };
	if (detailGiven) {
		throw new TzspSniffError(
			"cli/flag-conflict",
			`--fields ${neededBy} needs --detail ${needed} or more, and --detail is ${detail}.`,
			`Drop --detail, and --fields picks it, or give --detail ${needed}.`,
		);
	}
	return { fields, detail: needed };
}

/** Turn parsed flags into capture options, refusing what cannot apply. */
export function plan(args: ParsedArgs): Plan {
	const one = (name: string) => args.flags.get(name)?.[0];
	const has = (name: string) => args.flags.has(name);
	const formatText = one("format") ?? "text";
	if (formatText === "json") {
		throw invalid(
			"format",
			"does not take json: a capture is a stream, and jsonl carries the same records, one per line.",
			"Use --format jsonl; jq reads it, and `jq -s .` makes one array.",
		);
	}
	const format = choice("format", formatText, FORMATS);
	if (format === "pcapng") {
		// A capture file has no detail, fields or summary to choose: refused,
		// not ignored (tikoci-cli-mcp, "Refuse, never drop").
		for (const flag of ["fields", "stats", "detail"]) {
			if (!has(flag)) continue;
			throw new TzspSniffError(
				"cli/flag-conflict",
				`--${flag} does not apply to --format pcapng, which writes each datagram whole.`,
				flag === "stats"
					? "Drop --format pcapng and keep --stats, and add --write <file> to save the datagrams too."
					: `Drop --${flag}, or use --format jsonl or text for it, and --write <file> to save the datagrams too.`,
			);
		}
	}
	const writePath = one("write");
	if (writePath !== undefined && (writePath === "" || writePath === "-")) {
		throw invalid(
			"write",
			`must be a file path, not ${JSON.stringify(writePath)}.`,
			writePath === "-"
				? "To write pcapng to stdout, use --format pcapng."
				: "Give it as --write capture.pcapng.",
		);
	}
	if (has("overwrite") && writePath === undefined) {
		throw new TzspSniffError(
			"cli/flag-conflict",
			"--overwrite applies only with --write.",
			"Add --write <file>, or drop --overwrite.",
		);
	}
	const detailText = one("detail");
	let detail: Detail =
		detailText !== undefined
			? choice("detail", detailText, DETAILS)
			: format === "text"
				? "line"
				: "summary";
	const fieldsText = one("fields");
	let fields: string[] | undefined;
	if (fieldsText !== undefined) {
		({ fields, detail } = checkFields(
			fieldsText,
			format,
			has("stats"),
			detail,
			detailText !== undefined,
		));
	}
	const options: CaptureOptions = {
		ports: ports(args.flags.get("port")),
		detail,
	};
	const filter = filterSpec(args);
	// A label from --port has this grammar, so a sender that is neither one
	// nor an address is a typo, refused here; the library takes any label.
	for (const [flag, values] of [
		["sender", filter.sender],
		["not-sender", filter.not?.sender],
	] as const) {
		for (const value of values ?? []) {
			if (!LABEL.test(value) && !senderAddress(value)) {
				throw new TzspSniffError(
					"filter/invalid-value",
					`--${flag} ${JSON.stringify(value)} is not a listener label or a peer address.`,
					`Give a label from --port <port>=<label>, an address such as --${flag} 10.0.2.15, or an address and port such as --${flag} 10.0.2.15:37008.`,
				);
			}
		}
	}
	// Checked here, so a bad value is a usage error (exit 2) before any bind.
	if (createFilter(filter).flags.length) options.filter = filter;
	const bind = one("bind");
	if (bind !== undefined) {
		if (isIP(bind) === 0) {
			throw invalid(
				"bind",
				`must be an IP address, not ${JSON.stringify(bind)}.`,
				"Use 0.0.0.0, ::, or one of the host's addresses.",
			);
		}
		options.bind = bind;
	}
	const count = one("count");
	if (count !== undefined) options.count = positiveInt("count", count);
	const durationText = one("duration");
	if (durationText !== undefined)
		options.durationMs = duration("duration", durationText);
	const idle = one("idle");
	if (idle !== undefined) options.idleMs = duration("idle", idle);
	const expect = one("expect");
	if (expect !== undefined) options.expect = positiveInt("expect", expect);
	if (has("stats")) options.stats = true;

	if (
		options.expect !== undefined &&
		options.count !== undefined &&
		options.expect > options.count
	) {
		throw new TzspSniffError(
			"cli/flag-conflict",
			`--expect ${options.expect} can never be met with --count ${options.count}.`,
			"Make --count at least --expect, or drop --count.",
		);
	}
	const tips: TipRecord[] = [];
	if (
		!has("follow") &&
		options.count === undefined &&
		options.durationMs === undefined &&
		options.idleMs === undefined
	) {
		options.durationMs = DEFAULT_DURATION_MS;
		tips.push({
			type: "tip",
			code: "tip/default-duration",
			message: `No limit given, so this stops after ${DEFAULT_DURATION_MS / 1000}s: set one with --duration, --count or --idle, or run until Ctrl-C with --follow.`,
		});
	}
	return {
		options,
		format,
		tips,
		...(fields ? { fields } : {}),
		...(writePath !== undefined
			? { write: { path: writePath, overwrite: has("overwrite") } }
			: {}),
	};
}

/** Run the CLI; resolves to the exit code. */
export async function main(argv: readonly string[], io: Io): Promise<number> {
	try {
		return await run(argv, io);
	} catch (error) {
		if (error instanceof OutputClosedError) return 0;
		// stdout failed or stalled: say so where it can still be read.
		if (error instanceof TzspSniffError && error.code.startsWith("output/")) {
			await io.stderr.write(errorText(error));
			return 1;
		}
		throw error;
	}
}

async function run(argv: readonly string[], io: Io): Promise<number> {
	if (wantsHelp(argv)) {
		await io.stdout.write(helpText());
		return 0;
	}
	let planned: Plan | "version";
	try {
		const args = parseArgs(argv);
		// Plan even for --version, so a flag it would refuse is refused here
		// too; only --help comes first, so a broken command can still ask.
		const checked = plan(args);
		if (checked.format === "pcapng" && io.stdoutTerminal) {
			throw new TzspSniffError(
				"cli/binary-to-terminal",
				"--format pcapng writes a binary capture file, and stdout is a terminal.",
				"Redirect it (> capture.pcapng), pipe it (| tshark -r -), or use --write capture.pcapng with a text format.",
			);
		}
		planned = args.flags.has("version") ? "version" : checked;
	} catch (error) {
		if (!(error instanceof TzspSniffError)) throw error;
		await io.stderr.write(errorText(error));
		return 2;
	}
	// Outside the usage catch: a failed write is an output error (exit 1), not a usage one.
	if (planned === "version") {
		await io.stdout.write(`${VERSION}\n`);
		return 0;
	}
	const { options, format, tips, fields, write } = planned;
	if (io.signal) options.signal = io.signal;
	if (write) {
		options.write = pcapngWriter(
			fileSink(write.path, { overwrite: write.overwrite }),
			{ target: write.path },
		);
	}
	if (format === "pcapng") {
		// stdout's sink times itself out (output/stalled) and tells a closed
		// pipe apart, so the writer adds no timer of its own.
		options.writeReported = pcapngWriter(
			{ write: (chunk) => io.stdout.write(chunk) },
			{ target: "stdout", stallMs: 0 },
		);
	}

	let stream: Awaited<ReturnType<typeof openCapture>>;
	try {
		stream = await openCapture(options);
	} catch (error) {
		if (error instanceof TzspSniffError) {
			await io.stderr.write(errorText(error));
			return 1;
		}
		// Interrupted before the sockets were bound: nothing was captured.
		if (io.signal?.aborted) return 130;
		throw error;
	}
	try {
		return await print(
			stream,
			{ format, tips, statsOnly: options.stats ?? false, fields },
			io,
		);
	} finally {
		// Exit means released, however the loop ended (an output error too):
		// the ports can be bound again once this returns.
		await stream.listener.closed;
	}
}

/** Render the stream in `format`; resolves to the exit code. */
async function print(
	stream: CaptureStream,
	how: {
		format: Format;
		tips: TipRecord[];
		statsOnly: boolean;
		fields: string[] | undefined;
	},
	io: Io,
): Promise<number> {
	const { format, tips, statsOnly, fields } = how;
	const showListener = stream.header.listeners.length > 1;
	let exitCode = 0;

	for await (const record of stream) {
		if (record.type === "summary" && record.status === "error") exitCode = 1;
		if (
			format === "pcapng" &&
			(record.type === "packet" || record.type === "record")
		) {
			// The capture writes these to stdout itself.
			continue;
		}
		if (format === "jsonl") {
			const shaped = fields ? selectFields(record, fields) : record;
			await io.stdout.write(`${JSON.stringify(shaped)}\n`);
			if (record.type === "header") {
				for (const tip of tips)
					await io.stdout.write(`${JSON.stringify(tip)}\n`);
			}
			continue;
		}
		switch (record.type) {
			case "header":
				await io.stderr.write(headerText(record));
				for (const tip of tips) await io.stderr.write(noticeText(tip));
				break;
			case "packet":
			case "record":
				await io.stdout.write(
					fields
						? fieldsText(selectFields(record, fields))
						: entryText(record, showListener),
				);
				break;
			case "warning":
			case "tip":
				await io.stderr.write(noticeText(record));
				break;
			case "summary":
				// --fields shapes the result: the summary only when it is the result.
				await (statsOnly ? io.stdout : io.stderr).write(
					statsOnly && fields
						? fieldsText(selectFields(record, fields))
						: summaryText(record),
				);
				if (record.error) await io.stderr.write(errorText(record.error));
				break;
		}
	}
	return exitCode;
}
