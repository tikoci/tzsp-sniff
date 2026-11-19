/**
 * The CLI's one flag registry (DESIGN.md, "Requirement, flags"): each flag's
 * arity, the commands it applies to and the flags it conflicts with. The
 * parser and `--help` both read it, and `test/unit/cli.test.ts` holds them in
 * step.
 */
import { TzspSniffError } from "../errors.ts";

export const COMMANDS = {
	listen:
		"Receive and print, until a limit is met or, with --follow, until interrupted. The default command.",
} as const;
export type CommandName = keyof typeof COMMANDS;

export interface FlagSpec {
	name: string;
	/** The value's placeholder in help; a flag without one is a switch. */
	value?: string;
	repeatable?: boolean;
	commands: readonly CommandName[];
	conflicts?: readonly string[];
	help: string;
}

export const FLAGS: readonly FlagSpec[] = [
	{
		name: "port",
		value: "<port>[=<label>]",
		repeatable: true,
		commands: ["listen"],
		help: "UDP port to listen on, and a label for the router that sends to it. Repeat for one port per router. Default 37008; 0 takes any free port (the header says which).",
	},
	{
		name: "bind",
		value: "<address>",
		commands: ["listen"],
		help: "Local address to bind: 0.0.0.0 (default, every IPv4 address), :: for IPv6, or one of the host's addresses.",
	},
	{
		name: "count",
		value: "<n>",
		commands: ["listen"],
		conflicts: ["follow"],
		help: "Stop after <n> packets are reported.",
	},
	{
		name: "duration",
		value: "<time>",
		commands: ["listen"],
		conflicts: ["follow"],
		help: "Stop after <time>, such as 30s, 500ms, 2m or 1h; a bare number is seconds. With no limit at all, listen stops after 10s.",
	},
	{
		name: "idle",
		value: "<time>",
		commands: ["listen"],
		conflicts: ["follow"],
		help: "Stop when nothing has arrived for <time>: the clock starts when the ports are bound and restarts with each datagram.",
	},
	{
		name: "follow",
		commands: ["listen"],
		conflicts: ["count", "duration", "idle"],
		help: "Run until interrupted (Ctrl-C, SIGTERM). The summary still prints.",
	},
	{
		name: "expect",
		value: "<n>",
		commands: ["listen"],
		help: "Exit 1 with capture/expect-unmet when fewer than <n> packets are reported, also after Ctrl-C.",
	},
	{
		name: "format",
		value: "text|jsonl",
		commands: ["listen"],
		help: "text (default): a line per packet or record on stdout; the start line, warnings, tips and the summary on stderr (the summary on stdout with --stats). jsonl: a JSON record per line, header first, summary last; jq reads it, and `jq -s .` makes one array.",
	},
	{
		name: "detail",
		value: "line|summary|layers|full",
		commands: ["listen"],
		conflicts: ["stats"],
		help: "How much each packet carries: line (text's default), summary (adds addresses, ports, protocols, flags; jsonl's default), layers (adds every layer's fields), full (adds the datagram as hex).",
	},
	{
		name: "stats",
		commands: ["listen"],
		conflicts: ["detail"],
		help: "Print only the summary, to stdout: counters, protocols, senders and conversations.",
	},
	{
		name: "help",
		commands: ["listen"],
		help: "Show this help (also -h).",
	},
	{
		name: "version",
		commands: ["listen"],
		help: "Print the version.",
	},
];

const BY_NAME = new Map(FLAGS.map((f) => [f.name, f]));

/** Own keys only: `constructor` or `__proto__` is not a command. */
const isCommand = (name: string): name is CommandName =>
	Object.hasOwn(COMMANDS, name);

export interface ParsedArgs {
	command: CommandName;
	/** Flag name to its values, in order; a switch has one empty string. */
	flags: Map<string, string[]>;
}

const usage = (
	code:
		| "cli/unknown-command"
		| "cli/unknown-flag"
		| "cli/missing-value"
		| "cli/invalid-value"
		| "cli/repeated-flag"
		| "cli/flag-conflict"
		| "cli/unexpected-argument",
	message: string,
	fix: string,
) => new TzspSniffError(code, message, fix);

/** The command `--help` asks about, or undefined when it is not asked for. Stops at `--`. */
export function wantsHelp(
	argv: readonly string[],
): { command?: CommandName } | undefined {
	for (const arg of argv) {
		if (arg === "--") return undefined;
		if (arg === "--help" || arg === "-h") {
			const first = argv[0];
			return first && isCommand(first) ? { command: first } : {};
		}
	}
	return undefined;
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
	let i = 0;
	let command: CommandName = "listen";
	const first = argv[0];
	if (first !== undefined && !first.startsWith("-")) {
		if (!isCommand(first)) {
			throw usage(
				"cli/unknown-command",
				`"${first}" is not a command.`,
				`Commands: ${Object.keys(COMMANDS).join(", ")}; run tzsp-sniff --help.`,
			);
		}
		command = first;
		i = 1;
	}
	const flags = new Map<string, string[]>();
	for (; i < argv.length; i++) {
		const arg = argv[i] as string;
		if (arg === "--") {
			const rest = argv.slice(i + 1);
			if (rest.length) {
				throw usage(
					"cli/unexpected-argument",
					`${command} takes no arguments, and got ${JSON.stringify(rest[0])}.`,
					"Remove it; run tzsp-sniff --help for the flags.",
				);
			}
			break;
		}
		if (!arg.startsWith("--")) {
			throw usage(
				arg.startsWith("-") ? "cli/unknown-flag" : "cli/unexpected-argument",
				arg.startsWith("-")
					? `${arg} is not a flag; flags are long, such as --count.`
					: `${command} takes no arguments, and got ${JSON.stringify(arg)}.`,
				"Run tzsp-sniff --help for the flags.",
			);
		}
		const eq = arg.indexOf("=");
		const name = arg.slice(2, eq < 0 ? undefined : eq);
		const spec = BY_NAME.get(name);
		if (!spec?.commands.includes(command)) {
			throw usage(
				"cli/unknown-flag",
				`--${name} is not a flag of ${command}.`,
				"Run tzsp-sniff --help for the flags.",
			);
		}
		let value = "";
		if (spec.value) {
			if (eq >= 0) value = arg.slice(eq + 1);
			else {
				const next = argv[i + 1];
				if (next === undefined || next.startsWith("--")) {
					throw usage(
						"cli/missing-value",
						`--${name} needs a value: ${spec.value}.`,
						`Give it as --${name} <value> or --${name}=<value>.`,
					);
				}
				value = next;
				i += 1;
			}
		} else if (eq >= 0) {
			throw usage(
				"cli/invalid-value",
				`--${name} takes no value.`,
				`Give it as --${name} alone.`,
			);
		}
		const values = flags.get(name);
		if (!values) flags.set(name, [value]);
		else if (spec.repeatable) values.push(value);
		else if (values[0] !== value) {
			throw usage(
				"cli/repeated-flag",
				`--${name} is given twice, as ${JSON.stringify(values[0])} and ${JSON.stringify(value)}.`,
				`Give --${name} once.`,
			);
		}
	}
	for (const name of flags.keys()) {
		for (const other of BY_NAME.get(name)?.conflicts ?? []) {
			if (flags.has(other)) {
				throw usage(
					"cli/flag-conflict",
					`--${name} and --${other} cannot be used together.`,
					name === "follow" || other === "follow"
						? "--follow runs until interrupted; drop it to stop at a limit, or drop the limit."
						: `Keep one of --${name} and --${other}.`,
				);
			}
		}
	}
	return { command, flags };
}
