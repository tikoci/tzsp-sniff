/**
 * The CLI's one flag registry (DESIGN.md, "Requirement, flags"): each flag's
 * arity, the commands it applies to and the flags it conflicts with. The
 * parser and `--help` both read it, and `test/unit/cli.test.ts` holds them in
 * step.
 */
import { TzspSniffError } from "../errors.ts";
import { FILTER_KEYS, type FilterKey, filterFlag } from "../filter.ts";
import { ENTRY_FIELDS, SUMMARY_FIELDS } from "../records.ts";

export const COMMANDS = {
	listen:
		"Receive and print, until a limit is met or, with --follow, until interrupted. The default command.",
	decode:
		"Read a capture file (pcapng or pcap, detected) or hex lines (--input hex), or stdin as -, and print it as listen does. No network.",
	dissectors:
		"List the protocols this tool decodes: how each is matched (link, EtherType, IP protocol) and the fields its layer carries. No network, no input.",
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
	/** A filter flag: the spec term it sets. */
	filter?: FilterKey;
	/** A `--not-` filter flag: help lists these together. */
	negated?: boolean;
}

const BOTH = ["listen", "decode"] as const;
const ALL = ["listen", "decode", "dissectors"] as const;

/** What each filter flag keeps; `--src-` and `--dst-` forms fix the direction. */
const FILTER_HELP: Record<FilterKey, { value: string; help: string }> = {
	proto: {
		value: "<name>",
		help: "Keep packets with this protocol in their chain, or named by their IP header: tcp, udp, icmp, icmpv6, arp, ipv4, ipv6, vlan, gre, ospf, vrrp …",
	},
	host: {
		value: "<address>",
		help: "Keep packets to or from this IPv4 or IPv6 address (in the IP header, or ARP's sender and target).",
	},
	srcHost: { value: "<address>", help: "As --host, the source only." },
	dstHost: { value: "<address>", help: "As --host, the destination only." },
	net: {
		value: "<prefix>",
		help: "Keep packets to or from an address in this prefix, such as 10.0.0.0/8 or 2001:db8::/32.",
	},
	srcNet: { value: "<prefix>", help: "As --net, the source only." },
	dstNet: { value: "<prefix>", help: "As --net, the destination only." },
	portMatch: {
		value: "<port>",
		help: "Keep packets to or from this UDP or TCP port (--port is the port to listen on).",
	},
	srcPortMatch: { value: "<port>", help: "As --port-match, the source only." },
	dstPortMatch: {
		value: "<port>",
		help: "As --port-match, the destination only.",
	},
	mac: {
		value: "<mac>",
		help: "Keep frames to or from this Ethernet address, such as 02:00:00:00:00:0a.",
	},
	srcMac: { value: "<mac>", help: "As --mac, the source only." },
	dstMac: { value: "<mac>", help: "As --mac, the destination only." },
	etherType: {
		value: "<0xNNNN>",
		help: "Keep frames with this EtherType in the Ethernet header or a VLAN tag, such as 0x0800 or 0x88cc.",
	},
	sender: {
		value: "<label|address[:port]>",
		help: "Keep packets from this sender: a listener label from --port, or the UDP peer's address, or address:port. Never a field inside the packet.",
	},
};

const filterFlags = (negated: boolean): FlagSpec[] =>
	FILTER_KEYS.map((key) => ({
		name: `${negated ? "not-" : ""}${filterFlag(key)}`,
		value: FILTER_HELP[key].value,
		repeatable: true,
		commands: BOTH,
		help: negated
			? `Remove the packets --${filterFlag(key)} would keep.`
			: FILTER_HELP[key].help,
		filter: key,
		...(negated ? { negated } : {}),
	}));

/** Every field --fields can name, packets and records first, then the summary's. */
export const FIELD_NAMES: readonly string[] = [
	...new Set([...Object.keys(ENTRY_FIELDS), ...SUMMARY_FIELDS]),
];

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
		commands: BOTH,
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
		commands: BOTH,
		help: "Exit 1 with capture/expect-unmet when fewer than <n> packets are reported, also after Ctrl-C.",
	},
	{
		name: "format",
		value: "text|jsonl|pcapng",
		commands: ALL,
		help: "text (default): a line per packet or record on stdout; the start line, warnings, tips and the summary on stderr (the summary on stdout with --stats). jsonl: a JSON record per line, header first, summary last; jq reads it, and `jq -s .` makes one array. With dissectors, text or jsonl: one record per protocol, and no header or summary. pcapng (listen only): the datagrams the filters keep, as a capture file on stdout (as --write saves them), for a pipe or a redirect, not a terminal; everything else on stderr. --fields, --stats and --detail do not apply to it.",
	},
	{
		name: "write",
		value: "<file>",
		commands: ["listen"],
		help: "Also save every datagram the capture reads, as received, to <file>, a pcapng capture with link type TZSP: before filters, whatever --format, --detail and --stats print (the summary's dropped and unread count what was never read). The file is new and owner-only, and not the file stdout or stderr goes to; the summary says what was written. Read it again with Wireshark or TShark.",
	},
	{
		name: "overwrite",
		commands: ["listen"],
		help: "Let --write replace a regular file that is already there, with a new owner-only file: a reader of the old one never sees the capture.",
	},
	{
		name: "detail",
		value: "line|summary|layers|full",
		commands: BOTH,
		conflicts: ["stats"],
		help: "How much each packet carries: line (text's default), summary (adds addresses, ports, protocols, flags; jsonl's default), layers (adds every layer's fields), full (adds the datagram as hex).",
	},
	{
		name: "stats",
		commands: BOTH,
		conflicts: ["detail"],
		help: "Print only the summary, to stdout: counters, protocols, senders and conversations.",
	},
	{
		name: "fields",
		value: "<a,b,…>",
		commands: BOTH,
		help: `Only these fields of each packet and record, and of the summary in jsonl or with --stats, in this order; type, and a summary's status, always stay. In text, the record's type comes first and the fields follow as key=value, in this order; layers, tags and datagram take lines of their own where they are named. Without --detail, the detail is the least that carries them. Fields: ${FIELD_NAMES.join(", ")}.`,
	},
	{
		name: "input",
		value: "pcapng|pcap|hex",
		commands: ["decode"],
		help: "The input's format. Default: detected from its first bytes, pcapng or pcap. hex, one TZSP datagram per line (blank lines and # comments skipped), is never guessed.",
	},
	{
		name: "tzsp-port",
		value: "<port>",
		repeatable: true,
		commands: ["decode"],
		help: "In an Ethernet, raw IP or Linux cooked capture (tshark's), UDP to this port is TZSP and is unwrapped; any other Ethernet frame is decoded as captured (a file RouterOS saved). Default 37008; repeat for one port per router.",
	},
	...filterFlags(false),
	...filterFlags(true),
	{
		name: "help",
		commands: ALL,
		help: "Show this help (also -h).",
	},
	{
		name: "version",
		commands: ALL,
		help: "Print the version.",
	},
];

const BY_NAME = new Map(FLAGS.map((f) => [f.name, f]));

/**
 * Where a flag `dissectors` refused belongs, as a command that runs as
 * printed: listen's help when listen takes it, else decode's.
 */
const ownerExample = (spec: FlagSpec) =>
	spec.commands.includes("listen")
		? "To capture with it, see tzsp-sniff listen --help"
		: "To read a file with it, see tzsp-sniff decode --help";

/** Own keys only: `constructor` or `__proto__` is not a command. */
const isCommand = (name: string): name is CommandName =>
	Object.hasOwn(COMMANDS, name);

export interface ParsedArgs {
	command: CommandName;
	/** decode's file, or `-` for stdin. */
	input?: string;
	/** Flag name to its values, in order; a switch has one empty string. */
	flags: Map<string, string[]>;
}

const usage = (
	code:
		| "cli/unknown-command"
		| "cli/unknown-flag"
		| "cli/wrong-command"
		| "cli/missing-argument"
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
	let input: string | undefined;
	/** decode takes one file; anything else, or a second one, is refused. */
	const positional = (arg: string) => {
		if (command === "decode" && input === undefined) {
			input = arg;
			return;
		}
		throw usage(
			"cli/unexpected-argument",
			command === "decode"
				? `decode reads one input, and got a second: ${JSON.stringify(arg)}.`
				: `${command} takes no arguments, and got ${JSON.stringify(arg)}.`,
			command === "decode"
				? "Decode one file at a time."
				: command === "dissectors"
					? `Remove it: dissectors lists every protocol. To see one, filter the list with jq: tzsp-sniff dissectors --format jsonl | jq 'select(.protocol == "tcp")'`
					: "Remove it; to read a capture file, run tzsp-sniff decode <file>.",
		);
	};
	for (; i < argv.length; i++) {
		const arg = argv[i] as string;
		if (arg === "--") {
			for (const rest of argv.slice(i + 1)) positional(rest);
			break;
		}
		// `-` is stdin, not a flag.
		if (arg === "-" || !arg.startsWith("-")) {
			positional(arg);
			continue;
		}
		if (!arg.startsWith("--")) {
			throw usage(
				"cli/unknown-flag",
				`${arg} is not a flag; flags are long, such as --count.`,
				"Run tzsp-sniff --help for the flags.",
			);
		}
		const eq = arg.indexOf("=");
		const name = arg.slice(2, eq < 0 ? undefined : eq);
		const spec = BY_NAME.get(name);
		if (spec && !spec.commands.includes(command)) {
			// Refused, not dropped, and named: an agent learns where it belongs.
			const owners = spec.commands.join(" and ");
			throw usage(
				"cli/wrong-command",
				`--${name} is a flag of ${owners}, not ${command}.`,
				command === "decode"
					? `Drop it: decode reads a file to its end, with no network. To capture, run tzsp-sniff listen --${name}.`
					: command === "dissectors"
						? `Drop it: dissectors lists the protocols and reads no packets. ${ownerExample(spec)}`
						: `Drop it, or run tzsp-sniff ${owners} --${name}.`,
			);
		}
		if (!spec) {
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
	if (command === "decode" && input === undefined && !flags.has("version")) {
		throw usage(
			"cli/missing-argument",
			"decode needs an input: a capture file, or - for stdin.",
			"Give it as tzsp-sniff decode capture.pcapng, or pipe into tzsp-sniff decode -.",
		);
	}
	return input === undefined ? { command, flags } : { command, flags, input };
}
