import { afterAll, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { COMMANDS, FLAGS, parseArgs, wantsHelp } from "../../src/cli/flags.ts";
import { entryText } from "../../src/cli/text.ts";
import {
	DEFAULT_DURATION_MS,
	helpText,
	type Io,
	main,
	OutputClosedError,
	plan,
} from "../../src/cli/main.ts";
import { dissectors } from "../../src/dissect.ts";
import { TzspSniffError } from "../../src/errors.ts";
import { filterFlags } from "../../src/filter.ts";
import { VERSION } from "../../src/version.ts";
import {
	closeSocket,
	expectPortFree,
	fixture,
	holdPort,
	send,
	until,
} from "./helpers.ts";
import { readPcapng } from "./pcapng-reader.ts";
import type { ByteSink } from "../../src/pcapng.ts";

const STREAM = fixture("7.25.1-x86-sniffer-stream");
const REQUEST = STREAM[0] as string;

const codeOf = (fn: () => unknown): string | undefined => {
	try {
		fn();
	} catch (error) {
		if (error instanceof TzspSniffError) return error.code;
		throw error;
	}
	return undefined;
};

/** Sinks that record what was written; `stdoutFailsAfter` simulates a reader that went away. */
function memoryIo(
	options: {
		stdoutFailsAfter?: number;
		signal?: AbortSignal;
		stdoutTerminal?: boolean;
	} = {},
) {
	const out: string[] = [];
	const err: string[] = [];
	/** Binary writes to stdout (--format pcapng), in order. */
	const bin: Uint8Array[] = [];
	const io: Io = {
		stdout: {
			async write(data) {
				if (
					options.stdoutFailsAfter !== undefined &&
					out.length + bin.length >= options.stdoutFailsAfter
				) {
					throw new OutputClosedError();
				}
				if (typeof data === "string") out.push(data);
				else bin.push(data);
			},
		},
		stderr: {
			async write(data) {
				err.push(String(data));
			},
		},
	};
	if (options.signal) io.signal = options.signal;
	if (options.stdoutTerminal) io.stdoutTerminal = true;
	return {
		io,
		out,
		err,
		bin,
		stdout: () => out.join(""),
		stderr: () => err.join(""),
		stdoutBytes: () => Buffer.concat(bin),
	};
}

/** The bound port, from the JSONL header or the text start line. */
const boundPort = (text: string) => {
	const m = /"port":(\d+)|0\.0\.0\.0:(\d+)/.exec(text);
	return Number(m?.[1] ?? m?.[2]);
};

describe("flags and help", () => {
	test("--help and -h are answered before dispatch, and not after --", () => {
		expect(wantsHelp(["--help"])).toEqual({});
		expect(wantsHelp(["--count", "x", "-h"])).toEqual({});
		expect(wantsHelp(["listen", "--help"])).toEqual({ command: "listen" });
		expect(wantsHelp(["--", "--help"])).toBeUndefined();
		expect(wantsHelp(["--count", "3"])).toBeUndefined();
	});

	test("help lists every flag with its value and every command, from the registry", () => {
		const help = helpText();
		for (const flag of FLAGS) {
			// The --not- forms are listed together, by name.
			if (flag.negated) {
				expect(help).toMatch(new RegExp(` --${flag.name}[,.]`));
				expect(flag.value).toBe(
					FLAGS.find((f) => f.name === flag.name.slice(4))?.value,
				);
				continue;
			}
			expect(help).toContain(
				`  --${flag.name}${flag.value ? ` ${flag.value}` : ""}\n`,
			);
			expect(help).toContain(flag.help);
		}
		for (const name of Object.keys(COMMANDS))
			expect(help).toContain(`  ${name}`);
	});

	test("every flag the CLI reads is in the registry", () => {
		const source = readFileSync(
			join(import.meta.dir, "../../src/cli/main.ts"),
			"utf8",
		);
		const read = [
			...source.matchAll(
				/(?:one|has)\("([a-z-]+)"\)|flags\.(?:get|has)\("([a-z-]+)"\)/g,
			),
		].map((m) => m[1] ?? m[2]);
		expect(read.length).toBeGreaterThan(5);
		const names = new Set(FLAGS.map((f) => f.name));
		for (const name of read)
			expect({ name, known: names.has(name as string) }).toEqual({
				name,
				known: true,
			});
	});

	test("conflicts are declared on both sides", () => {
		for (const flag of FLAGS) {
			for (const other of flag.conflicts ?? []) {
				expect({
					flag: flag.name,
					other,
					back: FLAGS.find((f) => f.name === other)?.conflicts,
				}).toMatchObject({
					back: expect.arrayContaining([flag.name]),
				});
			}
		}
	});

	test("parses commands, values in both spellings, repeats and --", () => {
		expect(parseArgs([]).command).toBe("listen");
		const a = parseArgs([
			"listen",
			"--port",
			"1=a",
			"--port=2",
			"--count=3",
			"--stats",
			"--",
		]);
		expect(a.flags.get("port")).toEqual(["1=a", "2"]);
		expect(a.flags.get("count")).toEqual(["3"]);
		expect(a.flags.get("stats")).toEqual([""]);
		expect(parseArgs(["decode", "x.pcapng", "--count", "1"])).toMatchObject({
			command: "decode",
			input: "x.pcapng",
		});
		expect(parseArgs(["decode", "-"]).input).toBe("-");
		// After --, a name that looks like a flag is the input.
		expect(parseArgs(["decode", "--", "--odd"]).input).toBe("--odd");
		expect(parseArgs(["decode", "--version"]).input).toBeUndefined();
		// The same value twice is a no-op.
		expect(parseArgs(["--count", "3", "--count=3"]).flags.get("count")).toEqual(
			["3"],
		);
	});

	test("refuses what it cannot apply, each with its own code", () => {
		const cases: [string[], string][] = [
			[["--nope"], "cli/unknown-flag"],
			[["-c", "3"], "cli/unknown-flag"],
			[["--count"], "cli/missing-value"],
			[["--count", "--follow"], "cli/missing-value"],
			[["--follow=yes"], "cli/invalid-value"],
			[["--count", "3", "--count", "4"], "cli/repeated-flag"],
			[["--follow", "--count", "3"], "cli/flag-conflict"],
			[["--duration", "5s", "--follow"], "cli/flag-conflict"],
			[["--stats", "--detail", "full"], "cli/flag-conflict"],
			[["stray"], "cli/unknown-command"],
			[["listen", "stray"], "cli/unexpected-argument"],
			[["--", "stray"], "cli/unexpected-argument"],
			// Own registry keys only, not inherited names.
			[["constructor"], "cli/unknown-command"],
			[["__proto__"], "cli/unknown-command"],
			// decode: one input, and no flag of listen.
			[["decode"], "cli/missing-argument"],
			[["decode", "--count", "1"], "cli/missing-argument"],
			[["decode", "a.pcapng", "b.pcapng"], "cli/unexpected-argument"],
			[["decode", "a.pcapng", "--", "b"], "cli/unexpected-argument"],
			[["decode", "a.pcapng", "--follow"], "cli/wrong-command"],
			[["decode", "a.pcapng", "--port", "1"], "cli/wrong-command"],
			[["decode", "-", "--write", "x.pcapng"], "cli/wrong-command"],
			[["decode", "-", "--duration=5s"], "cli/wrong-command"],
			[["--input", "hex"], "cli/wrong-command"],
			[["listen", "--tzsp-port", "1"], "cli/wrong-command"],
			[["-"], "cli/unexpected-argument"],
			// dissectors: no input, and no capture flag.
			[["dissectors", "tcp"], "cli/unexpected-argument"],
			[["dissectors", "--count", "1"], "cli/wrong-command"],
			[["dissectors", "--fields", "protocol"], "cli/wrong-command"],
			[["dissectors", "--proto", "tcp"], "cli/wrong-command"],
			[["dissectors", "--detail", "full"], "cli/wrong-command"],
		];
		for (const [argv, code] of cases) {
			expect({ argv, code: codeOf(() => parseArgs(argv)) }).toEqual({
				argv,
				code,
			});
		}
	});
});

describe("dissectors", () => {
	test("text: a block per protocol, its matches, then a line per field", async () => {
		const m = memoryIo();
		expect(await main(["dissectors"], m.io)).toBe(0);
		expect(m.stderr()).toBe("");
		const text = m.stdout();
		for (const d of dissectors()) {
			expect(text).toContain(`${d.protocol}: ${d.name} (${d.reference})\n`);
			for (const f of d.fields)
				expect(text).toContain(`  ${f.name} (${f.type}`);
		}
		expect(text).toContain(
			"vlan: IEEE 802.1Q VLAN tag, and the 802.1ad outer tag (IEEE 802.1Q)\n  matched by etherType 0x8100, etherType 0x88a8\n",
		);
		expect(text).toContain("  extensions[].header (number): ");
		expect(text).toContain("  protocolName (string, optional): ");
	});

	test("jsonl: one dissector record per protocol, nothing else", async () => {
		const m = memoryIo();
		expect(await main(["dissectors", "--format", "jsonl"], m.io)).toBe(0);
		expect(m.stderr()).toBe("");
		const records = m
			.stdout()
			.trimEnd()
			.split("\n")
			.map((l) => JSON.parse(l));
		expect(records).toEqual(
			dissectors().map((d) => ({ type: "dissector", ...d })),
		);
	});

	test("json and pcapng are refused, as on listen and decode", async () => {
		for (const [format, code] of [
			["json", "cli/invalid-value"],
			["pcapng", "cli/wrong-command"],
			["xml", "cli/invalid-value"],
		]) {
			const m = memoryIo();
			expect(
				await main(["dissectors", "--format", format as string], m.io),
			).toBe(2);
			expect(m.stdout()).toBe("");
			expect(m.stderr()).toContain(`error ${code}:`);
		}
		const m = memoryIo();
		await main(["dissectors", "--format", "json"], m.io);
		expect(m.stderr()).toContain("--format jsonl");
	});

	test("--version still checks --format", async () => {
		for (const format of ["json", "pcapng", "xml"]) {
			const m = memoryIo();
			expect(
				await main(["dissectors", "--version", "--format", format], m.io),
			).toBe(2);
			expect(m.stdout()).toBe("");
		}
	});

	test("a refused flag's fix is a command that takes it, and the jq hint runs as printed", async () => {
		const fixOf = (argv: string[]) => {
			try {
				parseArgs(argv);
			} catch (error) {
				if (error instanceof TzspSniffError) return error.fix;
			}
			return undefined;
		};
		expect(fixOf(["dissectors", "--input", "hex"])).toContain(
			"run tzsp-sniff decode <file> --input pcapng|pcap|hex",
		);
		expect(fixOf(["dissectors", "--tzsp-port", "1"])).toContain(
			"run tzsp-sniff decode <file> --tzsp-port <port>",
		);
		expect(fixOf(["dissectors", "--count", "1"])).toContain(
			"run tzsp-sniff listen --count <n>",
		);
		const jq = fixOf(["dissectors", "tcp"]) ?? "";
		expect(jq).toEndWith(`jq 'select(.protocol == "tcp")'`);
	});

	test("a capture flag is refused with where it applies", async () => {
		const m = memoryIo();
		expect(await main(["dissectors", "--count", "1"], m.io)).toBe(2);
		expect(m.stderr()).toContain(
			"--count is a flag of listen and decode, not dissectors.",
		);
		expect(m.stderr()).toContain("tzsp-sniff listen --count");
	});

	test("--version and --help", async () => {
		const v = memoryIo();
		expect(await main(["dissectors", "--version"], v.io)).toBe(0);
		expect(v.stdout()).toBe(`${VERSION}\n`);
		const h = memoryIo();
		expect(await main(["dissectors", "--help"], h.io)).toBe(0);
		expect(h.stdout()).toContain("tzsp-sniff dissectors [--format text|jsonl]");
	});

	test("a closed stdout ends it quietly", async () => {
		const m = memoryIo({ stdoutFailsAfter: 0 });
		expect(await main(["dissectors"], m.io)).toBe(0);
		expect(m.stderr()).toBe("");
	});
});

describe("plan: flags to capture options", () => {
	const planOf = (argv: string[]) => plan(parseArgs(argv));

	test("no limit: the default duration, with a tip naming the limits and --follow", () => {
		const p = planOf([]);
		expect(p.format).toBe("text");
		expect(p.options).toMatchObject({
			ports: [{ port: 37008 }],
			detail: "line",
			durationMs: DEFAULT_DURATION_MS,
		});
		expect(p.tips.map((t) => t.code)).toEqual(["tip/default-duration"]);
		for (const flag of ["--duration", "--count", "--follow"])
			expect(p.tips[0]?.message).toContain(flag);
	});

	test("any limit, or --follow, means no default and no tip", () => {
		for (const argv of [
			["--follow"],
			["--count", "1"],
			["--idle", "2s"],
			["--duration", "1"],
		]) {
			const p = planOf(argv);
			expect(p.tips).toEqual([]);
		}
		expect(planOf(["--follow"]).options.durationMs).toBeUndefined();
	});

	test("json is refused whatever the limits, with a fix that names jsonl", () => {
		for (const extra of [
			[],
			["--count", "1"],
			["--duration", "5s"],
			["--follow"],
		]) {
			let caught: unknown;
			try {
				planOf(["--format", "json", ...extra]);
			} catch (error) {
				caught = error;
			}
			expect({ extra, caught }).toMatchObject({
				extra,
				caught: {
					code: "cli/invalid-value",
					fix: expect.stringContaining("--format jsonl"),
				},
			});
		}
	});

	test("jsonl defaults to summary detail", () => {
		expect(planOf(["--format", "jsonl"]).options.detail).toBe("summary");
		expect(
			planOf(["--format", "jsonl", "--detail", "line"]).options.detail,
		).toBe("line");
	});

	test("durations", () => {
		const ms = (text: string) =>
			planOf(["--duration", text]).options.durationMs;
		expect(ms("500ms")).toBe(500);
		expect(ms("1.5s")).toBe(1500);
		expect(ms("30")).toBe(30_000);
		expect(ms("2m")).toBe(120_000);
		expect(ms("1h")).toBe(3_600_000);
		for (const bad of ["0", "0.0001s", "5d", "-1", "1e3", "", "1000h"]) {
			expect({ bad, code: codeOf(() => planOf(["--duration", bad])) }).toEqual({
				bad,
				code: "cli/invalid-value",
			});
		}
	});

	test("ports and labels", () => {
		expect(
			planOf(["--port", "37008=router-a", "--port", "0", "--port", "0"]).options
				.ports,
		).toEqual([{ port: 37008, label: "router-a" }, { port: 0 }, { port: 0 }]);
		for (const bad of [
			["70000"],
			["x"],
			["1=a b"],
			["1="],
			["5", "5"],
			["1=a", "2=a"],
		]) {
			const argv = bad.flatMap((p) => ["--port", p]);
			expect({ bad, code: codeOf(() => planOf(argv)) }).toEqual({
				bad,
				code: "cli/invalid-value",
			});
		}
	});

	test("filter flags make the spec: comma lists and repeats OR, --not- excludes", () => {
		expect(planOf([]).options.filter).toBeUndefined();
		expect(
			planOf([
				"--proto",
				"tcp,udp",
				"--proto=icmp",
				"--src-port-match",
				"22",
				"--not-host",
				"10.0.0.1",
				"--sender",
				"router-a",
			]).options.filter,
		).toEqual({
			proto: ["tcp", "udp", "icmp"],
			srcPortMatch: ["22"],
			sender: ["router-a"],
			not: { host: ["10.0.0.1"] },
		});
		// The listen port and a port filter are different flags.
		expect(planOf(["--port", "0", "--port-match", "53"]).options).toMatchObject(
			{ ports: [{ port: 0 }], filter: { portMatch: ["53"] } },
		);
	});

	test("a filter value it cannot read is a usage error naming the flag", () => {
		for (const argv of [
			["--host", "router"],
			["--not-net", "10.0.0.0/40"],
			["--proto", "tcp,"],
			["--ether-type", "0800"],
		]) {
			let caught: unknown;
			try {
				planOf(argv);
			} catch (error) {
				caught = error;
			}
			expect({ argv, caught }).toMatchObject({
				argv,
				caught: {
					code: "filter/invalid-value",
					message: expect.stringContaining(argv[0] as string),
				},
			});
		}
	});

	test("--fields: the detail is the least that carries them, unless --detail is given", () => {
		const p = (argv: string[]) => planOf(argv);
		expect(p(["--fields", "seq,line"]).options.detail).toBe("line");
		expect(p(["--fields", "src,dst"]).options.detail).toBe("summary");
		expect(p(["--fields", "seq, layers"]).options.detail).toBe("layers");
		expect(p(["--fields", "datagram,seq"]).options.detail).toBe("full");
		// jsonl already carries summary fields; more is raised, less is kept.
		expect(p(["--format", "jsonl", "--fields", "seq"]).options.detail).toBe(
			"summary",
		);
		expect(p(["--fields", "src,src,dst"]).fields).toEqual(["src", "dst"]);
		expect(p(["--detail", "full", "--fields", "src"]).options.detail).toBe(
			"full",
		);
		expect(codeOf(() => p(["--detail", "summary", "--fields", "layers"]))).toBe(
			"cli/flag-conflict",
		);
		expect(codeOf(() => p(["--stats", "--fields", "counters,status"]))).toBe(
			undefined,
		);
	});

	test("--fields: a summary field needs a summary result (jsonl, or --stats)", () => {
		const fixOf = (argv: string[]) => {
			try {
				planOf(argv);
			} catch (error) {
				return error;
			}
			return undefined;
		};
		// Only summary fields: --stats or jsonl both keep them.
		expect(fixOf(["--fields", "counters,status"])).toMatchObject({
			code: "cli/invalid-value",
			fix: expect.stringContaining("need --stats or --format jsonl"),
		});
		// Mixed with a packet field, --stats would refuse seq: name jsonl only.
		const mixed = fixOf(["--fields", "seq,counters"]) as TzspSniffError;
		expect(mixed).toMatchObject({
			code: "cli/invalid-value",
			fix: expect.stringContaining("next to packet fields need --format jsonl"),
		});
		expect(String(mixed.fix).includes("--stats")).toBe(false);
		expect(
			planOf(["--format", "jsonl", "--fields", "seq,counters"]).fields,
		).toEqual(["seq", "counters"]);
		expect(planOf(["--stats", "--fields", "counters"]).fields).toEqual([
			"counters",
		]);
	});

	test("--sender on the command line is a --port label or an address", () => {
		expect(
			planOf([
				"--sender",
				"router-a,10.0.2.2,[::1]:5",
				"--not-sender",
				"1.2.3.4:9",
			]).options.filter,
		).toEqual({
			sender: ["router-a", "10.0.2.2", "[::1]:5"],
			not: { sender: ["1.2.3.4:9"] },
		});
		for (const argv of [
			["--sender", "a b"],
			["--sender", "10.0.2.2:70000"],
			["--not-sender", "[10.0.2.2]:5"],
		]) {
			expect({ argv, code: codeOf(() => planOf(argv)) }).toEqual({
				argv,
				code: "filter/invalid-value",
			});
		}
	});

	test("a printed filter flag parses back to its value, also one that looks like a flag", () => {
		for (const label of ["router-a", "--help", "-x", "10.0.2.2:5000"]) {
			const flag = filterFlags({ sender: [label] })[0] as string;
			// These are safe shell words: one argument when joined with `=`,
			// else the flag and the value.
			const argv = flag.startsWith("--sender=") ? [flag] : flag.split(" ");
			expect({ label, help: wantsHelp(argv) }).toEqual({
				label,
				help: undefined,
			});
			expect(planOf(argv).options.filter?.sender).toEqual([label]);
		}
		expect(filterFlags({ sender: ["--help"] })).toEqual(["--sender=--help"]);
	});

	test("--fields refuses a field the output never has", () => {
		for (const argv of [
			["--fields", "src,nope"],
			["--fields", ""],
			["--fields", ","],
			// --stats prints only the summary: packet fields never appear.
			["--stats", "--fields", "src"],
		]) {
			let caught: unknown;
			try {
				planOf(argv);
			} catch (error) {
				caught = error;
			}
			expect({ argv, caught }).toMatchObject({
				argv,
				caught: {
					code: "cli/invalid-value",
					fix: expect.stringContaining("Fields"),
				},
			});
		}
	});

	test("refusals", () => {
		expect(codeOf(() => planOf(["--count", "2", "--expect", "3"]))).toBe(
			"cli/flag-conflict",
		);
		expect(codeOf(() => planOf(["--bind", "localhost"]))).toBe(
			"cli/invalid-value",
		);
		expect(codeOf(() => planOf(["--format", "csv"]))).toBe("cli/invalid-value");
		expect(codeOf(() => planOf(["--detail", "all"]))).toBe("cli/invalid-value");
		expect(codeOf(() => planOf(["--detail="]))).toBe("cli/invalid-value");
		expect(codeOf(() => planOf(["--count", "0"]))).toBe("cli/invalid-value");
	});
});

describe("main", () => {
	test("--help and --version print to stdout and exit 0", async () => {
		const help = memoryIo();
		expect(await main(["--count", "nope", "--help"], help.io)).toBe(0);
		expect(help.stdout()).toBe(helpText());
		const version = memoryIo();
		expect(await main(["--version"], version.io)).toBe(0);
		expect(version.stdout()).toBe(`${VERSION}\n`);
	});

	test("--version still refuses a flag it would refuse without it", async () => {
		const m = memoryIo();
		expect(await main(["--format", "json", "--version"], m.io)).toBe(2);
		expect(m.stdout()).toBe("");
		expect(m.stderr()).toContain("error cli/invalid-value");
	});

	test("interrupted before the bind: exit 130, nothing on stdout", async () => {
		const controller = new AbortController();
		controller.abort();
		const m = memoryIo({ signal: controller.signal });
		expect(await main(["--port", "0", "--count", "1"], m.io)).toBe(130);
		expect(m.stdout()).toBe("");
	});

	test("a usage error: exit 2, the code and fix on stderr, nothing on stdout", async () => {
		const m = memoryIo();
		expect(await main(["--format", "json"], m.io)).toBe(2);
		expect(m.stdout()).toBe("");
		expect(m.stderr()).toMatch(
			/^error cli\/invalid-value: --format does not take json.*\n {2}fix: Use --format jsonl/,
		);
	});

	test("a port in use: exit 1 with listen/bind-failed", async () => {
		const held = await holdPort();
		try {
			const m = memoryIo();
			expect(
				await main(["--port", String(held.port), "--count", "1"], m.io),
			).toBe(1);
			expect(m.stderr()).toContain("error listen/bind-failed");
			expect(m.stderr()).toContain(`:${held.port}`);
		} finally {
			await closeSocket(held.socket);
		}
	});

	test("jsonl: every line is JSON, header first, tip after it, summary last", async () => {
		const m = memoryIo();
		const run = main(
			["--port", "0", "--format", "jsonl", "--idle", "200ms"],
			m.io,
		);
		await until(() => m.out.length > 0);
		await send(boundPort(m.stdout()), [REQUEST, "01040000"]);
		expect(await run).toBe(0);
		const records = m
			.stdout()
			.trimEnd()
			.split("\n")
			.map((l) => JSON.parse(l));
		expect(records.map((r) => r.type)).toEqual([
			"header",
			"packet",
			"record",
			"summary",
		]);
		expect(records[1]).toMatchObject({
			src: "10.0.2.15",
			dst: "10.0.2.3",
			protocols: ["ethernet", "ipv4", "icmp"],
		});
		expect(records.at(-1)).toMatchObject({
			status: "complete",
			stoppedBy: "idle",
		});
		expect(m.stderr()).toBe("");
	});

	test("jsonl carries the default-duration tip in the stream", async () => {
		const controller = new AbortController();
		const m = memoryIo({ signal: controller.signal });
		const run = main(["--port", "0", "--format", "jsonl"], m.io);
		await until(() => m.out.length >= 2);
		controller.abort();
		expect(await run).toBe(0);
		const types = m
			.stdout()
			.trimEnd()
			.split("\n")
			.map((l) => JSON.parse(l).type);
		expect(types.slice(0, 2)).toEqual(["header", "tip"]);
		expect(types.at(-1)).toBe("summary");
	});

	test("text: packet lines on stdout; start line, notices and summary on stderr", async () => {
		const m = memoryIo();
		const run = main(["--port", "0", "--count", "1"], m.io);
		await until(() => m.err.length > 0);
		await send(boundPort(m.stderr()), [REQUEST]);
		expect(await run).toBe(0);
		expect(m.stdout()).toMatch(
			/^\d\d:\d\d:\d\d\.\d{3} 10\.0\.2\.15 > 10\.0\.2\.3 icmp echo-request id=45568 seq=0 len=36\n$/,
		);
		expect(m.stderr()).toMatch(
			/^listening on UDP 0\.0\.0\.0:\d+, until 1 packets\n/,
		);
		expect(m.stderr()).toContain("summary: complete, stopped by count");
	});

	test("text --detail summary adds the summary fields under the line", async () => {
		const m = memoryIo();
		const run = main(
			["--port", "0", "--count", "1", "--detail", "summary"],
			m.io,
		);
		await until(() => m.err.length > 0);
		await send(boundPort(m.stderr()), [REQUEST]);
		expect(await run).toBe(0);
		const [line, fields, ...rest] = m.stdout().split("\n");
		expect(line).toMatch(/ icmp echo-request id=45568 seq=0 len=36$/);
		expect(fields).toMatch(
			/^ {2}peer=127\.0\.0\.1:\d+ length=\d+ protocols=ethernet,ipv4,icmp src=10\.0\.2\.15 dst=10\.0\.2\.3$/,
		);
		expect(rest).toEqual([""]);
	});

	test("text --stats: the summary is the result, on stdout", async () => {
		const m = memoryIo();
		expect(
			await main(["--port", "0", "--duration", "50ms", "--stats"], m.io),
		).toBe(0);
		expect(m.stdout()).toMatch(/^summary: complete, stopped by duration/);
		expect(m.stderr()).toContain("warning capture/no-datagrams");
	});

	test("jsonl --fields: packets and the summary shaped, the header whole with its filters", async () => {
		const m = memoryIo();
		const run = main(
			[
				"--port",
				"0",
				"--format",
				"jsonl",
				"--idle",
				"200ms",
				"--proto",
				"icmp",
				"--not-dst-host",
				"10.0.2.15",
				"--fields",
				"dst,seq,counters",
			],
			m.io,
		);
		await until(() => m.out.length > 0);
		await send(boundPort(m.stdout()), [...STREAM.slice(0, 2), "01040000"]);
		expect(await run).toBe(0);
		const records = m
			.stdout()
			.trimEnd()
			.split("\n")
			.map((l) => JSON.parse(l));
		expect(records[0]).toMatchObject({
			type: "header",
			filters: { proto: ["icmp"], not: { dstHost: ["10.0.2.15"] } },
			detail: "summary",
		});
		// The reply to 10.0.2.15 is filtered; the keepalive is a record.
		expect(records.slice(1, -1)).toEqual([
			{ type: "packet", dst: "10.0.2.3", seq: 1 },
			{ type: "record", seq: 3 },
		]);
		const summary = records.at(-1);
		expect(Object.keys(summary)).toEqual(["type", "status", "counters"]);
		expect(summary.counters).toMatchObject({ packets: 1, filtered: 1 });
	});

	test("text --fields: key=value lines; the start line names the filters", async () => {
		const m = memoryIo();
		const run = main(
			[
				"--port",
				"0",
				"--count",
				"1",
				"--host",
				"10.0.2.3",
				"--fields",
				"src,dst,protocols",
			],
			m.io,
		);
		await until(() => m.err.length > 0);
		await send(boundPort(m.stderr()), [REQUEST]);
		expect(await run).toBe(0);
		expect(m.stdout()).toBe(
			"packet src=10.0.2.15 dst=10.0.2.3 protocols=ethernet,ipv4,icmp\n",
		);
		expect(m.stderr()).toMatch(
			/^listening on UDP 0\.0\.0\.0:\d+, until 1 packets, keeping --host 10\.0\.2\.3\n/,
		);
	});

	test("text --fields: the type always shows, and every field is printed in the order named", async () => {
		const m = memoryIo();
		const run = main(["--port", "0", "--count", "1", "--fields", "type"], m.io);
		await until(() => m.err.length > 0);
		await send(boundPort(m.stderr()), ["01040000", REQUEST]);
		expect(await run).toBe(0);
		expect(m.stdout()).toBe("record\npacket\n");

		const n = memoryIo();
		const ordered = main(
			["--port", "0", "--count", "1", "--fields", "datagram,seq,layers"],
			n.io,
		);
		await until(() => n.err.length > 0);
		await send(boundPort(n.stderr()), [REQUEST]);
		expect(await ordered).toBe(0);
		const lines = n.stdout().split("\n");
		expect(lines[0]).toBe("packet");
		expect(lines[1]).toBe(`  datagram ${REQUEST}`);
		expect(lines[2]).toBe("  seq=1");
		expect(lines[3]).toMatch(/^ {2}tzsp @0\+75 /);
	});

	test("text --stats --fields: the chosen summary fields are the result", async () => {
		const m = memoryIo();
		expect(
			await main(
				[
					"--port",
					"0",
					"--duration",
					"50ms",
					"--stats",
					"--fields",
					"stoppedBy",
				],
				m.io,
			),
		).toBe(0);
		expect(m.stdout()).toBe("summary status=complete stoppedBy=duration\n");
	});

	test("text: all filtered is a warning naming the filters; the summary counts them", async () => {
		const m = memoryIo();
		const run = main(
			["--port", "0", "--idle", "200ms", "--port-match", "53"],
			m.io,
		);
		await until(() => m.err.length > 0);
		await send(boundPort(m.stderr()), [REQUEST]);
		expect(await run).toBe(0);
		expect(m.stdout()).toBe("");
		expect(m.stderr()).toContain(
			"warning capture/all-filtered: 1 frames arrived on",
		);
		expect(m.stderr()).toContain("--port-match 53");
		expect(m.stderr()).toContain("packets 0, filtered 1,");
	});

	test("a filter value it cannot read: exit 2, nothing bound", async () => {
		const m = memoryIo();
		expect(await main(["--not-mac", "nope"], m.io)).toBe(2);
		expect(m.stdout()).toBe("");
		expect(m.stderr()).toContain("error filter/invalid-value: --not-mac");
	});

	test("--expect unmet: exit 1 and the error on stderr, also after an interrupt", async () => {
		const m = memoryIo();
		expect(
			await main(["--port", "0", "--duration", "50ms", "--expect", "1"], m.io),
		).toBe(1);
		expect(m.stderr()).toContain("error capture/expect-unmet");
		const controller = new AbortController();
		const n = memoryIo({ signal: controller.signal });
		const run = main(["--port", "0", "--follow", "--expect", "1"], n.io);
		await until(() => n.err.length > 0);
		controller.abort();
		expect(await run).toBe(1);
	});

	test("a stdout that fails for real: exit 1 with the code on stderr", async () => {
		const m = memoryIo();
		m.io.stdout = {
			async write() {
				throw new TzspSniffError(
					"output/failed",
					"Writing to stdout failed: ENOSPC",
					"Check where stdout goes.",
				);
			},
		};
		expect(
			await main(
				["--port", "0", "--format", "jsonl", "--duration", "20ms"],
				m.io,
			),
		).toBe(1);
		expect(m.stderr()).toContain("error output/failed");
	});

	test("after an output error, main returns only once the port is free", async () => {
		const m = memoryIo();
		m.io.stdout = {
			async write() {
				throw new TzspSniffError(
					"output/failed",
					"Writing to stdout failed: ENOSPC",
				);
			},
		};
		const run = main(["--port", "0", "--follow"], m.io);
		await until(() => m.err.length > 0);
		const port = boundPort(m.stderr());
		await send(port, [REQUEST]);
		expect(await run).toBe(1);
		await expectPortFree(port);
	});

	test("--version to a failing stdout is an output error (exit 1), not a usage one", async () => {
		const m = memoryIo();
		m.io.stdout = {
			async write() {
				throw new TzspSniffError(
					"output/failed",
					"Writing to stdout failed: ENOSPC",
				);
			},
		};
		expect(await main(["--version"], m.io)).toBe(1);
		expect(m.stderr()).toContain("error output/failed");
	});

	test("a closed stdout stops the capture quietly and frees the port", async () => {
		const m = memoryIo({ stdoutFailsAfter: 1 });
		const run = main(["--port", "0", "--format", "jsonl", "--follow"], m.io);
		await until(() => m.out.length > 0);
		const port = boundPort(m.stdout());
		await send(port, [REQUEST]);
		expect(await run).toBe(0);
		await expectPortFree(port);
	});
});

describe("--write and --format pcapng", () => {
	const dir = mkdtempSync(join(tmpdir(), "tzsp-sniff-cli-"));
	afterAll(() => rmSync(dir, { recursive: true, force: true }));
	let n = 0;
	const fresh = () => join(dir, `c-${++n}.pcapng`);
	const hexOf = (p: { data: Uint8Array }) =>
		Buffer.from(p.data).toString("hex");
	const planOf = (argv: string[]) => plan(parseArgs(argv));

	test("pcapng refuses --fields, --stats and --detail, each with a fix", () => {
		for (const [flag, ...rest] of [
			["--fields", "src"],
			["--stats"],
			["--detail", "full"],
		] as const) {
			let error: TzspSniffError | undefined;
			try {
				planOf(["--format", "pcapng", flag, ...rest]);
			} catch (e) {
				error = e as TzspSniffError;
			}
			expect(error?.code).toBe("cli/flag-conflict");
			expect(error?.message).toContain(flag);
			expect(error?.fix).toContain("--write");
		}
	});

	test("--write needs a path, --write - points at --format pcapng, --overwrite needs --write", () => {
		expect(codeOf(() => planOf(["--write", "-"]))).toBe("cli/invalid-value");
		expect(codeOf(() => planOf(["--write="]))).toBe("cli/invalid-value");
		expect(codeOf(() => planOf(["--overwrite"]))).toBe("cli/flag-conflict");
		expect(planOf(["--write", "x.pcapng", "--overwrite"]).write).toEqual({
			path: "x.pcapng",
			overwrite: true,
		});
		expect(planOf(["--write", "x.pcapng"]).write?.overwrite).toBe(false);
		expect(planOf(["--format", "pcapng"]).format).toBe("pcapng");
	});

	test("--format pcapng to a terminal: exit 2 before any bind, with a fix", async () => {
		const m = memoryIo({ stdoutTerminal: true });
		expect(await main(["--format", "pcapng", "--count", "1"], m.io)).toBe(2);
		expect(m.stderr()).toMatch(
			/^error cli\/binary-to-terminal: .*\n {2}fix: Redirect it/,
		);
		expect(m.bin).toHaveLength(0);
		// Text to a terminal is fine.
		expect(
			await main(
				["--port", "0", "--duration", "10ms"],
				memoryIo({ stdoutTerminal: true }).io,
			),
		).toBe(0);
	});

	test("--write with --stats: every datagram saved, before filters; the summary says what was written", async () => {
		const path = fresh();
		const m = memoryIo();
		const run = main(
			[
				"--port",
				"0",
				"--idle",
				"300ms",
				"--stats",
				"--format",
				"jsonl",
				"--proto",
				"tcp",
				"--write",
				path,
			],
			m.io,
		);
		await until(() => m.out.length > 0);
		await send(boundPort(m.stdout()), [REQUEST, "01040000"]);
		expect(await run).toBe(0);
		const records = m
			.stdout()
			.trimEnd()
			.split("\n")
			.map((l) => JSON.parse(l));
		expect(records[0]).toMatchObject({ type: "header", write: path });
		const file = readPcapng(readFileSync(path));
		expect(file.packets.map(hexOf)).toEqual([REQUEST, "01040000"]);
		expect(records.at(-1)).toMatchObject({
			type: "summary",
			status: "complete",
			counters: { packets: 0, filtered: 1, control: 1 },
			written: { datagrams: 2, bytes: readFileSync(path).length },
		});
	});

	test("text: the start line names the file, and the summary counts what was written", async () => {
		const path = fresh();
		const m = memoryIo();
		const run = main(["--port", "0", "--count", "1", "--write", path], m.io);
		await until(() => m.err.length > 0);
		expect(m.stderr()).toContain(`, saving every datagram to ${path}\n`);
		await send(boundPort(m.stderr()), [REQUEST]);
		expect(await run).toBe(0);
		expect(m.stderr()).toMatch(/\n {2}written: 1 datagrams, \d+ bytes\n/);
		expect(m.stdout()).toContain("icmp echo-request");
	});

	test("an existing file: exit 1 with write/exists naming --overwrite; the file is kept", async () => {
		const path = fresh();
		writeFileSync(path, "keep");
		const m = memoryIo();
		expect(
			await main(["--port", "0", "--count", "1", "--write", path], m.io),
		).toBe(1);
		expect(m.stderr()).toMatch(
			/^error write\/exists: .*\n {2}fix: .*--overwrite/,
		);
		expect(m.stdout()).toBe("");
		expect(readFileSync(path, "utf8")).toBe("keep");
		// --overwrite replaces it.
		const o = memoryIo();
		const run = main(
			["--port", "0", "--count", "1", "--write", path, "--overwrite"],
			o.io,
		);
		await until(() => o.err.length > 0);
		await send(boundPort(o.stderr()), [REQUEST]);
		expect(await run).toBe(0);
		expect(readPcapng(readFileSync(path)).packets).toHaveLength(1);
	});

	/** A --write sink in memory that fails its nth write, or its close. */
	const failingSink = (o: { failAt?: number; closeFails?: boolean }) => {
		let writes = 0;
		const sink: ByteSink = {
			async write() {
				writes += 1;
				if (writes === o.failAt) {
					throw new TzspSniffError(
						"write/failed",
						"Writing c.pcapng failed: ENOSPC: no space left on device",
						"Check the free space.",
					);
				}
			},
			async close() {
				if (o.closeFails) {
					throw new TzspSniffError(
						"write/failed",
						"Closing c.pcapng failed: EIO: i/o error",
					);
				}
			},
		};
		return sink;
	};

	test("a write that fails after packets were printed: exit 1, write/failed on stderr", async () => {
		const m = memoryIo();
		// The section header, the interface and the first packet block pass.
		m.io.writeSink = () => failingSink({ failAt: 4 });
		const run = main(["--port", "0", "--follow", "--write", "c.pcapng"], m.io);
		await until(() => m.err.length > 0);
		const port = boundPort(m.stderr());
		await send(port, [REQUEST]);
		await until(() => m.out.length > 0);
		await send(port, [REQUEST]);
		expect(await run).toBe(1);
		expect(m.out).toHaveLength(1);
		expect(m.stderr()).toContain("error write/failed: Writing c.pcapng failed");
		expect(m.stderr()).toMatch(/summary: error.* unsaved 1/s);
		await expectPortFree(port);
	});

	test("a closed stdout does not hide a capture file that failed to close: exit 1", async () => {
		const m = memoryIo({ stdoutFailsAfter: 2 });
		m.io.writeSink = () => failingSink({ closeFails: true });
		const run = main(
			["--port", "0", "--follow", "--format", "pcapng", "--write", "c.pcapng"],
			m.io,
		);
		await until(() => m.err.length > 0);
		await send(boundPort(m.stderr()), [REQUEST]);
		expect(await run).toBe(1);
		expect(m.stderr()).toContain("error write/failed: Closing c.pcapng failed");
	});

	test("stdout closed on the section header, and the file fails to close: exit 1", async () => {
		const m = memoryIo({ stdoutFailsAfter: 0 });
		m.io.writeSink = () => failingSink({ closeFails: true });
		expect(
			await main(
				[
					"--port",
					"0",
					"--count",
					"1",
					"--format",
					"pcapng",
					"--write",
					"c.pcapng",
				],
				m.io,
			),
		).toBe(1);
		expect(m.stderr()).toContain("error write/failed: Closing c.pcapng failed");
	});

	test("text: stdout closed at a packet line, and the file fails to close: exit 1", async () => {
		const m = memoryIo({ stdoutFailsAfter: 0 });
		m.io.writeSink = () => failingSink({ closeFails: true });
		const run = main(["--port", "0", "--follow", "--write", "c.pcapng"], m.io);
		await until(() => m.err.length > 0);
		await send(boundPort(m.stderr()), [REQUEST]);
		expect(await run).toBe(1);
		expect(m.stderr()).toContain("error write/failed: Closing c.pcapng failed");
		// And with the file closing cleanly, the closed stdout stays quiet.
		const q = memoryIo({ stdoutFailsAfter: 0 });
		q.io.writeSink = () => failingSink({});
		const quiet = main(
			["--port", "0", "--follow", "--write", "c.pcapng"],
			q.io,
		);
		await until(() => q.err.length > 0);
		await send(boundPort(q.stderr()), [REQUEST]);
		expect(await quiet).toBe(0);
	});

	test("--format pcapng with only control records: the warning's fix works with pcapng", async () => {
		const m = memoryIo();
		const run = main(
			["--port", "0", "--idle", "200ms", "--format", "pcapng"],
			m.io,
		);
		await until(() => m.err.length > 0);
		await send(boundPort(m.stderr()), ["01040000"]);
		expect(await run).toBe(0);
		expect(m.stderr()).toContain("warning capture/no-frames");
		expect(m.stderr()).toContain(
			"fix: Run again with --format text or jsonl and --detail full",
		);
	});

	test("--write naming the file stdout goes to: exit 2 before the bind", async () => {
		const path = fresh();
		writeFileSync(path, "");
		const { statSync } = await import("node:fs");
		const s = statSync(path, { bigint: true });
		const m = memoryIo();
		m.io.outputFiles = [{ dev: s.dev, ino: s.ino }];
		expect(
			await main(["--count", "1", "--write", path, "--overwrite"], m.io),
		).toBe(2);
		expect(m.stderr()).toContain("error cli/write-to-output");
		// Another file is fine.
		expect(codeOf(() => planOf(["--write", fresh()]))).toBeUndefined();
	});

	test("--format pcapng: the reported datagrams on stdout; the start line and summary on stderr", async () => {
		const m = memoryIo();
		const run = main(
			[
				"--port",
				"0",
				"--idle",
				"300ms",
				"--format",
				"pcapng",
				"--proto",
				"tcp",
			],
			m.io,
		);
		await until(() => m.err.length > 0);
		expect(m.stderr()).toContain("listening on UDP");
		await send(boundPort(m.stderr()), [REQUEST, "01040000"]);
		expect(await run).toBe(0);
		expect(m.stdout()).toBe("");
		const file = readPcapng(m.stdoutBytes());
		expect(file.interfaces).toHaveLength(1);
		// The ICMP frame is filtered out; the control record is reported.
		expect(file.packets.map(hexOf)).toEqual(["01040000"]);
		expect(m.stderr()).toContain("summary: complete");
	});

	test("--format pcapng and --write together: the file has everything, stdout what the filters keep", async () => {
		const path = fresh();
		const m = memoryIo();
		const run = main(
			[
				"--port",
				"0",
				"--idle",
				"300ms",
				"--format",
				"pcapng",
				"--proto",
				"tcp",
				"--write",
				path,
			],
			m.io,
		);
		await until(() => m.err.length > 0);
		await send(boundPort(m.stderr()), [REQUEST]);
		expect(await run).toBe(0);
		expect(readPcapng(readFileSync(path)).packets.map(hexOf)).toEqual([
			REQUEST,
		]);
		expect(readPcapng(m.stdoutBytes()).packets).toHaveLength(0);
	});

	test("--format pcapng to a closed stdout stops quietly and frees the port; the file is closed whole", async () => {
		const path = fresh();
		// The section header and the interface block go through; the
		// packet block finds the reader gone.
		const m = memoryIo({ stdoutFailsAfter: 2 });
		const run = main(
			["--port", "0", "--follow", "--format", "pcapng", "--write", path],
			m.io,
		);
		await until(() => m.err.length > 0);
		const port = boundPort(m.stderr());
		await send(port, [REQUEST]);
		expect(await run).toBe(0);
		await expectPortFree(port);
		expect(m.stderr()).not.toContain("summary");
		expect(m.bin).toHaveLength(2);
		// The datagram was saved before stdout failed, and the file closed.
		const file = readPcapng(readFileSync(path));
		expect(file.packets).toHaveLength(1);
		expect(file.trailing).toBe(0);
	});
});

describe("decode", () => {
	const dir = mkdtempSync(join(tmpdir(), "tzsp-sniff-decode-"));
	afterAll(() => rmSync(dir, { recursive: true, force: true }));
	const ROUTEROS = join(
		import.meta.dir,
		"..",
		"fixtures",
		"routeros",
		"7.25.1-x86-sniffer-file.pcapng",
	);
	const planOf = (argv: string[]) => plan(parseArgs(argv));
	const lines = (text: string) =>
		text
			.trimEnd()
			.split("\n")
			.map((l) => JSON.parse(l));

	test("a listen flag under decode names listen, and --format pcapng is listen's", () => {
		let error: TzspSniffError | undefined;
		try {
			parseArgs(["decode", "x", "--follow"]);
		} catch (e) {
			error = e as TzspSniffError;
		}
		expect(error?.message).toBe("--follow is a flag of listen, not decode.");
		expect(error?.fix).toContain("tzsp-sniff listen --follow");
		expect(codeOf(() => planOf(["decode", "x", "--format", "pcapng"]))).toBe(
			"cli/wrong-command",
		);
	});

	test("plan: no default duration; --input and --tzsp-port are checked", () => {
		const p = planOf([
			"decode",
			"x",
			"--tzsp-port",
			"37009,37010",
			"--count",
			"2",
		]);
		expect(p.tips).toEqual([]);
		expect(p.decode).toEqual({
			input: "x",
			options: {
				name: "x",
				detail: "line",
				tzspPorts: [37009, 37010],
				count: 2,
			},
		});
		expect(
			planOf(["decode", "x", "--input", "hex"]).decode?.options.format,
		).toBe("hex");
		// Only a capture file has an interface or a comment.
		expect(codeOf(() => planOf(["--fields", "interface"]))).toBe(
			"cli/invalid-value",
		);
		expect(
			planOf(["decode", "x", "--fields", "interface,comment"]).fields,
		).toEqual(["interface", "comment"]);
		expect(codeOf(() => planOf(["decode", "x", "--input", "json"]))).toBe(
			"cli/invalid-value",
		);
		for (const port of ["0", "65536", "x", "1.5"]) {
			expect(codeOf(() => planOf(["decode", "x", "--tzsp-port", port]))).toBe(
				"cli/invalid-value",
			);
		}
	});

	test("text: packet lines on stdout, the start line and summary on stderr", async () => {
		const m = memoryIo();
		expect(await main(["decode", ROUTEROS], m.io)).toBe(0);
		expect(m.stderr()).toStartWith(`decoding ${ROUTEROS} (pcapng)\n`);
		expect(m.stderr()).toContain("summary: complete, read to the end;");
		const out = m.stdout().trimEnd().split("\n");
		expect(out).toHaveLength(6);
		expect(out[0]).toMatch(
			/^\d\d:\d\d:\d\d\.\d{3} 10\.0\.2\.15 > 10\.0\.2\.3 icmp echo-request/,
		);
		const summary = memoryIo();
		expect(
			await main(["decode", ROUTEROS, "--detail", "layers"], summary.io),
		).toBe(0);
		expect(summary.stdout()).toContain("[ether1 tx] 10.0.2.15 > 10.0.2.3");
		expect(summary.stdout()).toContain("interface=ether1 tx");
		expect(summary.stdout()).toContain('  comment "cpu:0 fp:0"\n');
	});

	test("jsonl --fields: the decode header, shaped packets, the summary last", async () => {
		const m = memoryIo();
		const code = await main(
			[
				"decode",
				ROUTEROS,
				"--format",
				"jsonl",
				"--fields",
				"seq,interface,comment",
			],
			m.io,
		);
		expect(code).toBe(0);
		const records = lines(m.stdout());
		expect(records[0]).toMatchObject({
			type: "header",
			command: "decode",
			input: { name: ROUTEROS, format: "pcapng" },
			detail: "layers",
		});
		expect(records[1]).toEqual({
			type: "packet",
			seq: 1,
			interface: "ether1 tx",
			comment: "cpu:0 fp:0",
		});
		expect(records.at(-1)).toMatchObject({
			type: "summary",
			status: "complete",
		});
	});

	test("stdin as -", async () => {
		const m = memoryIo();
		const data = readFileSync(ROUTEROS);
		m.io.stdin = () =>
			(async function* () {
				yield data.subarray(0, 100);
				yield data.subarray(100);
			})();
		expect(
			await main(["decode", "-", "--count", "2", "--format", "jsonl"], m.io),
		).toBe(0);
		const records = lines(m.stdout());
		expect(records[0]).toMatchObject({ input: { name: "-" } });
		expect(records.filter((r) => r.type === "packet")).toHaveLength(2);
		expect(records.at(-1)).toMatchObject({ stoppedBy: "count" });
	});

	test("stdin with no destroy(): stopping early runs its return(), so its cleanup runs", async () => {
		const m = memoryIo();
		const data = readFileSync(ROUTEROS);
		let cleaned = false;
		m.io.stdin = () =>
			(async function* () {
				try {
					yield data.subarray(0, 100);
					yield data.subarray(100);
					yield data.subarray(0, 0);
				} finally {
					cleaned = true;
				}
			})();
		expect(await main(["decode", "-", "--count", "1"], m.io)).toBe(0);
		expect(cleaned).toBe(true);
	});

	test("stdin with no destroy(): an abort does not wait on a stalled return(), and a throwing one is dropped (final review of 71d400c)", async () => {
		const source =
			(onReturn: () => Promise<IteratorResult<Uint8Array>>) => () => ({
				[Symbol.asyncIterator]() {
					let sent = false;
					return {
						next(): Promise<IteratorResult<Uint8Array>> {
							if (sent) return new Promise(() => {});
							sent = true;
							return Promise.resolve({
								done: false,
								value: new TextEncoder().encode(`${REQUEST}\n${REQUEST}\n`),
							});
						},
						return: onReturn,
					};
				},
			});
		const controller = new AbortController();
		const m = memoryIo({ signal: controller.signal });
		const write = m.io.stdout.write;
		m.io.stdout = {
			async write(data) {
				await write(data);
				if (String(data).includes('"type":"packet"')) controller.abort();
			},
		};
		m.io.stdin = source(() => new Promise(() => {}));
		// main settles: the summary is written and nothing waits on return().
		await main(["decode", "-", "--input", "hex", "--format", "jsonl"], m.io);
		expect(lines(m.stdout()).at(-1)).toMatchObject({ status: "interrupted" });

		const thrown = memoryIo();
		thrown.io.stdin = source(() => {
			throw new Error("the source's own cleanup failed");
		});
		expect(
			await main(["decode", "-", "--input", "hex", "--count", "1"], thrown.io),
		).toBe(0);
	}, 2000);

	test("stdin: an abort ends the wait on a return() that began before it (final review of 5ea61d0)", async () => {
		const controller = new AbortController();
		const m = memoryIo({ signal: controller.signal });
		m.io.stdin = () => ({
			[Symbol.asyncIterator]: () => ({
				async next(): Promise<IteratorResult<Uint8Array>> {
					return { done: false, value: new TextEncoder().encode("zzzz") };
				},
				// Not a format: cleanup starts with no abort, then stalls.
				return(): Promise<IteratorResult<Uint8Array>> {
					setTimeout(() => controller.abort(), 20);
					return new Promise(() => {});
				},
			}),
		});
		expect(await main(["decode", "-"], m.io)).toBe(130);
	}, 2000);

	test.skipIf(process.platform === "win32")(
		"a named pipe is refused without waiting for a writer, and the fix says to pipe it to - (final review of 71d400c)",
		async () => {
			const fifo = join(dir, "pipe");
			expect(spawnSync("mkfifo", [fifo]).status).toBe(0);
			const m = memoryIo();
			// No writer ever comes: a blocking open would never return.
			expect(await main(["decode", fifo], m.io)).toBe(1);
			expect(m.stderr()).toStartWith("error decode/read-failed: ");
			expect(m.stderr()).toContain("not a regular file");
			expect(m.stderr()).toContain("decode -");
		},
		2000,
	);

	test("an input it cannot read or tell: exit 1 with the code on stderr, nothing on stdout", async () => {
		const notCapture = join(dir, "notes.txt");
		writeFileSync(notCapture, `${REQUEST}\n`);
		const cases: [string[], string][] = [
			[["decode", join(dir, "missing.pcapng")], "decode/read-failed"],
			[["decode", dir], "decode/read-failed"],
			[["decode", notCapture], "decode/unknown-format"],
		];
		for (const [argv, code] of cases) {
			const m = memoryIo();
			expect({ argv, exit: await main(argv, m.io) }).toEqual({ argv, exit: 1 });
			expect(m.stderr()).toStartWith(`error ${code}: `);
			expect(m.stdout()).toBe("");
		}
		const hex = memoryIo();
		expect(await main(["decode", notCapture, "--input", "hex"], hex.io)).toBe(
			0,
		);
		expect(hex.stdout()).toContain("icmp echo-request");
	});

	test("a corrupt file: the packets before it, then exit 1 with decode/malformed", async () => {
		const path = join(dir, "corrupt.pcapng");
		const data = readFileSync(ROUTEROS);
		// The first packet whole, then a block length over the limit.
		const cut = Buffer.concat([data, Buffer.from("06000000fffffff0", "hex")]);
		writeFileSync(path, cut);
		const m = memoryIo();
		expect(await main(["decode", path], m.io)).toBe(1);
		expect(m.stdout().trimEnd().split("\n")).toHaveLength(6);
		expect(m.stderr()).toContain("summary: error");
		expect(m.stderr()).toContain("error decode/malformed: ");
	});

	test("a file cut inside a block: exit 0, a warning, incomplete; --expect still decides", async () => {
		const path = join(dir, "cut.pcapng");
		const data = readFileSync(ROUTEROS);
		writeFileSync(path, data.subarray(0, data.length - 10));
		const m = memoryIo();
		expect(await main(["decode", path], m.io)).toBe(0);
		expect(m.stdout().trimEnd().split("\n")).toHaveLength(5);
		expect(m.stderr()).toContain("warning decode/truncated: ");
		expect(m.stderr()).toContain("summary: incomplete");
		expect(await main(["decode", path, "--expect", "6"], memoryIo().io)).toBe(
			1,
		);
	});

	test("round trip: listen --write, then decode, gives the same packet records", async () => {
		const path = join(dir, "round-trip.pcapng");
		const listened = memoryIo();
		const run = main(
			[
				"--port",
				"0=router-a",
				"--count",
				"6",
				"--duration",
				"5s",
				"--format",
				"jsonl",
				"--detail",
				"full",
				"--write",
				path,
			],
			listened.io,
		);
		await until(() => listened.out.length > 0);
		await send(boundPort(listened.stdout()), STREAM);
		expect(await run).toBe(0);
		const decoded = memoryIo();
		expect(
			await main(
				["decode", path, "--format", "jsonl", "--detail", "full"],
				decoded.io,
			),
		).toBe(0);
		const packets = (text: string) =>
			lines(text).filter((r) => r.type === "packet" || r.type === "record");
		const before = packets(listened.stdout());
		expect(before).toHaveLength(6);
		expect(before[0]).toMatchObject({ listener: "router-a" });
		expect(packets(decoded.stdout())).toEqual(before);
		// Past the 5 s capture budget, with room to set up and decode.
	}, 15_000);
});

describe("text output (final review of 5ea61d0)", () => {
	test("the clock is read from the T, so a six-digit year does not move it", () => {
		const at = (time: string) =>
			entryText(
				{
					type: "record",
					seq: 1,
					time,
					kind: "control",
					tzspType: "keepalive",
					length: 4,
					line: "tzsp keepalive",
				} as Parameters<typeof entryText>[0],
				false,
			);
		expect(at("2026-11-20T09:16:57.123Z")).toStartWith(
			"09:16:57.123 tzsp keepalive\n",
		);
		expect(at("+275760-09-13T00:00:00.000Z")).toStartWith(
			"00:00:00.000 tzsp keepalive\n",
		);
	});
});
