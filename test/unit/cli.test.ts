import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { COMMANDS, FLAGS, parseArgs, wantsHelp } from "../../src/cli/flags.ts";
import {
	DEFAULT_DURATION_MS,
	JSON_MAX_RECORDS,
	helpText,
	type Io,
	main,
	OutputClosedError,
	plan,
} from "../../src/cli/main.ts";
import { TzspSniffError } from "../../src/errors.ts";
import { VERSION } from "../../src/version.ts";
import {
	closeSocket,
	expectPortFree,
	fixture,
	holdPort,
	send,
	until,
} from "./helpers.ts";

const REQUEST = fixture("7.25.1-x86-sniffer-stream")[0] as string;

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
	options: { stdoutFailsAfter?: number; signal?: AbortSignal } = {},
) {
	const out: string[] = [];
	const err: string[] = [];
	const io: Io = {
		stdout: {
			async write(text) {
				if (
					options.stdoutFailsAfter !== undefined &&
					out.length >= options.stdoutFailsAfter
				) {
					throw new OutputClosedError();
				}
				out.push(text);
			},
		},
		stderr: {
			async write(text) {
				err.push(text);
			},
		},
	};
	if (options.signal) io.signal = options.signal;
	return {
		io,
		out,
		err,
		stdout: () => out.join(""),
		stderr: () => err.join(""),
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
		// The same value twice is a no-op.
		expect(parseArgs(["--count", "3", "--count=3"]).flags.get("count")).toEqual(
			["3"],
		);
	});

	test("refuses what it cannot apply, each with its own code", () => {
		const cases: [string[], string][] = [
			[["decode", "x.pcapng"], "cli/unknown-command"],
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
		];
		for (const [argv, code] of cases) {
			expect({ argv, code: codeOf(() => parseArgs(argv)) }).toEqual({
				argv,
				code,
			});
		}
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

	test("json bounds its document; other formats do not", () => {
		expect(
			planOf(["--format", "json", "--count", "1"]).options.recordLimit,
		).toBe(JSON_MAX_RECORDS);
		expect(planOf(["--format", "jsonl"]).options.recordLimit).toBeUndefined();
	});

	test("jsonl and json default to summary detail", () => {
		expect(planOf(["--format", "jsonl"]).options.detail).toBe("summary");
		expect(planOf(["--format", "json", "--count", "1"]).options.detail).toBe(
			"summary",
		);
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

	test("refusals that need two flags", () => {
		expect(codeOf(() => planOf(["--format", "json"]))).toBe(
			"cli/json-needs-limit",
		);
		expect(codeOf(() => planOf(["--format", "json", "--idle", "5s"]))).toBe(
			"cli/json-needs-limit",
		);
		expect(codeOf(() => planOf(["--format", "json", "--follow"]))).toBe(
			"cli/json-needs-limit",
		);
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

	test("a usage error: exit 2, the code and fix on stderr, nothing on stdout", async () => {
		const m = memoryIo();
		expect(await main(["--format", "json"], m.io)).toBe(2);
		expect(m.stdout()).toBe("");
		expect(m.stderr()).toMatch(
			/^error cli\/json-needs-limit: .*\n {2}fix: .*--format jsonl/,
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

	test("text --stats: the summary is the result, on stdout", async () => {
		const m = memoryIo();
		expect(
			await main(["--port", "0", "--duration", "50ms", "--stats"], m.io),
		).toBe(0);
		expect(m.stdout()).toMatch(/^summary: complete, stopped by duration/);
		expect(m.stderr()).toContain("warning capture/no-datagrams");
	});

	test("json: one document with every section", async () => {
		const m = memoryIo();
		expect(
			await main(
				["--port", "0", "--duration", "50ms", "--format", "json"],
				m.io,
			),
		).toBe(0);
		expect(m.out).toHaveLength(1);
		const doc = JSON.parse(m.stdout());
		expect(Object.keys(doc)).toEqual([
			"header",
			"packets",
			"records",
			"warnings",
			"tips",
			"summary",
		]);
		expect(doc.warnings[0].code).toBe("capture/no-datagrams");
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
