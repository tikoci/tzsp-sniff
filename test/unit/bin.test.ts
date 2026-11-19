import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { expectPortFree, fixture, send } from "./helpers.ts";

/**
 * The real executable, spawned: process streams, exit codes and signals,
 * which the in-process tests of main() cannot reach. Run under Bun from
 * src/; test/smoke/node-smoke.mjs runs the built one under Node.
 */
const BIN = join(import.meta.dir, "..", "..", "src", "cli", "bin.ts");
const REQUEST = fixture("7.25.1-x86-sniffer-stream")[0] as string;

/**
 * An explicit environment, not a copy of this one (tikoci-testing,
 * "Hermetic"). Windows sockets need SystemRoot, so it is kept when set.
 */
const env: Record<string, string> = {
	PATH: process.env.PATH ?? "",
	NO_COLOR: "1",
};
for (const key of ["SystemRoot", "SYSTEMROOT", "TEMP", "TMP"]) {
	const value = process.env[key];
	if (value !== undefined) env[key] = value;
}

function spawn(args: string[]) {
	const proc = Bun.spawn([process.execPath, "--no-env-file", BIN, ...args], {
		env,
		stdout: "pipe",
		stderr: "pipe",
	});
	const reader = proc.stdout.getReader();
	const decoder = new TextDecoder();
	let text = "";
	/** stdout so far, read until `pattern` matches or the process ends. */
	const readUntil = async (pattern: RegExp) => {
		while (!pattern.test(text)) {
			const { value, done } = await reader.read();
			if (done) break;
			text += decoder.decode(value);
		}
		return text;
	};
	return { proc, readUntil };
}

describe("tzsp-sniff executable", () => {
	test("jsonl to a pipe: header, packet, summary, exit 0", async () => {
		const { proc, readUntil } = spawn([
			"--port",
			"0",
			"--count",
			"1",
			"--format",
			"jsonl",
		]);
		const header = JSON.parse((await readUntil(/\n/)).split("\n")[0] as string);
		const port = header.listeners[0].port as number;
		await send(port, [REQUEST]);
		const lines = (await readUntil(/"type":"summary".*\n/))
			.trimEnd()
			.split("\n");
		expect(await proc.exited).toBe(0);
		expect(lines.map((l) => JSON.parse(l).type)).toEqual([
			"header",
			"packet",
			"summary",
		]);
		await expectPortFree(port);
	});

	test("a usage error exits 2 with the code on stderr", async () => {
		const { proc } = spawn(["--format", "json"]);
		expect(await proc.exited).toBe(2);
		expect(await new Response(proc.stderr).text()).toContain(
			"error cli/json-needs-limit",
		);
	});

	// Windows has no SIGINT to send to a child; the interrupt path is covered
	// in process there (cli.test.ts, capture.test.ts).
	test.skipIf(process.platform === "win32")(
		"SIGINT ends --follow as interrupted, with the summary, exit 0",
		async () => {
			const { proc, readUntil } = spawn([
				"--port",
				"0",
				"--follow",
				"--format",
				"jsonl",
			]);
			const header = JSON.parse(
				(await readUntil(/\n/)).split("\n")[0] as string,
			);
			proc.kill("SIGINT");
			const last = (await readUntil(/"type":"summary".*\n/))
				.trimEnd()
				.split("\n")
				.at(-1) as string;
			expect(await proc.exited).toBe(0);
			expect(JSON.parse(last)).toMatchObject({
				status: "interrupted",
				stoppedBy: "interrupt",
			});
			await expectPortFree(header.listeners[0].port);
		},
	);
});
