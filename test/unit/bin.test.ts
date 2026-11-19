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
/** Each child must be done well inside this; a stuck one is killed. */
const CHILD_MS = 8000;

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

const spawn = (args: string[]) =>
	Bun.spawn([process.execPath, "--no-env-file", BIN, ...args], {
		env,
		stdout: "pipe",
		stderr: "pipe",
	});
type Child = ReturnType<typeof spawn>;
type Header = { listeners: { port: number }[] };

/**
 * Run the executable. `onHeader` runs once the first stdout line (the JSONL
 * header) is in; the result holds stdout and stderr read to EOF. The child
 * is killed if it outlives CHILD_MS, and always in `finally`.
 */
async function run(
	args: string[],
	onHeader: (header: Header, proc: Child) => Promise<void> = async () => {},
) {
	const proc = spawn(args);
	const killer = setTimeout(() => proc.kill("SIGKILL"), CHILD_MS);
	try {
		const stderr = new Response(proc.stderr).text();
		const reader = proc.stdout.getReader();
		const decoder = new TextDecoder();
		let stdout = "";
		let headerSeen = false;
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			stdout += decoder.decode(value, { stream: true });
			if (!headerSeen && stdout.includes("\n")) {
				headerSeen = true;
				await onHeader(JSON.parse(stdout.split("\n")[0] as string), proc);
			}
		}
		return { code: await proc.exited, stdout, stderr: await stderr };
	} finally {
		clearTimeout(killer);
		proc.kill("SIGKILL");
	}
}

/** Every stdout line parsed; exactly one summary, and it is last. */
const records = (stdout: string) => {
	const lines = stdout
		.trimEnd()
		.split("\n")
		.map((l) => JSON.parse(l) as { type: string });
	expect(lines.filter((r) => r.type === "summary")).toHaveLength(1);
	expect(lines.at(-1)?.type).toBe("summary");
	return lines;
};

describe("tzsp-sniff executable", () => {
	test("jsonl to a pipe: header, packet, summary, exit 0, port freed", async () => {
		let port = 0;
		const result = await run(
			["--port", "0", "--count", "1", "--format", "jsonl"],
			async (header) => {
				port = header.listeners[0]?.port as number;
				await send(port, [REQUEST]);
			},
		);
		expect(result.code).toBe(0);
		expect(records(result.stdout).map((r) => r.type)).toEqual([
			"header",
			"packet",
			"summary",
		]);
		await expectPortFree(port);
	});

	test("a usage error exits 2 with the code on stderr and nothing on stdout", async () => {
		const result = await run(["--format", "json"]);
		expect(result.code).toBe(2);
		expect(result.stdout).toBe("");
		expect(result.stderr).toContain("error cli/invalid-value");
	});

	// Windows has no SIGINT to send to a child; the interrupt path is covered
	// in process there (cli.test.ts, capture.test.ts).
	test.skipIf(process.platform === "win32")(
		"SIGINT ends --follow as interrupted, with the summary, exit 0",
		async () => {
			let port = 0;
			const result = await run(
				["--port", "0", "--follow", "--format", "jsonl"],
				async (header, proc) => {
					port = header.listeners[0]?.port as number;
					proc.kill("SIGINT");
				},
			);
			expect(result.code).toBe(0);
			expect(records(result.stdout).at(-1)).toMatchObject({
				status: "interrupted",
				stoppedBy: "interrupt",
			});
			await expectPortFree(port);
		},
	);

	test("a reader that closes the pipe ends --follow quietly, exit 0, port freed", async () => {
		const proc = spawn(["--port", "0", "--follow", "--format", "jsonl"]);
		const killer = setTimeout(() => proc.kill("SIGKILL"), CHILD_MS);
		try {
			const reader = proc.stdout.getReader();
			let text = "";
			while (!text.includes("\n")) {
				const { value, done } = await reader.read();
				if (done) break;
				text += new TextDecoder().decode(value);
			}
			const header = JSON.parse(text.split("\n")[0] as string) as Header;
			const port = header.listeners[0]?.port as number;
			await reader.cancel();
			// Each datagram makes a write; the first one after the close fails.
			for (let i = 0; i < 50 && proc.exitCode === null; i++) {
				await send(port, [REQUEST]);
				await new Promise((r) => setTimeout(r, 20));
			}
			expect(await proc.exited).toBe(0);
			expect(await new Response(proc.stderr).text()).toBe("");
			await expectPortFree(port);
		} finally {
			clearTimeout(killer);
			proc.kill("SIGKILL");
		}
	});
});
