import { afterAll, describe, expect, test } from "bun:test";
import {
	closeSync,
	mkdtempSync,
	openSync,
	readFileSync,
	rmSync,
	statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	childEnv,
	expectPortFree,
	fixture,
	openPty,
	send,
	stalledTerminal,
	until,
} from "./helpers.ts";
import { blocks, readPcapng } from "./pcapng-reader.ts";

/**
 * The real executable, spawned: process streams, exit codes and signals,
 * which the in-process tests of main() cannot reach. Run under Bun from
 * src/; test/smoke/node-smoke.mjs runs the built one under Node.
 */
const BIN = join(import.meta.dir, "..", "..", "src", "cli", "bin.ts");
const REQUEST = fixture("7.25.1-x86-sniffer-stream")[0] as string;
/** Each child must be done well inside this; a stuck one is killed. */
const CHILD_MS = 8000;

const env = childEnv();

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

	// A terminal nobody reads (Ctrl-S): the event loop must stay free, so
	// SIGINT ends the capture with output/stalled after the grace (2 s).
	// libc pseudo-terminals: Linux and macOS.
	test.skipIf(process.platform === "win32")(
		"stdout on a terminal nobody reads: SIGINT ends it with output/stalled, port freed",
		async () => {
			const result = await stalledTerminal(
				[process.execPath, "--no-env-file", BIN],
				CHILD_MS,
			);
			expect(result.runningBeforeInterrupt).toBe(true);
			expect(result.code).toBe(1);
			expect(result.stderr).toContain("error output/stalled");
			expect(result.ms).toBeLessThan(CHILD_MS);
			await expectPortFree(result.port);
		},
		CHILD_MS * 2,
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

	describe("--write and --format pcapng", () => {
		const dir = mkdtempSync(join(tmpdir(), "tzsp-sniff-bin-"));
		afterAll(() => rmSync(dir, { recursive: true, force: true }));

		// Windows has no SIGINT to send to a child.
		test.skipIf(process.platform === "win32")(
			"SIGINT during --follow --write: a valid file up to the last whole block, owner-only",
			async () => {
				const path = join(dir, "sigint.pcapng");
				let port = 0;
				const result = await run(
					["--port", "0", "--follow", "--format", "jsonl", "--write", path],
					async (header, proc) => {
						port = header.listeners[0]?.port as number;
						await send(port, [REQUEST, REQUEST, REQUEST]);
						// Each block is written as it comes: all three are in the
						// file before the interrupt.
						await until(() => {
							try {
								return readPcapng(readFileSync(path)).packets.length === 3;
							} catch {
								return false;
							}
						}, 4000);
						proc.kill("SIGINT");
					},
				);
				expect(result.code).toBe(0);
				const file = readFileSync(path);
				expect(blocks(file).trailing).toBe(0);
				expect(readPcapng(file).packets).toHaveLength(3);
				expect(statSync(path).mode & 0o777).toBe(0o600);
				const lines = records(result.stdout) as {
					type: string;
					status?: string;
					written?: { datagrams: number; bytes: number };
				}[];
				expect(lines.at(-1)).toMatchObject({
					status: "interrupted",
					written: { datagrams: 3, bytes: file.length },
				});
				await expectPortFree(port);
			},
		);

		test("--format pcapng through a real pipe: the bytes arrive whole", async () => {
			const proc = Bun.spawn(
				[
					process.execPath,
					"--no-env-file",
					BIN,
					"--port",
					"0",
					"--count",
					"2",
					"--format",
					"pcapng",
				],
				{ env, stdout: "pipe", stderr: "pipe" },
			);
			const killer = setTimeout(() => proc.kill("SIGKILL"), CHILD_MS);
			try {
				const stdout = new Response(proc.stdout).arrayBuffer();
				const reader = proc.stderr.getReader();
				let stderr = "";
				while (!stderr.includes("\n")) {
					const { value, done } = await reader.read();
					if (done) break;
					stderr += new TextDecoder().decode(value);
				}
				const port = Number(/:(\d+)/.exec(stderr)?.[1]);
				await send(port, [REQUEST, REQUEST]);
				expect(await proc.exited).toBe(0);
				const file = readPcapng(new Uint8Array(await stdout));
				expect(file.trailing).toBe(0);
				expect(
					file.packets.map((p) => Buffer.from(p.data).toString("hex")),
				).toEqual([REQUEST, REQUEST]);
			} finally {
				clearTimeout(killer);
				proc.kill("SIGKILL");
			}
		});

		test("--write naming the file stdout is redirected to: exit 2, the file left alone", async () => {
			const path = join(dir, "redirected.pcapng");
			const fd = openSync(path, "w");
			try {
				const proc = Bun.spawn(
					[
						process.execPath,
						"--no-env-file",
						BIN,
						"--count",
						"1",
						"--write",
						path,
						"--overwrite",
					],
					{ env, stdout: fd, stderr: "pipe" },
				);
				const killer = setTimeout(() => proc.kill("SIGKILL"), CHILD_MS);
				try {
					expect(await proc.exited).toBe(2);
					expect(await new Response(proc.stderr).text()).toContain(
						"error cli/write-to-output",
					);
				} finally {
					clearTimeout(killer);
					proc.kill("SIGKILL");
				}
			} finally {
				closeSync(fd);
			}
			expect(readFileSync(path).length).toBe(0);
		});

		test.if(process.platform !== "win32")(
			"--write naming the device stdout goes to: exit 2, refused before the bind",
			async () => {
				const fd = openSync("/dev/null", "w");
				try {
					const proc = Bun.spawn(
						[
							process.execPath,
							"--no-env-file",
							BIN,
							"--count",
							"1",
							"--write",
							"/dev/null",
						],
						{ env, stdout: fd, stderr: "pipe" },
					);
					const killer = setTimeout(() => proc.kill("SIGKILL"), CHILD_MS);
					try {
						expect(await proc.exited).toBe(2);
						expect(await new Response(proc.stderr).text()).toContain(
							"error cli/write-to-output",
						);
					} finally {
						clearTimeout(killer);
						proc.kill("SIGKILL");
					}
				} finally {
					closeSync(fd);
				}
			},
		);

		// libc pseudo-terminals: Linux and macOS.
		test.skipIf(process.platform === "win32")(
			"--format pcapng with stdout on a terminal: exit 2, nothing written there",
			async () => {
				const { master, slave } = openPty();
				try {
					const proc = Bun.spawn(
						[process.execPath, "--no-env-file", BIN, "--format", "pcapng"],
						{ env, stdout: slave, stderr: "pipe" },
					);
					const killer = setTimeout(() => proc.kill("SIGKILL"), CHILD_MS);
					try {
						expect(await proc.exited).toBe(2);
						expect(await new Response(proc.stderr).text()).toContain(
							"error cli/binary-to-terminal",
						);
					} finally {
						clearTimeout(killer);
						proc.kill("SIGKILL");
					}
				} finally {
					closeSync(slave);
					closeSync(master);
				}
			},
		);
	});
});
