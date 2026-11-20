import { expect, test } from "bun:test";
import { join } from "node:path";
import {
	expectPortFree,
	fixture,
	interruptWithStdinOpen,
	stalledTerminal,
} from "../unit/helpers.ts";

/**
 * The built executable under Node with stdout on a terminal nobody reads.
 * Bun drives the test (libc pseudo-terminal through bun:ffi); Node runs the
 * CLI, from dist/, so this runs after `bun run build` (`bun run
 * test:node-terminal`, and CI's Node smoke job). Bun's own case is in
 * test/unit/bin.test.ts.
 */
const BIN = join(import.meta.dir, "..", "..", "dist", "cli", "bin.js");
const BUDGET_MS = 8000;

test.skipIf(process.platform === "win32")(
	"node: stdout on a terminal nobody reads: SIGINT ends it with output/stalled, port freed",
	async () => {
		const result = await stalledTerminal(["node", BIN], BUDGET_MS);
		expect(result.runningBeforeInterrupt).toBe(true);
		expect(result.code).toBe(1);
		expect(result.stderr).toContain("error output/stalled");
		expect(result.ms).toBeLessThan(BUDGET_MS);
		await expectPortFree(result.port);
	},
	BUDGET_MS * 2,
);

test.skipIf(process.platform === "win32")(
	"node: decode - with stdin left open: Ctrl-C ends it, after a packet and before the format is known",
	async () => {
		const request = fixture("7.25.1-x86-sniffer-stream")[0] as string;
		const started = await interruptWithStdinOpen(
			["node", BIN, "decode", "-", "--input", "hex", "--format", "jsonl"],
			new TextEncoder().encode(`${request}\n`),
			{ ready: /"type":"packet"/, budgetMs: BUDGET_MS },
		);
		expect(started.code).toBe(0);
		expect(started.ms).toBeLessThan(BUDGET_MS / 2);
		expect(started.stdout.trimEnd().split("\n").at(-1)).toContain(
			'"status":"interrupted"',
		);
		const detecting = await interruptWithStdinOpen(
			["node", BIN, "decode", "-"],
			Uint8Array.of(0x0a, 0x0d),
			{ settleMs: 500, budgetMs: BUDGET_MS },
		);
		expect(detecting.code).toBe(130);
		expect(detecting.ms).toBeLessThan(BUDGET_MS / 2);
	},
	BUDGET_MS * 4,
);
