import { expect, test } from "bun:test";
import { join } from "node:path";
import { expectPortFree, stalledTerminal } from "../unit/helpers.ts";

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
