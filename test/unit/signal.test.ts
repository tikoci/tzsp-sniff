/**
 * The labs' second signal exits at once and names every machine the run may
 * have left (tikoci-testing, "`finally` does not run on an unhandled
 * signal"). quickchr is stubbed (signal-lab.ts); no machine is booted.
 */
import { expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { childEnv, until } from "./helpers.ts";

// A `pgrep` that finds a QEMU for every name; POSIX signals and a shell
// script, so not on Windows.
test.skipIf(process.platform === "win32")(
	"a second signal names a failed create and one still starting",
	async () => {
		const bin = mkdtempSync(join(tmpdir(), "tzsp-sniff-pgrep-"));
		writeFileSync(join(bin, "pgrep"), "#!/bin/sh\necho 4242\n");
		chmodSync(join(bin, "pgrep"), 0o755);
		const env = childEnv();
		env.PATH = `${bin}${delimiter}${env.PATH}`;
		const proc = Bun.spawn(["bun", join(import.meta.dir, "signal-lab.ts")], {
			env,
			stdin: "ignore",
			stdout: "pipe",
			stderr: "pipe",
		});
		const killer = setTimeout(() => proc.kill("SIGKILL"), 15_000);
		try {
			let stderr = "";
			const drained = (async () => {
				const decoder = new TextDecoder();
				for await (const chunk of proc.stderr)
					stderr += decoder.decode(chunk, { stream: true });
			})();
			const stdout = new Response(proc.stdout).text();
			await until(() => /machine: starting-/.test(stderr), 10_000);
			proc.kill("SIGINT");
			await until(() => /SIGINT: stopping/.test(stderr), 10_000);
			proc.kill("SIGINT");
			expect(await proc.exited).toBe(130);
			await drained;
			expect(await stdout).toContain("ready");
			expect(stderr).toMatch(
				/NOT REMOVED: failed-[0-9a-f]{8}: .*\/machines\/failed-[0-9a-f]{8}\//,
			);
			expect(stderr).toMatch(
				/NOT REMOVED: starting-[0-9a-f]{8}: .*\/machines\/starting-[0-9a-f]{8}\//,
			);
		} finally {
			clearTimeout(killer);
			proc.kill("SIGKILL");
			rmSync(bin, { recursive: true, force: true });
		}
	},
);
