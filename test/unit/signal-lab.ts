/**
 * A lab for signal.test.ts, with quickchr stubbed: one create fails after
 * QEMU would have started (the test's `pgrep` reports a process for it), and
 * one never finishes starting. It prints `ready` once both are under way,
 * then waits for signals with the labs' own handler.
 */
import { mock } from "bun:test";
import * as real from "@tikoci/quickchr";

mock.module("@tikoci/quickchr", () => ({
	...real,
	QuickCHR: {
		get: () => null,
		listOrphans: () => [],
		start: ({ name }: { name: string }) =>
			name.startsWith("failed-")
				? Promise.reject(new Error("state write failed"))
				: new Promise(() => {}),
	},
}));

const lab = await import("../chr/quickchr.ts");
process.on("SIGINT", () => lab.onSignal("SIGINT"));
process.on("SIGTERM", () => lab.onSignal("SIGTERM"));

const target = { routeros: "stable", arch: "x86" } as const;
await lab.create("failed", target).catch(() => {});
lab.create("starting", target).catch(() => {});
setInterval(() => {}, 1000);
console.log("ready");
