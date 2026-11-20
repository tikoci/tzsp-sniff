import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { CODES } from "../../src/errors.ts";
import { VERSION } from "../../src/version.ts";

/**
 * The code registry is the source of truth (tikoci-cli-mcp, "Errors"): a
 * code used in src/ must be registered, and a registered code must be used.
 * Codes are literals here, so a scan of the source finds every one.
 */
const ROOT = join(import.meta.dir, "..", "..");
const SRC = join(ROOT, "src");

const sources = (readdirSync(SRC, { recursive: true }) as string[])
	.filter((f) => f.endsWith(".ts") && f !== "errors.ts")
	.map((f) => readFileSync(join(SRC, f), "utf8"));
const used = new Set(
	sources.flatMap((s) =>
		[
			...s.matchAll(
				/"((?:listen|capture|cli|filter|output|summary|tip|write)\/[a-z-]+)"/g,
			),
		].map((m) => m[1] as string),
	),
);

describe("code registry", () => {
	test("every code used in src/ is registered", () => {
		expect(used.size).toBeGreaterThan(10);
		for (const code of used)
			expect({ code, registered: code in CODES }).toEqual({
				code,
				registered: true,
			});
	});

	test("every registered code is used", () => {
		for (const code of Object.keys(CODES))
			expect({ code, used: used.has(code) }).toEqual({ code, used: true });
	});

	test("codes are family/slug, and their kind matches the family", () => {
		for (const [code, { kind }] of Object.entries(CODES)) {
			expect(code).toMatch(/^[a-z]+\/[a-z]+(?:-[a-z]+)*$/);
			expect({ code, tip: kind === "tip" }).toEqual({
				code,
				tip: code.startsWith("tip/"),
			});
		}
	});
});

test("VERSION matches package.json", () => {
	const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
		version: string;
	};
	expect(VERSION).toBe(pkg.version);
});
