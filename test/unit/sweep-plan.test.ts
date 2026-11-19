import { describe, expect, test } from "bun:test";
import { plan } from "../../scripts/sweep-plan.ts";

const ACTIVE_ALL = ["stable", "long-term", "testing", "development"];

describe("plan", () => {
	test("boots each version once, listing every channel that resolved to it", () => {
		const versions = {
			stable: "7.25.1",
			"long-term": "7.24.6",
			testing: "7.25.1",
			development: "7.26beta5",
		};
		expect(plan(versions, ACTIVE_ALL)).toEqual([
			{ version: "7.25.1", channels: "stable, testing" },
			{ version: "7.24.6", channels: "long-term" },
			{ version: "7.26beta5", channels: "development" },
		]);
	});

	test("leaves out channels that are not active", () => {
		const versions = {
			stable: "7.25.1",
			"long-term": "7.24.6",
			testing: "7.25rc2",
			development: "7.26beta5",
		};
		expect(plan(versions, ["stable", "long-term", "development"])).toEqual([
			{ version: "7.25.1", channels: "stable" },
			{ version: "7.24.6", channels: "long-term" },
			{ version: "7.26beta5", channels: "development" },
		]);
	});

	test("refuses a channel that resolved to nothing or to a non-version", () => {
		expect(() =>
			plan({ stable: "", "long-term": "7.24.6" }, ["stable", "long-term"]),
		).toThrow('stable resolved to ""');
		expect(() =>
			plan({ stable: "7.25.1", "long-term": "unresolved" }, [
				"stable",
				"long-term",
			]),
		).toThrow('long-term resolved to "unresolved"');
	});

	test("refuses a plan without stable and long-term", () => {
		expect(() => plan({ stable: "7.25.1" }, ["stable"])).toThrow(
			"long-term is not in the plan",
		);
	});
});
