import { describe, expect, test } from "bun:test";
import { checkBunPin, OVERRIDE } from "../../scripts/check-bun-pin.ts";

const pkg = {
	packageManager: "bun@1.4.4",
	engines: { bun: ">=1.4.4" },
	devDependencies: { "@types/bun": "1.4.4" },
};

const workflow = (setup: string, env = "") => `
name: CI
${env}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
${setup}
`;
const setupBun = (
	extra = "",
) => `      - uses: oven-sh/setup-bun@0000000000000000000000000000000000000000 # v2
        with:
          bun-version-file: package.json${extra}`;
const OVERRIDE_ENV =
	// biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression in workflow YAML
	"env:\n  BUN_VERSION: ${{ github.event_name == 'schedule' && 'latest' || inputs.bun-version }}";

describe("checkBunPin", () => {
	test("accepts the pin, matching types and a setup-bun step that reads it", () => {
		expect(checkBunPin(pkg, { "ci.yml": workflow(setupBun()) })).toEqual([]);
	});

	test("accepts the dispatch override when the workflow defines it", () => {
		const step = setupBun(`\n          bun-version: ${OVERRIDE}`);
		expect(
			checkBunPin(pkg, { "ci.yml": workflow(step, OVERRIDE_ENV) }),
		).toEqual([]);
	});

	test("rejects a range, mismatched types and an engines floor above the pin", () => {
		const errors = checkBunPin(
			{
				packageManager: "bun@^1.4.4",
				engines: { bun: ">=1.4.4" },
				devDependencies: {},
			},
			{},
		);
		expect(errors.join("\n")).toContain("expected one exact");
		const more = checkBunPin(
			{
				packageManager: "bun@1.4.4",
				engines: { bun: ">=1.5.0" },
				devDependencies: { "@types/bun": "1.4.3" },
			},
			{},
		);
		expect(more).toHaveLength(2);
		expect(more.join("\n")).toContain("@types/bun");
		expect(more.join("\n")).toContain("engines.bun");
	});

	test("rejects an inline version, a missing version file and setup before checkout", () => {
		const inline = setupBun("\n          bun-version: latest");
		expect(checkBunPin(pkg, { "a.yml": workflow(inline) }).join()).toContain(
			"inline bun-version",
		);
		const override = setupBun(`\n          bun-version: ${OVERRIDE}`);
		expect(checkBunPin(pkg, { "b.yml": workflow(override) }).join()).toContain(
			"does not define env.BUN_VERSION",
		);
		const noFile = `      - uses: oven-sh/setup-bun@0000000000000000000000000000000000000000 # v2`;
		expect(checkBunPin(pkg, { "c.yml": workflow(noFile) }).join()).toContain(
			"bun-version-file",
		);
		const early = `
jobs:
  test:
    steps:
${setupBun()}
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
`;
		expect(checkBunPin(pkg, { "d.yml": early }).join()).toContain(
			"before actions/checkout",
		);
	});
});
