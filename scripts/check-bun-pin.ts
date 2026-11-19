#!/usr/bin/env bun
/**
 * check-bun-pin: the tested Bun changes only through a reviewed diff
 * (tikoci-toolchain, "One Bun pin"). Adapted from tikoci/quickchr
 * scripts/check-bun-pin.ts, which reads `.bun-version`; the house pin is
 * package.json `packageManager`.
 *
 * Asserts:
 *   - `packageManager` is one exact `bun@x.y.z`;
 *   - `@types/bun` is the same exact version, and `engines.bun` allows it;
 *   - every `oven-sh/setup-bun` step reads `bun-version-file: package.json` in
 *     its own `with:`, after `actions/checkout`; the one inline `bun-version`
 *     allowed is `${{ env.BUN_VERSION }}`, with BUN_VERSION defined at the
 *     workflow level (the tikoci-ci dispatch override).
 *
 * Workflows are YAML-parsed, not scanned by line: a key under `env:` is
 * invisible to the action, and an indentation scan would accept it.
 */
import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";

interface Step {
	uses?: unknown;
	with?: Record<string, unknown>;
}
interface Workflow {
	env?: Record<string, unknown>;
	jobs?: Record<string, { steps?: Step[] }>;
}
interface PackageJson {
	packageManager?: unknown;
	engines?: { bun?: unknown };
	devDependencies?: Record<string, unknown>;
}

const SETUP_BUN = "oven-sh/setup-bun@";
/** The one inline bun-version allowed: a GitHub expression, not a JS template. */
// biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, compared as text
export const OVERRIDE = "${{ env.BUN_VERSION }}";

/** Every violation, one line each; empty means the pin holds. */
export function checkBunPin(
	pkg: PackageJson,
	workflows: Record<string, string>,
): string[] {
	const errors: string[] = [];
	const match = /^bun@(\d+\.\d+\.\d+)$/.exec(String(pkg.packageManager ?? ""));
	const pin = match?.[1];
	if (!pin) {
		errors.push(
			`package.json packageManager is ${JSON.stringify(pkg.packageManager ?? null)}, expected one exact "bun@x.y.z"`,
		);
	} else {
		const types = pkg.devDependencies?.["@types/bun"];
		if (types !== pin) {
			errors.push(
				`package.json devDependencies @types/bun is ${JSON.stringify(types ?? null)}, expected "${pin}" (it moves with the pin)`,
			);
		}
		const floor = pkg.engines?.bun;
		if (typeof floor !== "string" || !Bun.semver.satisfies(pin, floor)) {
			errors.push(
				`package.json engines.bun ${JSON.stringify(floor ?? null)} does not allow the pin ${pin}`,
			);
		}
	}

	for (const [file, text] of Object.entries(workflows)) {
		let workflow: Workflow;
		try {
			workflow = Bun.YAML.parse(text) as Workflow;
		} catch (error) {
			errors.push(`${file}: not valid YAML (${String(error)})`);
			continue;
		}
		const overrideDefined =
			typeof workflow?.env?.BUN_VERSION === "string" &&
			workflow.env.BUN_VERSION.includes("inputs.bun-version");
		for (const [jobName, job] of Object.entries(workflow?.jobs ?? {})) {
			const where = `${file} / ${jobName}`;
			let checkedOut = false;
			for (const step of job?.steps ?? []) {
				const uses = typeof step?.uses === "string" ? step.uses : "";
				if (uses.includes("actions/checkout")) checkedOut = true;
				if (!uses.includes(SETUP_BUN)) continue;
				const inputs = step.with ?? {};
				if (inputs["bun-version-file"] !== "package.json") {
					errors.push(
						`${where}: setup-bun needs with.bun-version-file: package.json (found ${JSON.stringify(inputs["bun-version-file"] ?? null)})`,
					);
				}
				if ("bun-version" in inputs) {
					if (inputs["bun-version"] !== OVERRIDE) {
						errors.push(
							`${where}: inline bun-version ${JSON.stringify(inputs["bun-version"])}; only ${OVERRIDE} is allowed`,
						);
					} else if (!overrideDefined) {
						errors.push(
							`${where}: uses ${OVERRIDE} but the workflow does not define env.BUN_VERSION from inputs.bun-version`,
						);
					}
				}
				if (!checkedOut) {
					errors.push(
						`${where}: setup-bun runs before actions/checkout, so package.json is not on disk yet`,
					);
				}
			}
		}
	}
	return errors;
}

if (import.meta.main) {
	const root = resolve(import.meta.dir, "..");
	const dir = join(root, ".github", "workflows");
	const workflows: Record<string, string> = {};
	for (const name of readdirSync(dir).sort()) {
		if (name.endsWith(".yml") || name.endsWith(".yaml")) {
			workflows[name] = await Bun.file(join(dir, name)).text();
		}
	}
	const pkg = (await Bun.file(
		join(root, "package.json"),
	).json()) as PackageJson;
	const errors = checkBunPin(pkg, workflows);
	if (errors.length > 0) {
		console.error(
			`check-bun-pin: ${errors.length} violation(s)\n  ${errors.join("\n  ")}`,
		);
		process.exit(1);
	}
	console.log("check-bun-pin: OK");
}
