/**
 * The nightly sweep's matrix (.github/workflows/sweep.yml): every active
 * RouterOS channel, booted once per resolved version (tikoci-testing,
 * "RouterOS versions"). Which channels are active is quickchr's
 * `selectActiveChannels`: stable and long-term always, a pre-release channel
 * when it is at or ahead of stable.
 *
 *   bun scripts/sweep-plan.ts
 *
 * Prints the matrix and, in CI, writes `matrix=<json>` to $GITHUB_OUTPUT.
 */
import { appendFile } from "node:fs/promises";

export interface Leg {
	/** The version to boot. */
	version: string;
	/** The channels that resolved to it, for job names and the summary. */
	channels: string;
}

const VERSION = /^\d+\.\d+(\.\d+)?(beta\d+|rc\d+)?$/;
const REQUIRED = ["stable", "long-term"];

/** Group the active channels by the version each resolved to, in channel order. */
export function plan(
	versions: Record<string, string>,
	active: string[],
): Leg[] {
	for (const channel of REQUIRED)
		if (!active.includes(channel))
			throw new Error(`${channel} is not in the plan`);
	const legs: Leg[] = [];
	for (const channel of active) {
		const version = versions[channel] ?? "";
		if (!VERSION.test(version))
			throw new Error(`${channel} resolved to ${JSON.stringify(version)}`);
		const leg = legs.find((l) => l.version === version);
		if (leg) leg.channels += `, ${channel}`;
		else legs.push({ version, channels: channel });
	}
	return legs;
}

if (import.meta.main) {
	// quickchr ships TypeScript source that this repo's tsc settings reject
	// (exactOptionalPropertyTypes), so it is imported by a name tsc does not
	// resolve and typed here by what this script uses (test/chr/quickchr.ts).
	const name: string = "@tikoci/quickchr";
	const quickchr = (await import(name)) as {
		resolveAllVersions(): Promise<Record<string, string>>;
		selectActiveChannels(versions: Record<string, string>): string[];
	};
	const versions = await quickchr.resolveAllVersions();
	const legs = plan(versions, quickchr.selectActiveChannels(versions));
	const matrix = JSON.stringify(legs);
	console.log(`resolved: ${JSON.stringify(versions)}`);
	console.log(`matrix=${matrix}`);
	if (process.env.GITHUB_OUTPUT)
		await appendFile(process.env.GITHUB_OUTPUT, `matrix=${matrix}\n`);
}
