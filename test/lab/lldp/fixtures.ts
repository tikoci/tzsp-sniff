/**
 * Turn the LLDP lab's evidence into unit-test fixtures (test/fixtures/lldp/):
 * one hex file per experiment and router (one TZSP datagram per line), and
 * index.json with each file's provenance and what the router reported.
 *
 *   bun test/lab/lldp/fixtures.ts
 *
 * Reads only test/lab/lldp/evidence/, which is committed, so it gives the
 * same output on any checkout. The new set is built beside the old one and
 * checked (every run complete, every experiment present with its count,
 * every datagram an LLDPDU that shows its experiment's setup) before it
 * replaces the old set; on any error the old set stays.
 */
import {
	mkdir,
	readdir,
	readFile,
	rename,
	rm,
	writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { type Evidence, lldpView, SHOWS } from "./lab.ts";

const EVIDENCE = join(import.meta.dir, "evidence");
const FIXTURES = join(import.meta.dir, "..", "..", "fixtures");
const OUT = join(FIXTURES, "lldp");
const NEXT = join(FIXTURES, ".lldp-next");
const OLD = join(FIXTURES, ".lldp-old");

/** Each experiment, and the LLDPDUs its run must have kept (lab.ts). */
const EXPERIMENTS: Record<string, number> = {
	default: 2,
	"optional-tlvs": 1,
	"identity-utf8": 1,
};

export interface LldpFixture {
	file: string;
	experiment: string;
	routeros: string;
	architecture: string;
	channel: string;
	accelerator: string;
	/** UTC date of the run. */
	date: string;
	/** ether1's MAC address, as the router reported it. */
	mac: string;
	/** The system identity, as booted (the `identity-utf8` experiment changes it). */
	identity: string;
	/** The run's evidence, with every command and its output. */
	evidence: string;
}

async function build(): Promise<LldpFixture[]> {
	await rm(NEXT, { recursive: true, force: true });
	await mkdir(NEXT, { recursive: true });
	const index: LldpFixture[] = [];
	const names = (await readdir(EVIDENCE)).filter((f) => f.endsWith(".json"));
	for (const name of names.sort()) {
		const ev = JSON.parse(
			await readFile(join(EVIDENCE, name), "utf8"),
		) as Evidence;
		if (!ev.router || !ev.mac || !ev.identity || ev.failure)
			throw new Error(`${name}: not a completed run`);
		const stem = `${ev.router.version}-${ev.target.arch}`;
		for (const [want, count] of Object.entries(EXPERIMENTS)) {
			const exp = ev.experiments.find((e) => e.name === want);
			if (exp?.datagrams.length !== count)
				throw new Error(
					`${name}: ${want} has ${exp?.datagrams.length ?? 0} LLDPDUs, not ${count}`,
				);
			for (const d of exp.datagrams) {
				const view = lldpView(Buffer.from(d.hex, "hex"));
				if (!view || !SHOWS[want]?.(view, ev.identity))
					throw new Error(
						`${name} ${want}: an LLDPDU that does not show its setup`,
					);
			}
			const file = `${stem}-${want}.hex`;
			await writeFile(
				join(NEXT, file),
				`${exp.datagrams.map((d) => d.hex).join("\n")}\n`,
			);
			index.push({
				file,
				experiment: want,
				routeros: ev.router.version,
				architecture: ev.router.architecture,
				channel: ev.target.channel,
				accelerator: ev.accelerator,
				date: ev.date.slice(0, 10),
				mac: ev.mac,
				identity: ev.identity,
				evidence: `test/lab/lldp/evidence/${name}`,
			});
		}
	}
	await writeFile(
		join(NEXT, "index.json"),
		`${JSON.stringify(index, null, "\t")}\n`,
	);
	return index;
}

if (import.meta.main) {
	try {
		const index = await build();
		await rm(OLD, { recursive: true, force: true });
		const hadOld = await rename(OUT, OLD).then(
			() => true,
			() => false,
		);
		try {
			await rename(NEXT, OUT);
		} catch (e) {
			if (hadOld) await rename(OLD, OUT);
			throw e;
		}
		await rm(OLD, { recursive: true, force: true });
		console.log(`${index.length} fixtures in ${OUT}`);
	} catch (e) {
		await rm(NEXT, { recursive: true, force: true });
		console.error(
			`fixtures not changed: ${e instanceof Error ? e.message : String(e)}`,
		);
		process.exit(1);
	}
}
