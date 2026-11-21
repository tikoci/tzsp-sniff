/**
 * Turn the MNDP lab's evidence into unit-test fixtures (test/fixtures/mndp/):
 * one hex file per experiment and router (one TZSP datagram per line), and
 * index.json with each file's provenance and what the router reported.
 *
 *   bun test/lab/mndp/fixtures.ts
 *
 * Reads only test/lab/mndp/evidence/, which is committed, so it gives the
 * same output on any checkout. The new set is built beside the old one and
 * checked (every run complete, every experiment present with its header
 * count, every datagram a whole announcement that shows its setup, the
 * software id redacted) before it replaces the old set; on any error the
 * old set stays.
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
import { type Evidence, mndpView, PLAN, SHOWS } from "./lab.ts";

const EVIDENCE = join(import.meta.dir, "evidence");
const FIXTURES = join(import.meta.dir, "..", "..", "fixtures");
const OUT = join(FIXTURES, "mndp");
const NEXT = join(FIXTURES, ".mndp-next");
const OLD = join(FIXTURES, ".mndp-old");

export interface MndpFixture {
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
	/** `/system/resource` board-name. */
	board: string;
	/** The whole version string `/system/resource` reports, channel included. */
	versionString: string;
	/** The run's evidence, with every command and its output. */
	evidence: string;
}

async function build(): Promise<MndpFixture[]> {
	await rm(NEXT, { recursive: true, force: true });
	await mkdir(NEXT, { recursive: true });
	const index: MndpFixture[] = [];
	const names = (await readdir(EVIDENCE)).filter((f) => f.endsWith(".json"));
	for (const name of names.sort()) {
		const ev = JSON.parse(
			await readFile(join(EVIDENCE, name), "utf8"),
		) as Evidence;
		if (!ev.router || !ev.mac || !ev.identity || ev.failure)
			throw new Error(`${name}: not a completed run`);
		const stem = `${ev.router.version}-${ev.target.arch}`;
		for (const [want, , count] of PLAN) {
			const exp = ev.experiments.find((e) => e.name === want);
			if (!exp) throw new Error(`${name}: no ${want} experiment`);
			const headers = new Set<string>();
			for (const d of exp.datagrams) {
				const view = mndpView(Buffer.from(d.hex, "hex"));
				if (!view || !SHOWS[want]?.(view, ev.identity))
					throw new Error(
						`${name} ${want}: a datagram that does not show its setup`,
					);
				const id = view.fields.softwareId;
				if (id !== undefined && !/^X*$/.test(id))
					throw new Error(`${name} ${want}: a software id not redacted`);
				headers.add(view.fields.header);
			}
			if (headers.size !== count)
				throw new Error(
					`${name}: ${want} has ${headers.size} announcements, not ${count}`,
				);
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
				board: ev.router.board,
				versionString: ev.router.versionString,
				evidence: `test/lab/mndp/evidence/${name}`,
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
