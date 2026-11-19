/**
 * Turn the lab's evidence into unit-test fixtures (test/fixtures/routeros/):
 * one hex file per experiment and router (one datagram per line), the
 * RouterOS-saved capture file, and index.json with each file's provenance.
 *
 *   bun test/lab/tzsp-senders/fixtures.ts
 *
 * Reads only test/lab/tzsp-senders/evidence/, which is committed (JSON and
 * pcapng), so it gives the same output on any checkout. The new set is
 * built beside the old one and checked (every expected fixture present,
 * every datagram the lab's own traffic, every pcapng matching the SHA-256
 * its run recorded) before it replaces the old set; on any error the old
 * set stays.
 */
import { createHash } from "node:crypto";
import {
	mkdir,
	readdir,
	readFile,
	rename,
	rm,
	writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { classify, type Evidence } from "./lab.ts";

const EVIDENCE = join(import.meta.dir, "evidence");
const FIXTURES = join(import.meta.dir, "..", "..", "fixtures");
const OUT = join(FIXTURES, "routeros");
const NEXT = join(FIXTURES, ".routeros-next");
const OLD = join(FIXTURES, ".routeros-old");

/** Every fixture expected per architecture, after `<version>-<arch>-`. */
const EXPECTED: Record<string, string[]> = {
	x86: [
		"sniffer-stream.hex",
		"sniffer-only-headers.hex",
		"mangle-prerouting.hex",
		"mangle-input.hex",
		"mangle-output.hex",
		"mangle-postrouting.hex",
		"mangle-sniff-id.hex",
		"mangle-sniff-pc.hex",
		"mangle-self-output.hex",
		"mangle-self-postrouting.hex",
		"mangle-mirrors-sniffer.hex",
		"sniffer-file.pcapng",
		"sniffer-or-two-protocols.hex",
		"sniffer-filter-stream-yes.hex",
		"sniffer-filter-stream-no.hex",
	],
	arm64: ["sniffer-stream.hex"],
};

export interface FixtureEntry {
	file: string;
	experiment: string;
	routeros: string;
	architecture: string;
	channel: string;
	accelerator: string;
	/** UTC date of the run. */
	date: string;
	/** The host UDP port the router sent to: inner datagrams to it are the stream itself. */
	listenerPort: number;
	/** The run's evidence, with every command and its output. */
	evidence: string;
}

async function build(): Promise<FixtureEntry[]> {
	await rm(NEXT, { recursive: true, force: true });
	await mkdir(NEXT, { recursive: true });
	const index: FixtureEntry[] = [];
	const names = (await readdir(EVIDENCE)).filter((f) => f.endsWith(".json"));
	for (const name of names.sort()) {
		const ev = JSON.parse(
			await readFile(join(EVIDENCE, name), "utf8"),
		) as Evidence;
		if (!ev.router || ev.listenerPort === undefined || ev.failure)
			throw new Error(`${name}: not a completed run`);
		const port = ev.listenerPort;
		const stem = `${ev.router.version}-${ev.target.arch}`;
		const base = {
			routeros: ev.router.version ?? "",
			architecture: ev.router.architecture ?? "",
			channel: ev.target.channel,
			accelerator: ev.accelerator,
			date: ev.date.slice(0, 10),
			listenerPort: port,
			evidence: `test/lab/tzsp-senders/evidence/${name}`,
		};
		for (const exp of ev.experiments) {
			if (exp.name === "sniffer-file") {
				if (!ev.pcapng) throw new Error(`${name}: no pcapng recorded`);
				const bytes = await readFile(join(EVIDENCE, ev.pcapng.file));
				const sha = createHash("sha256").update(bytes).digest("hex");
				if (sha !== ev.pcapng.sha256)
					throw new Error(`${ev.pcapng.file}: not the file ${name} recorded`);
				const file = `${stem}-sniffer-file.pcapng`;
				await writeFile(join(NEXT, file), bytes);
				index.push({ file, experiment: exp.name, ...base });
				continue;
			}
			if (exp.datagrams.length === 0) continue;
			for (const d of exp.datagrams)
				if (classify(Buffer.from(d.hex, "hex"), port) === "other")
					throw new Error(`${name} ${exp.name}: not lab traffic`);
			const file = `${stem}-${exp.name}.hex`;
			await writeFile(
				join(NEXT, file),
				`${exp.datagrams.map((d) => d.hex).join("\n")}\n`,
			);
			index.push({ file, experiment: exp.name, ...base });
		}
		for (const want of EXPECTED[ev.target.arch] ?? [])
			if (!index.some((e) => e.file === `${stem}-${want}`))
				throw new Error(`${name}: no ${want}`);
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
		await rename(OUT, OLD).catch(() => {});
		await rename(NEXT, OUT);
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
