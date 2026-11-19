/**
 * Turn the lab's evidence into unit-test fixtures (test/fixtures/routeros/):
 * one hex file per experiment and router (one datagram per line), the
 * RouterOS-saved capture file, and index.json with each file's provenance.
 *
 *   bun test/lab/tzsp-senders/fixtures.ts
 *
 * Kept: the datagrams an experiment received, minus MNDP announcements (they
 * carry the CHR's software id and identity, and no experiment is about them).
 * The loop experiment keeps the lab's first few datagrams only.
 */
import {
	copyFile,
	mkdir,
	readdir,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { biomeFormat, nesting } from "./lab.ts";

const EVIDENCE = join(import.meta.dir, "evidence");
const OUT = join(import.meta.dir, "..", "..", "fixtures", "routeros");

interface Evidence {
	target: { channel: string; arch: string };
	date: string;
	host: { os: string; accelerator: string };
	quickchr: string;
	router?: { version: string; architecture: string };
	listenerPort?: number;
	experiments: {
		name: string;
		steps: { command: string }[];
		datagrams: { hex: string }[];
	}[];
}

export interface FixtureEntry {
	file: string;
	experiment: string;
	routeros: string;
	architecture: string;
	channel: string;
	accelerator: string;
	date: string;
	/** The host UDP port the router sent to: inner datagrams to it are the stream itself. */
	listenerPort: number;
	commands: string[];
	evidence: string;
}

/** The innermost frame is UDP to or from port 5678 (MNDP). */
function isMndp(hex: string, port: number): boolean {
	let bytes = Buffer.from(hex, "hex");
	for (let i = 0; i <= nesting(hex, port); i++) {
		const eth = bytes.subarray(5);
		if (eth.length < 14 + 20 + 8 || eth.readUInt16BE(12) !== 0x0800)
			return false;
		const ip = eth.subarray(14);
		const udp = ip.subarray(((ip[0] ?? 0) & 0x0f) * 4);
		if (ip[9] !== 17) return false;
		if (udp.readUInt16BE(0) === 5678 || udp.readUInt16BE(2) === 5678)
			return true;
		bytes = udp.subarray(8);
	}
	return false;
}

if (import.meta.main) {
	await rm(OUT, { recursive: true, force: true });
	await mkdir(OUT, { recursive: true });
	const index: FixtureEntry[] = [];
	const files = (await readdir(EVIDENCE)).filter((f) => f.endsWith(".json"));
	for (const name of files.sort()) {
		const ev = JSON.parse(
			await readFile(join(EVIDENCE, name), "utf8"),
		) as Evidence;
		if (!ev.router || ev.listenerPort === undefined) continue;
		const port = ev.listenerPort;
		const base = {
			routeros: ev.router.version,
			architecture: ev.router.architecture,
			channel: ev.target.channel,
			accelerator: ev.host.accelerator,
			date: ev.date.slice(0, 10),
			listenerPort: port,
			evidence: `test/lab/tzsp-senders/evidence/${name}`,
		};
		const stem = `${ev.router.version}-${ev.target.arch}`;
		for (const exp of ev.experiments) {
			const lines = exp.datagrams
				.map((d) => d.hex)
				.filter((hex) => !isMndp(hex, port));
			const commands = exp.steps.map((s) => s.command);
			if (exp.name === "sniffer-file") {
				const pcap = `${stem}-sniffer-file.pcapng`;
				try {
					await copyFile(join(EVIDENCE, pcap), join(OUT, pcap));
					index.push({ file: pcap, experiment: exp.name, commands, ...base });
				} catch {
					// No file came back from the router; REPORT.md says why.
				}
				continue;
			}
			if (lines.length === 0) continue;
			const file = `${stem}-${exp.name}.hex`;
			await writeFile(join(OUT, file), `${lines.join("\n")}\n`);
			index.push({ file, experiment: exp.name, commands, ...base });
		}
	}
	await writeFile(
		join(OUT, "index.json"),
		`${JSON.stringify(index, null, "\t")}\n`,
	);
	await biomeFormat(join(OUT, "index.json"));
	console.log(`${index.length} fixtures in ${OUT}`);
}
