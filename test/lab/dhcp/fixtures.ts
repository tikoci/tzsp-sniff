/**
 * Turn the DHCP lab's evidence into unit-test fixtures (test/fixtures/dhcp/):
 * one hex file per experiment and router pair (one TZSP datagram per line),
 * and index.json with each file's provenance, who sent each line, and what
 * the routers reported.
 *
 *   bun test/lab/dhcp/fixtures.ts
 *
 * Reads only test/lab/dhcp/evidence/, which is committed, so it gives the
 * same output on any checkout. The new set is built beside the old one and
 * checked (every run complete, every experiment present with the messages
 * it waited for, every datagram DHCP with a known sender) before it
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
import { dhcpView, type Evidence, type Sender, WANTS } from "./lab.ts";

const EVIDENCE = join(import.meta.dir, "evidence");
const FIXTURES = join(import.meta.dir, "..", "..", "fixtures");
const OUT = join(FIXTURES, "dhcp");
const NEXT = join(FIXTURES, ".dhcp-next");
const OLD = join(FIXTURES, ".dhcp-old");

export interface DhcpFixture {
	file: string;
	experiment: string;
	routeros: string;
	architecture: string;
	channel: string;
	accelerator: string;
	/** UTC date of the run. */
	date: string;
	/** Each line's sender and DHCP message type, in order. */
	lines: { sender: Sender; message: string }[];
	/** `server`'s ether1 MAC: its own dhcp-client's chaddr toward QEMU. */
	serverEther1: string;
	/** `server`'s ether2 MAC: the RouterOS DHCP server. */
	serverEther2: string;
	/** `client`'s ether2 MAC: the RouterOS dhcp-client on the L2 link. */
	clientEther2: string;
	/** The run's evidence, with every command and its output. */
	evidence: string;
}

async function build(): Promise<DhcpFixture[]> {
	await rm(NEXT, { recursive: true, force: true });
	await mkdir(NEXT, { recursive: true });
	const index: DhcpFixture[] = [];
	const names = (await readdir(EVIDENCE)).filter((f) => f.endsWith(".json"));
	for (const name of names.sort()) {
		const ev = JSON.parse(
			await readFile(join(EVIDENCE, name), "utf8"),
		) as Evidence;
		const server = ev.server;
		const client = ev.client;
		const version = server?.identity?.version;
		const serverEther1 = server?.macs.ether1;
		const serverEther2 = server?.macs.ether2;
		const clientEther2 = client?.macs.ether2;
		if (
			!server?.identity ||
			!version ||
			!serverEther1 ||
			!serverEther2 ||
			!clientEther2 ||
			ev.failure
		)
			throw new Error(`${name}: not a completed run`);
		const stem = `${version}-${ev.target.arch}`;
		for (const [want, wants] of Object.entries(WANTS)) {
			const exp = ev.experiments.find((e) => e.name === want);
			if (!exp) throw new Error(`${name}: no ${want} experiment`);
			const lines: DhcpFixture["lines"] = [];
			for (const d of exp.datagrams) {
				const view = dhcpView(Buffer.from(d.hex, "hex"));
				if (!view?.message || d.sender === "unknown")
					throw new Error(`${name} ${want}: a datagram with no sender or type`);
				if (view.message !== d.message)
					throw new Error(
						`${name} ${want}: ${d.message} now reads ${view.message}`,
					);
				lines.push({ sender: d.sender, message: view.message });
			}
			for (const [sender, message] of wants)
				if (!lines.some((l) => l.sender === sender && l.message === message))
					throw new Error(`${name} ${want}: no ${sender} ${message}`);
			const file = `${stem}-${want}.hex`;
			await writeFile(
				join(NEXT, file),
				`${exp.datagrams.map((d) => d.hex).join("\n")}\n`,
			);
			index.push({
				file,
				experiment: want,
				routeros: version,
				architecture: server.identity.architecture,
				channel: ev.target.channel,
				accelerator: ev.accelerator,
				date: ev.date.slice(0, 10),
				lines,
				serverEther1,
				serverEther2,
				clientEther2,
				evidence: `test/lab/dhcp/evidence/${name}`,
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
