/**
 * Lab: what LLDP RouterOS sends on its own, as `/tool/sniffer` streams it
 * (issue #26). Not a test tier: run by hand, never a gate. REPORT.md says
 * what it showed; `fixtures.ts` turns evidence/ into test/fixtures/lldp/.
 *
 *   bun test/lab/lldp/lab.ts                 # x86 stable, x86 long-term, arm64 stable
 *   bun test/lab/lldp/lab.ts --only x86:stable
 *
 * Safety, as in test/lab/tzsp-senders/: each router is a machine this run
 * creates and owns (`tzsp-lab-lldp-<channel>-<arch>-<random>`), removed when
 * the run ends, fails or gets SIGINT or SIGTERM, with removal verified
 * (test/chr/quickchr.ts). A second signal exits at once, naming what is left.
 *
 * Capture. One UDP listener per router on 127.0.0.1, port 0; the sniffer
 * streams everything on ether1 to the SLIRP gateway with `filter-stream=yes`
 * (without it the stream captures itself, #5). Only datagrams whose frame
 * has EtherType 0x88cc are kept; the rest are counted.
 *
 * Experiments, one after another, each waiting for LLDPDUs sent after its
 * setup (RouterOS sends one per `discover-interval`, 30 s by default):
 *
 * - `default`: the discovery settings as booted; two LLDPDUs, to see the
 *   interval.
 * - `optional-tlvs`: `lldp-vlan-info`, `lldp-mac-phy-config` and
 *   `lldp-max-frame-size` on, to see which org-specific TLVs follow.
 * - `identity-utf8`: a system identity with a non-ASCII letter, to see how
 *   the system name TLV encodes it.
 *
 * Output. Every experiment must see its LLDPDUs before anything is written
 * to evidence/<version>-<arch>.json; a failed run writes to
 * .scratch/lldp-lab/ instead.
 */
import { createSocket, type Socket } from "node:dgram";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseTzsp, toHex } from "../../../src/tzsp.ts";
import {
	accelerator,
	cleanupAll,
	create,
	leftOver,
	owned,
	ROOT,
	services,
	stop,
	teardown,
	version,
} from "../../chr/quickchr.ts";
import { GATEWAY, Router } from "../../chr/router.ts";

const EVIDENCE = join(import.meta.dir, "evidence");
const FAILED = join(ROOT, ".scratch", "lldp-lab");
/** Two default intervals and a margin: one LLDPDU is due within 30 s. */
const WAIT_MS = 75_000;
/** The identity the `identity-utf8` experiment sets: "é" is two bytes in UTF-8. */
export const UTF8_IDENTITY = "lab-café";

export interface Target {
	channel: string;
	arch: "x86" | "arm64";
}

export interface Datagram {
	/** Milliseconds since the experiment's setup finished. */
	at: number;
	/** The whole TZSP datagram, as received. */
	hex: string;
}

export interface Experiment {
	name: string;
	setup: string[];
	datagrams: Datagram[];
}

export interface Evidence {
	target: Target;
	machine: string;
	date: string;
	accelerator: string;
	quickchr: string;
	bootMs?: number;
	listenerPort?: number;
	router?: Awaited<ReturnType<Router["identity"]>>;
	/** `/ip/neighbor/discovery-settings/export verbose`, as booted. */
	discovery?: string;
	/** ether1's MAC address, as `/interface/ethernet` reports it. */
	mac?: string | undefined;
	/** `/system/identity`'s name, as booted. */
	identity?: string | undefined;
	addresses?: string;
	ipv6?: string;
	/** Datagrams seen that were not LLDP, counted. */
	other: number;
	experiments: Experiment[];
	failure?: string;
}

/** The frame inside a TZSP datagram has EtherType 0x88cc (no VLAN tag on ether1). */
export function isLldp(datagram: Uint8Array): boolean {
	const d = parseTzsp(datagram);
	if (d.kind !== "packet" || !d.payload) return false;
	return d.payload[12] === 0x88 && d.payload[13] === 0xcc;
}

export class Listener {
	private sock: Socket | undefined;
	private start = 0;
	kept: Datagram[] = [];
	other = 0;
	/** A socket error after the bind, which fails the experiment waiting. */
	private failed: Error | undefined;
	async open(): Promise<number> {
		const sock = createSocket("udp4");
		this.sock = sock;
		// An error rejects the bind, or fails the next wait, so it reaches the
		// caller's catch and the machine is still removed in its finally.
		const bound = new Promise<void>((resolve, reject) => {
			sock.once("error", reject);
			sock.bind(0, "127.0.0.1", () => {
				sock.off("error", reject);
				sock.on("error", (e) => {
					this.failed = e;
				});
				resolve();
			});
		});
		sock.on("message", (msg) => {
			const b = new Uint8Array(msg);
			if (isLldp(b))
				this.kept.push({ at: Date.now() - this.start, hex: toHex(b) });
			else this.other++;
		});
		await bound;
		return sock.address().port;
	}
	/** Start a new experiment: what arrives from now on is its own. */
	reset(): void {
		this.kept = [];
		this.start = Date.now();
	}
	async waitFor(count: number): Promise<Datagram[]> {
		const until = Date.now() + WAIT_MS;
		while (this.kept.length < count && Date.now() < until) {
			if (interrupted) throw new Error("interrupted");
			if (this.failed) throw this.failed;
			await new Promise((r) => setTimeout(r, 500));
		}
		if (this.failed) throw this.failed;
		if (this.kept.length < count)
			throw new Error(
				`${this.kept.length} of ${count} LLDPDUs in ${WAIT_MS / 1000} s`,
			);
		return this.kept.slice(0, count);
	}
	close(): void {
		this.sock?.close();
	}
}

let interrupted: "SIGINT" | "SIGTERM" | undefined;
function onSignal(signal: "SIGINT" | "SIGTERM"): void {
	if (interrupted) {
		for (const n of owned.keys()) console.error(`NOT REMOVED: ${n}`);
		process.exit(signal === "SIGINT" ? 130 : 143);
	}
	interrupted = signal;
	console.error(`${signal}: stopping, then removing this run's machines`);
	stop();
}

const field = (output: string, name: string) =>
	new RegExp(`${name}=("[^"]*"|\\S+)`).exec(output)?.[1]?.replace(/"/g, "");

async function experiment(
	router: Router,
	listener: Listener,
	name: string,
	setup: string[],
	count: number,
): Promise<Experiment> {
	for (const command of setup) await router.exec(command);
	listener.reset();
	return { name, setup, datagrams: await listener.waitFor(count) };
}

async function lab(target: Target): Promise<boolean> {
	const ev: Evidence = {
		target,
		machine: "",
		date: new Date().toISOString(),
		accelerator: "",
		quickchr: await version(),
		other: 0,
		experiments: [],
	};
	const listener = new Listener();
	let ok = false;
	try {
		const made = await create(
			`tzsp-lab-lldp-${target.channel}-${target.arch}`,
			{
				routeros: target.channel,
				arch: target.arch,
			},
		);
		ev.machine = made.name;
		if (made.bootMs !== undefined) ev.bootMs = made.bootMs;
		ev.accelerator = accelerator(ev.machine);
		ev.listenerPort = await listener.open();
		const { restUrl, basic } = await services(ev.machine);
		const router = new Router(restUrl, basic);
		ev.router = await router.identity();
		ev.discovery = (
			await router.exec("/ip/neighbor/discovery-settings/export verbose")
		).output;
		ev.mac = field(
			(await router.exec("/interface/ethernet/print detail where name=ether1"))
				.output,
			"mac-address",
		)?.toLowerCase();
		ev.identity = /name: (.*)/
			.exec((await router.exec("/system/identity/print")).output)?.[1]
			?.trim();
		ev.addresses = (await router.exec("/ip/address/print detail")).output;
		ev.ipv6 = (await router.exec("/ipv6/address/print detail")).output;
		await router.exec(
			`/tool/sniffer/set streaming-enabled=yes streaming-server=${GATEWAY}:${ev.listenerPort} ` +
				`filter-mac-protocol="" filter-ip-address="" filter-ip-protocol="" ` +
				`filter-stream=yes only-headers=no file-name=""`,
		);
		await router.exec("/tool/sniffer/start");
		await router.sniffing();
		ev.experiments.push(
			await experiment(router, listener, "default", [], 2),
			await experiment(
				router,
				listener,
				"optional-tlvs",
				[
					"/ip/neighbor/discovery-settings/set lldp-vlan-info=yes lldp-mac-phy-config=yes lldp-max-frame-size=yes",
				],
				1,
			),
			await experiment(
				router,
				listener,
				"identity-utf8",
				[`/system/identity/set name="${UTF8_IDENTITY}"`],
				1,
			),
		);
		await router.exec("/tool/sniffer/stop");
		ok = true;
	} catch (e) {
		ev.failure = e instanceof Error ? e.message : String(e);
		if (e && typeof e === "object" && "step" in e)
			ev.failure += ` (${JSON.stringify((e as { step: unknown }).step)})`;
	} finally {
		ev.other = listener.other;
		try {
			listener.close();
		} catch {}
		if (ev.machine && owned.has(ev.machine) && !(await teardown(ev.machine)))
			console.error(leftOver(ev.machine));
	}
	const stem = `${ev.router?.version || target.channel}-${target.arch}`;
	const dir = ok ? EVIDENCE : FAILED;
	await mkdir(dir, { recursive: true });
	await writeFile(
		join(dir, `${stem}.json`),
		`${JSON.stringify(ev, null, "\t")}\n`,
	);
	console.log(
		`${ev.machine || stem}: ${ok ? "done" : `FAILED: ${ev.failure}`} -> ${join(dir, `${stem}.json`)}`,
	);
	return ok;
}

if (import.meta.main) {
	process.on("SIGINT", () => onSignal("SIGINT"));
	process.on("SIGTERM", () => onSignal("SIGTERM"));
	const only = process.argv.indexOf("--only");
	const all: Target[] = [
		{ channel: "stable", arch: "x86" },
		{ channel: "long-term", arch: "x86" },
		{ channel: "stable", arch: "arm64" },
	];
	const pick = only >= 0 ? (process.argv[only + 1] ?? "").split(",") : [];
	const targets =
		pick.length > 0
			? all.filter((t) => pick.includes(`${t.arch}:${t.channel}`))
			: all;
	if (targets.length === 0 || targets.length < pick.length) {
		console.error(
			`--only takes one or more of ${all.map((t) => `${t.arch}:${t.channel}`).join(",")}`,
		);
		process.exit(2);
	}
	// Each router has its own listener and waits mostly on the router's
	// interval, so all run at once.
	const results = await Promise.allSettled(targets.map((t) => lab(t)));
	const left = await cleanupAll();
	for (const n of left) console.error(leftOver(n));
	const failed = results.some((r) => r.status === "rejected" || !r.value);
	if (interrupted) process.exit(interrupted === "SIGINT" ? 130 : 143);
	process.exit(failed || left.length > 0 ? 1 : 0);
}
