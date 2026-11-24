/**
 * Lab: what MNDP RouterOS sends on its own, as `/tool/sniffer` streams it
 * (issue #31). Not a test tier: run by hand, never a gate. REPORT.md says
 * what it showed, against m2ir's profile; `fixtures.ts` turns evidence/
 * into test/fixtures/mndp/.
 *
 *   bun test/lab/mndp/lab.ts                 # stable and long-term, x86 and arm64
 *   bun test/lab/mndp/lab.ts --only x86:stable
 *
 * Safety, as in test/lab/lldp/: each router is a machine this run creates
 * and owns (`tzsp-lab-mndp-<channel>-<arch>-<random>`), removed when the run
 * ends, fails or gets SIGINT or SIGTERM, with removal verified
 * (test/chr/quickchr.ts). A second signal exits at once, naming what is left.
 *
 * Capture. One UDP listener per router on 127.0.0.1, port 0; the sniffer
 * streams everything on ether1 to the SLIRP gateway with `filter-stream=yes`
 * (#5). Only datagrams whose frame is UDP to or from port 5678, over IPv4 or
 * IPv6, are kept; the rest are counted.
 *
 * Experiments, one after another. Each keeps the announcements that show
 * its setup (`SHOWS`) until it has seen `count` different header values
 * (an IPv4 announcement and its IPv6 copy share one), then 2 s more for a
 * late copy:
 *
 * - `default`: as booted; two announcements, to see the counter advance.
 * - `discover-interval`: `discover-interval=10s`, to see TLV 19 follow
 *   m2ir's formula (10 × 4 + 1 = 41), and to make the rest quick.
 * - `identity-utf8`: an identity with a non-ASCII letter, for TLV 5.
 * - `packing`: an `/ip/packing` entry on ether1 with `unpacking=compress-all
 *   aggregated-size=1500`, for TLVs 2, 3, 4 and 9 (m2ir saw them on
 *   7.26beta5 x86_64 only; TLV 9's byte order elsewhere is its open question).
 * - `ipv6-disabled`: `disable-ipv6=yes`, then the next two announcements
 *   after the setup is done, whatever they carry: what TLV 14 and TLV 15 do
 *   on this version (m2ir did not test 7.21 to 7.25).
 *
 * Redaction. TLV 11 is the license software id, which m2ir says to treat
 * as device-identifying, and which the other labs keep out of the repo
 * (test/chr/router.ts `withoutComments`). Its value is overwritten with as
 * many `X` bytes (0x58) before a datagram is kept, so lengths and offsets
 * stay as sent; no checksum here covers it.
 *
 * Output. Every experiment must see its announcements before anything is
 * written to evidence/<version>-<arch>.json; a failed run writes to
 * .scratch/mndp-lab/ instead.
 */
import { createSocket, type Socket } from "node:dgram";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { dissect, type MndpFields } from "../../../src/dissect.ts";
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
import { Router, snifferStreamAll } from "../../chr/router.ts";

const EVIDENCE = join(import.meta.dir, "evidence");
const FAILED = join(ROOT, ".scratch", "mndp-lab");
/** Two default intervals and a margin: one announcement is due within 30 s. */
const WAIT_MS = 75_000;
/** After the last header an experiment waits for, for its IPv6 copy. */
const COPY_MS = 2_000;
/** The identity the `identity-utf8` experiment sets: "é" is two bytes in UTF-8. */
export const UTF8_IDENTITY = "lab-café";
/** m2ir profile.yaml TLV 19 `formula`: min(10 × 4 + 1, 255). */
export const TTL_AT_10S = 41;

export interface Target {
	channel: string;
	arch: "x86" | "arm64";
}

export interface Datagram {
	/** Milliseconds since the experiment's setup started. */
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
	/** `/ip/packing/print detail` after the `packing` setup. */
	packing?: string;
	/** Datagrams seen that were not MNDP, counted. */
	other: number;
	/** MNDP datagrams that did not show their experiment's setup, counted. */
	stale?: number;
	experiments: Experiment[];
	failure?: string;
}

/** The MNDP layer of a TZSP datagram, and the IP version it came over. */
export interface MndpView {
	/** The dissection had a problem: such a datagram is never evidence. */
	problem: boolean;
	ip: 4 | 6;
	fields: MndpFields;
}

export function mndpView(datagram: Uint8Array): MndpView | undefined {
	const d = parseTzsp(datagram);
	if (d.kind !== "packet" || !d.payload) return undefined;
	const dissection = dissect(d.payload);
	const l = dissection.layers.find((x) => x.protocol === "mndp");
	if (l?.protocol !== "mndp" || !l.fields) return undefined;
	return {
		problem: dissection.problem !== undefined,
		ip: dissection.protocols.includes("ipv6") ? 6 : 4,
		fields: l.fields,
	};
}

/** What an experiment's announcement must show to be its own, given the identity as booted. */
export type Shows = (v: MndpView, identity: string) => boolean;

/**
 * Each experiment's check: a whole announcement (no problem, not a request
 * from someone else) that shows the setup in effect. One sent before the
 * setup took effect is not its own, whenever it arrives.
 */
export const SHOWS: Record<string, Shows> = {
	default: (v, identity) => !v.problem && v.fields.identity === identity,
	"discover-interval": (v, identity) =>
		!v.problem && v.fields.identity === identity && v.fields.ttl === TTL_AT_10S,
	"identity-utf8": (v) =>
		!v.problem &&
		v.fields.identity === UTF8_IDENTITY &&
		v.fields.ttl === TTL_AT_10S,
	packing: (v) =>
		!v.problem &&
		v.fields.identity === UTF8_IDENTITY &&
		v.fields.unpackAll === true,
	// Whatever TLV 14 does is the finding, so any whole announcement after
	// the setup counts.
	"ipv6-disabled": (v) =>
		!v.problem &&
		v.fields.identity === UTF8_IDENTITY &&
		v.fields.unpackAll === true,
};

/**
 * Experiments whose check (SHOWS) cannot tell an announcement from before
 * the setup from one after it: only what arrives once the setup is done is
 * kept, and `at` counts from then.
 */
export const AFTER_SETUP = new Set(["ipv6-disabled"]);

/** Each experiment, its setup and how many header values it waits for. */
export const PLAN: [string, string[], number][] = [
	["default", [], 2],
	[
		"discover-interval",
		["/ip/neighbor/discovery-settings/set discover-interval=10s"],
		1,
	],
	["identity-utf8", [`/system/identity/set name="${UTF8_IDENTITY}"`], 1],
	[
		"packing",
		[
			"/ip/packing/add interface=ether1 packing=none unpacking=compress-all aggregated-size=1500",
		],
		1,
	],
	["ipv6-disabled", ["/ipv6/settings/set disable-ipv6=yes"], 2],
];

/** The byte the software id's value is overwritten with: `X`. */
export const REDACTED = 0x58;

/**
 * `datagram` with TLV 11's value overwritten by REDACTED, in place. The
 * frame is the tail of the TZSP datagram, so a layer's offset in the frame
 * is that much further into the datagram.
 */
export function redactSoftwareId(datagram: Uint8Array): Uint8Array {
	const d = parseTzsp(datagram);
	if (d.kind !== "packet" || !d.payload) return datagram;
	const l = dissect(d.payload).layers.find((x) => x.protocol === "mndp");
	if (!l) return datagram;
	const base = datagram.length - d.payload.length + l.offset;
	const end = base + l.length;
	for (let at = base + 4; at + 4 <= end; ) {
		const type = ((datagram[at] ?? 0) << 8) | (datagram[at + 1] ?? 0);
		const length = ((datagram[at + 2] ?? 0) << 8) | (datagram[at + 3] ?? 0);
		if (at + 4 + length > end) break;
		if (type === 11) datagram.fill(REDACTED, at + 4, at + 4 + length);
		at += 4 + length;
	}
	return datagram;
}

const headers = (ds: readonly Datagram[]) =>
	new Set(
		ds.map((d) => mndpView(Buffer.from(d.hex, "hex"))?.fields.header ?? ""),
	).size;

export class Listener {
	private sock: Socket | undefined;
	private start = 0;
	kept: Datagram[] = [];
	other = 0;
	/** MNDP datagrams that arrived during an experiment but did not show its setup. */
	stale = 0;
	private accept: (datagram: Uint8Array) => boolean = () => false;
	/** A socket error after the bind, which fails the experiment waiting. */
	private failed: Error | undefined;
	async open(): Promise<number> {
		const sock = createSocket("udp4");
		this.sock = sock;
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
			const b = redactSoftwareId(new Uint8Array(msg));
			if (!mndpView(b)) this.other++;
			else if (this.accept(b))
				this.kept.push({ at: Date.now() - this.start, hex: toHex(b) });
			else this.stale++;
		});
		await bound;
		return sock.address().port;
	}
	/** Start a new experiment: what arrives from now on, and passes `accept`, is its own. */
	reset(accept: (datagram: Uint8Array) => boolean): void {
		this.kept = [];
		this.accept = accept;
		this.start = Date.now();
	}
	/** Wait for `count` header values, then COPY_MS for a late IPv6 copy. */
	async waitFor(count: number): Promise<Datagram[]> {
		const until = Date.now() + WAIT_MS;
		while (headers(this.kept) < count && Date.now() < until) {
			if (interrupted) throw new Error("interrupted");
			if (this.failed) throw this.failed;
			await new Promise((r) => setTimeout(r, 250));
		}
		if (this.failed) throw this.failed;
		const seen = headers(this.kept);
		if (seen < count)
			throw new Error(
				`${seen} of ${count} announcements in ${WAIT_MS / 1000} s`,
			);
		await new Promise((r) => setTimeout(r, COPY_MS));
		// Stop taking more, so a later announcement does not join this one.
		this.accept = () => false;
		return [...this.kept];
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

export async function experiment(
	router: Router,
	listener: Listener,
	identity: string,
	name: string,
	setup: string[],
	count: number,
): Promise<Experiment> {
	const shows = SHOWS[name];
	if (!shows) throw new Error(`no check for experiment ${name}`);
	const accept = (b: Uint8Array) => {
		const view = mndpView(b);
		return view !== undefined && shows(view, identity);
	};
	// Armed before the setup runs: RouterOS announces at once when one of
	// these settings changes (m2ir lifecycle.triggered), which can arrive
	// before the REST call returns. `at` counts from here.
	listener.reset(accept);
	for (const command of setup) await router.exec(command);
	// An announcement sent before the setup took effect passes this one's
	// check too: it is dropped, and the count starts once the setup is done.
	if (AFTER_SETUP.has(name)) listener.reset(accept);
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
			`tzsp-lab-mndp-${target.channel}-${target.arch}`,
			{ routeros: target.channel, arch: target.arch },
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
		await router.exec(snifferStreamAll(ev.listenerPort));
		await router.exec("/tool/sniffer/start");
		await router.sniffing();
		const identity = ev.identity;
		if (!identity) throw new Error("the router reported no identity");
		// Each experiment is kept as it completes, so a failed run's evidence
		// still has the ones before it.
		for (const [name, setup, count] of PLAN) {
			ev.experiments.push(
				await experiment(router, listener, identity, name, setup, count),
			);
			if (name === "packing")
				ev.packing = (await router.exec("/ip/packing/print detail")).output;
		}
		await router.exec("/tool/sniffer/stop");
		ok = true;
	} catch (e) {
		ev.failure = e instanceof Error ? e.message : String(e);
		if (e && typeof e === "object" && "step" in e)
			ev.failure += ` (${JSON.stringify((e as { step: unknown }).step)})`;
	} finally {
		ev.other = listener.other;
		ev.stale = listener.stale;
		try {
			listener.close();
		} catch {}
		if (ev.machine && owned.has(ev.machine) && !(await teardown(ev.machine)))
			console.error(leftOver(ev.machine));
	}
	// The version comes from the router: keep it to a plain file name.
	const stem = `${ev.router?.version || target.channel}-${target.arch}`.replace(
		/[^\w.-]/g,
		"_",
	);
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
		{ channel: "long-term", arch: "arm64" },
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
	// Each router has its own listener and waits mostly on its interval, so
	// all run at once.
	const results = await Promise.allSettled(targets.map((t) => lab(t)));
	const left = await cleanupAll();
	for (const n of left) console.error(leftOver(n));
	const failed = results.some((r) => r.status === "rejected" || !r.value);
	if (interrupted) process.exit(interrupted === "SIGINT" ? 130 : 143);
	process.exit(failed || left.length > 0 ? 1 : 0);
}
