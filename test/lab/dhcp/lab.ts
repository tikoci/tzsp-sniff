/**
 * Lab: the DHCPv4 RouterOS sends as a client and as a server, as
 * `/tool/sniffer` streams it (issue #29, slice 6c of #18). Not a test tier:
 * run by hand, never a gate. REPORT.md says what it showed; `fixtures.ts`
 * turns evidence/ into test/fixtures/dhcp/.
 *
 *   bun test/lab/dhcp/lab.ts                 # stable and long-term, x86 and arm64
 *   bun test/lab/dhcp/lab.ts --only x86:stable
 *
 * Routers. Two machines per target, both this run's own
 * (`tzsp-lab-dhcp-<role>-<channel>-<arch>-<random>`), removed when the run
 * ends, fails or gets SIGINT or SIGTERM, with removal verified
 * (test/chr/quickchr.ts). A second signal exits at once, naming what is
 * left. `server` has ether1 on SLIRP (as quickchr boots it, a dhcp-client
 * on ether1) and ether2 on a quickchr named socket; `client` has the same,
 * its ether2 on the same socket, so the two share an L2 link.
 *
 * Capture. Only `server` sniffs: everything on all its interfaces, streamed
 * to the SLIRP gateway with `filter-stream=yes` (without it the stream
 * captures itself, #5), to a UDP listener on 127.0.0.1 port 0. Only
 * datagrams whose frame is UDP between ports 67 and 68 are kept; the rest
 * are counted. Each is labelled by its Ethernet source: `server`'s ether1
 * is `routeros-client` (its own dhcp-client), QEMU's SLIRP is `qemu-slirp`
 * (QEMU's DHCP server, not RouterOS's), `server`'s ether2 is
 * `routeros-server`, `client`'s ether2 is `routeros-client`.
 *
 * Experiments, in order, each waiting for the messages it names:
 *
 * - `client-renew`: `/ip/dhcp-client/renew` on `server`'s ether1; a REQUEST
 *   from RouterOS and QEMU's ACK.
 * - `server-exchange`: `server` serves 192.168.88.0/24 on ether2 (lease
 *   10 minutes, gateway, DNS server and a domain); `client` gets the
 *   identity `lab-café` (to see how the hostname option carries it) and a
 *   dhcp-client on ether2: DISCOVER, OFFER, REQUEST and ACK.
 * - `server-release`: `/ip/dhcp-client/release` on `client`'s ether2: a
 *   RELEASE.
 * - `client-release`: `/ip/dhcp-client/release` on `server`'s ether1, last:
 *   with no address the stream has no source until the client is bound
 *   again (the probe on #29), so the lab then waits for `bound`.
 *
 * Output. Every experiment must see its messages before anything is written
 * to evidence/<version>-<arch>.json; a failed run writes to
 * .scratch/dhcp-lab/ instead.
 */
import { randomBytes } from "node:crypto";
import { createSocket, type Socket } from "node:dgram";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { dissect } from "../../../src/dissect.ts";
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
const FAILED = join(ROOT, ".scratch", "dhcp-lab");
/** QEMU's SLIRP answers as 52:55:0a:00:02:02 (the gateway, 10.0.2.2). */
export const SLIRP_MAC = "52:55:0a:00:02:02";
/** The identity `client` sends in its hostname option: "é" is two bytes in UTF-8. */
export const UTF8_IDENTITY = "lab-café";

export interface Target {
	channel: string;
	arch: "x86" | "arm64";
}

export type Sender =
	| "routeros-client"
	| "routeros-server"
	| "qemu-slirp"
	| "unknown";

export interface Datagram {
	/** Milliseconds since the experiment's setup started. */
	at: number;
	sender: Sender;
	/** The DHCP message type's name, as the dissector read it. */
	message?: string;
	/** The whole TZSP datagram, as received. */
	hex: string;
}

export interface Experiment {
	name: string;
	/** Each command, with the router it ran on. */
	setup: string[];
	datagrams: Datagram[];
}

export interface RouterFacts {
	machine: string;
	bootMs?: number;
	identity?: Awaited<ReturnType<Router["identity"]>>;
	/** MAC addresses by interface name, lowercase. */
	macs: Record<string, string>;
}

export interface Evidence {
	target: Target;
	date: string;
	accelerator: string;
	quickchr: string;
	socket: string;
	listenerPort?: number;
	server?: RouterFacts;
	client?: RouterFacts;
	/** `server`'s dhcp-client on ether1, as booted. */
	dhcpClient?: unknown;
	/** `server`'s dhcp-client on ether1 at the end, after `client-release`. */
	dhcpClientAfter?: unknown;
	/** `/ip/dhcp-server/lease` on `server` after `server-exchange`. */
	leases?: unknown;
	/** Datagrams seen that were not DHCP, counted. */
	other: number;
	experiments: Experiment[];
	failure?: string;
}

/** The DHCP layer of a TZSP datagram, with the frame's Ethernet source; `undefined` when it has none. */
export function dhcpView(
	datagram: Uint8Array,
): { src: string; message?: string; problem: boolean } | undefined {
	const d = parseTzsp(datagram);
	if (d.kind !== "packet" || !d.payload) return undefined;
	const dissection = dissect(d.payload);
	const eth = dissection.layers.find((l) => l.protocol === "ethernet");
	const dhcp = dissection.layers.find((l) => l.protocol === "dhcp");
	if (eth?.protocol !== "ethernet" || !eth.fields || dhcp?.protocol !== "dhcp")
		return undefined;
	const view: { src: string; message?: string; problem: boolean } = {
		src: eth.fields.src,
		problem: dissection.problem !== undefined,
	};
	const name = dhcp.fields?.messageTypeName;
	if (name !== undefined) view.message = name;
	return view;
}

/** Who sent a frame from `src`, given both routers' MACs. */
export function senderOf(
	src: string,
	server: Record<string, string>,
	client: Record<string, string>,
): Sender {
	if (src === SLIRP_MAC) return "qemu-slirp";
	if (src === server.ether1 || src === client.ether2) return "routeros-client";
	if (src === server.ether2) return "routeros-server";
	return "unknown";
}

/** What each experiment waits for: a sender and message type, each seen at least once. */
export const WANTS: Record<string, [Sender, string][]> = {
	"client-renew": [
		["routeros-client", "request"],
		["qemu-slirp", "ack"],
	],
	"server-exchange": [
		["routeros-client", "discover"],
		["routeros-server", "offer"],
		["routeros-client", "request"],
		["routeros-server", "ack"],
	],
	"server-release": [["routeros-client", "release"]],
	"client-release": [["routeros-client", "release"]],
};

class Listener {
	private sock: Socket | undefined;
	private start = 0;
	kept: Datagram[] = [];
	other = 0;
	private label: (src: string) => Sender = () => "unknown";
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
			const b = new Uint8Array(msg);
			const view = dhcpView(b);
			if (!view) {
				this.other++;
				return;
			}
			const d: Datagram = {
				at: Date.now() - this.start,
				sender: this.label(view.src),
				hex: toHex(b),
			};
			if (view.message !== undefined) d.message = view.message;
			this.kept.push(d);
		});
		await bound;
		return sock.address().port;
	}
	/** Start a new experiment: what arrives from now on is its own. */
	reset(label: (src: string) => Sender): void {
		this.kept = [];
		this.label = label;
		this.start = Date.now();
	}
	async waitFor(wants: [Sender, string][], ms: number): Promise<Datagram[]> {
		const until = Date.now() + ms;
		const done = () =>
			wants.every(([s, m]) =>
				this.kept.some((d) => d.sender === s && d.message === m),
			);
		while (!done() && Date.now() < until) {
			if (interrupted) throw new Error("interrupted");
			if (this.failed) throw this.failed;
			await new Promise((r) => setTimeout(r, 500));
		}
		if (this.failed) throw this.failed;
		if (!done())
			throw new Error(
				`waited ${ms / 1000} s for ${wants.map((w) => w.join("/")).join(", ")}; saw ${
					this.kept.map((d) => `${d.sender}/${d.message}`).join(", ") ||
					"nothing"
				}`,
			);
		// A moment more, so a retransmission or a reply in flight is kept too.
		await new Promise((r) => setTimeout(r, 2000));
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

async function facts(router: Router, machine: string, bootMs?: number) {
	const out: RouterFacts = {
		machine,
		identity: await router.identity(),
		macs: {},
	};
	if (bootMs !== undefined) out.bootMs = bootMs;
	const ports = (await router.read("/interface/ethernet")) as {
		name?: string;
		"mac-address"?: string;
	}[];
	for (const p of ports)
		if (p.name && p["mac-address"])
			out.macs[p.name] = p["mac-address"].toLowerCase();
	return out;
}

/** Wait until `server`'s ether1 dhcp-client is bound again, as REST reports it. */
async function bound(router: Router, ms: number): Promise<unknown> {
	const until = Date.now() + ms;
	let last: unknown;
	while (Date.now() < until) {
		if (interrupted) throw new Error("interrupted");
		last = await router
			.read("/ip/dhcp-client?interface=ether1")
			.catch(() => undefined);
		const status = (last as { status?: string }[] | undefined)?.[0]?.status;
		if (status === "bound") return last;
		await new Promise((r) => setTimeout(r, 1000));
	}
	throw new Error(
		`ether1's dhcp-client not bound in ${ms / 1000} s: ${JSON.stringify(last)}`,
	);
}

async function lab(target: Target): Promise<boolean> {
	// Under TCG (arm64 on an x86 host) a command and a DHCP exchange take longer.
	const waitMs = target.arch === "x86" ? 60_000 : 150_000;
	const socket = `tzsp-dhcp-${randomBytes(4).toString("hex")}`;
	const ev: Evidence = {
		target,
		date: new Date().toISOString(),
		accelerator: "",
		quickchr: await version(),
		socket,
		other: 0,
		experiments: [],
	};
	const listener = new Listener();
	const machines: string[] = [];
	let ok = false;
	try {
		const networks = [
			"user" as const,
			{ type: "socket" as const, name: socket },
		];
		const target_ = { routeros: target.channel, arch: target.arch };
		const tag = `${target.channel}-${target.arch}`;
		const madeServer = await create(
			`tzsp-lab-dhcp-server-${tag}`,
			target_,
			networks,
		);
		machines.push(madeServer.name);
		const madeClient = await create(
			`tzsp-lab-dhcp-client-${tag}`,
			target_,
			networks,
		);
		machines.push(madeClient.name);
		ev.accelerator = accelerator(madeServer.name);
		const s = await services(madeServer.name);
		const c = await services(madeClient.name);
		const server = new Router(s.restUrl, s.basic);
		const client = new Router(c.restUrl, c.basic);
		ev.server = await facts(server, madeServer.name, madeServer.bootMs);
		ev.client = await facts(client, madeClient.name, madeClient.bootMs);
		const serverMacs = ev.server.macs;
		const clientMacs = ev.client.macs;
		if (!serverMacs.ether1 || !serverMacs.ether2 || !clientMacs.ether2)
			throw new Error("a router reported no ether1 or ether2 MAC");
		ev.dhcpClient = await server.read("/ip/dhcp-client");
		ev.listenerPort = await listener.open();
		await server.exec(
			`/tool/sniffer/set streaming-enabled=yes streaming-server=${GATEWAY}:${ev.listenerPort} ` +
				`filter-mac-protocol="" filter-ip-address="" filter-ip-protocol="" ` +
				`filter-stream=yes only-headers=no file-name=""`,
		);
		await server.exec("/tool/sniffer/start");
		await server.sniffing();
		const label = (src: string) => senderOf(src, serverMacs, clientMacs);

		const run = async (
			name: string,
			steps: [Router, string, string][],
			after?: () => Promise<void>,
		) => {
			const wants = WANTS[name];
			if (!wants) throw new Error(`no wants for ${name}`);
			listener.reset(label);
			for (const [router, _, command] of steps) await router.exec(command);
			const datagrams = await listener.waitFor(wants, waitMs);
			await after?.();
			ev.experiments.push({
				name,
				setup: steps.map(([, who, command]) => `${who}: ${command}`),
				datagrams,
			});
		};

		await run("client-renew", [
			[server, "server", "/ip/dhcp-client/renew [find interface=ether1]"],
		]);
		await run("server-exchange", [
			[
				server,
				"server",
				"/ip/address/add address=192.168.88.1/24 interface=ether2",
			],
			[
				server,
				"server",
				"/ip/pool/add name=lab ranges=192.168.88.10-192.168.88.20",
			],
			[
				server,
				"server",
				"/ip/dhcp-server/add name=lab interface=ether2 address-pool=lab lease-time=10m",
			],
			[
				server,
				"server",
				"/ip/dhcp-server/network/add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=192.168.88.1 domain=lab.test",
			],
			[client, "client", `/system/identity/set name="${UTF8_IDENTITY}"`],
			[
				client,
				"client",
				"/ip/dhcp-client/add interface=ether2 add-default-route=no use-peer-dns=no use-peer-ntp=no",
			],
		]);
		ev.leases = await server.read("/ip/dhcp-server/lease");
		await run("server-release", [
			[client, "client", "/ip/dhcp-client/release [find interface=ether2]"],
		]);
		await run(
			"client-release",
			[[server, "server", "/ip/dhcp-client/release [find interface=ether1]"]],
			async () => {
				ev.dhcpClientAfter = await bound(server, waitMs);
			},
		);
		await server.exec("/tool/sniffer/stop");
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
		for (const m of machines)
			if (owned.has(m) && !(await teardown(m))) console.error(leftOver(m));
	}
	const stem = `${ev.server?.identity?.version || target.channel}-${target.arch}`;
	const dir = ok ? EVIDENCE : FAILED;
	await mkdir(dir, { recursive: true });
	await writeFile(
		join(dir, `${stem}.json`),
		`${JSON.stringify(ev, null, "\t")}\n`,
	);
	console.log(
		`${stem}: ${ok ? "done" : `FAILED: ${ev.failure}`} -> ${join(dir, `${stem}.json`)}`,
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
	// Two machines per target; the targets run at once.
	const results = await Promise.allSettled(targets.map((t) => lab(t)));
	const left = await cleanupAll();
	for (const n of left) console.error(leftOver(n));
	const failed = results.some((r) => r.status === "rejected" || !r.value);
	if (interrupted) process.exit(interrupted === "SIGINT" ? 130 : 143);
	process.exit(failed || left.length > 0 ? 1 : 0);
}
