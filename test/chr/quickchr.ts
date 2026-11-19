/**
 * CHR machines through quickchr's library, shared by the lab
 * (test/lab/tzsp-senders/) and the integration tier (test/integration/).
 *
 * Safety. Each machine is one this process creates and owns: a random name
 * with a fixed prefix, checked absent, then created with `QuickCHR.add`,
 * which refuses an existing name (`MACHINE_EXISTS`). Only owned machines are
 * configured or removed, and removal is verified (`teardown`). A signal
 * stops the running children and REST calls (`stopping`); the caller then
 * removes its machines. A quickchr call already running in this process is
 * not interrupted: `remove` waits for its machine lock instead.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import {
	CHANNELS,
	type Channel,
	type ChrInstance,
	defaultBootTimeout,
	QuickCHR,
	type StartOptions,
} from "@tikoci/quickchr";

export const ROOT = join(import.meta.dir, "..", "..");

/**
 * quickchr waits for a machine's lock before `remove`, up to its boot budget
 * (`lifecycleLockWaitMs`, quickchr 0.6.0), then stops QEMU. The integration
 * tier's `afterAll` lets setup settle first, so this covers the stop.
 */
export const TEARDOWN_MS = 180_000;

/**
 * What to boot: a channel or an exact version, and the guest architecture.
 * The architecture is always given, so quickchr's own default (its
 * `default-arch` setting or QUICKCHR_DEFAULT_ARCH) cannot turn a boot into
 * cross-architecture emulation with a far longer budget.
 */
export interface Target {
	routeros: string;
	arch: "x86" | "arm64";
}

/** The guest architecture this host runs natively (no cross-architecture emulation). */
export const hostArch = (): Target["arch"] =>
	process.arch === "arm64" ? "arm64" : "x86";

/**
 * quickchr's boot budget for `arch`, in ms: `defaultBootTimeout` at its
 * slowest (TCG) accelerator, plus QUICKCHR_TIMEOUT_EXTRA (seconds, as the
 * quickchr CLI reads it), which `start` passes on as `timeoutExtra`.
 */
export const bootBudget = (arch: Target["arch"]): number =>
	defaultBootTimeout(arch, false, "tcg") + timeoutExtra();

const timeoutExtra = (): number =>
	Number(process.env.QUICKCHR_TIMEOUT_EXTRA ?? 0) * 1000 || 0;

/** quickchr's progress lines, which it prints to stdout unless given a callback. */
const onProgress = (message: string) => console.error(`quickchr: ${message}`);

/** Child processes get an allowlisted env, never a copy of process.env (tikoci-testing). */
export function childEnv(
	extra: Record<string, string> = {},
): Record<string, string> {
	const env: Record<string, string> = {};
	for (const [key, value] of Object.entries(process.env)) {
		if (value === undefined) continue;
		if (
			["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG"].includes(key) ||
			key.startsWith("XDG_") ||
			key.startsWith("QUICKCHR_")
		)
			env[key] = value;
	}
	return { ...env, QUICKCHR_NO_TIPS: "1", ...extra };
}

export interface Ran {
	code: number;
	stdout: string;
	stderr: string;
	timedOut: boolean;
}

/** Children still running, so a signal can stop them. */
const children = new Set<ChildProcess>();

/** Run a child; past `timeoutMs` it is killed. No deadline when undefined. */
export function run(
	argv: string[],
	opts: { env?: Record<string, string>; timeoutMs?: number } = {},
): Promise<Ran> {
	return new Promise((resolve) => {
		const [cmd, ...args] = argv as [string, ...string[]];
		const child = spawn(cmd, args, {
			env: opts.env ?? childEnv(),
			stdio: ["ignore", "pipe", "pipe"],
		});
		children.add(child);
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		const timer =
			opts.timeoutMs === undefined
				? undefined
				: setTimeout(() => {
						timedOut = true;
						child.kill("SIGKILL");
					}, opts.timeoutMs);
		child.stdout.on("data", (b: Buffer) => {
			stdout += b.toString();
		});
		child.stderr.on("data", (b: Buffer) => {
			stderr += b.toString();
		});
		child.on("close", (code) => {
			children.delete(child);
			clearTimeout(timer);
			resolve({ code: code ?? -1, stdout, stderr, timedOut });
		});
		child.on("error", (e) => {
			children.delete(child);
			clearTimeout(timer);
			resolve({ code: -1, stdout, stderr: String(e), timedOut });
		});
	});
}

/* ------------------------------------------------- ownership and cleanup */

/** Machines this process created, by name. Nothing else is configured or removed. */
export const owned = new Set<string>();
/** Temporary directories to remove on exit (the lab's askpass helper). */
export const tempDirs = new Set<string>();
const removals = new Map<string, Promise<boolean>>();
/** `create` calls still running, so cleanup waits for a machine mid-`add`. */
const provisioning = new Set<Promise<unknown>>();
/** Handles from `start`, by machine name. */
const instances = new Map<string, ChrInstance>();

/** quickchr knows nothing by this name: no machine, and no half-made directory. */
const absent = (name: string) =>
	QuickCHR.get(name) === null && !QuickCHR.listOrphans().includes(name);

/**
 * Remove one owned machine and confirm quickchr no longer knows it. A
 * directory an interrupted `add` left without its state (quickchr's
 * `listOrphans`) is removed too.
 */
export function teardown(name: string): Promise<boolean> {
	const pending = removals.get(name);
	if (pending) return pending;
	const p = (async () => {
		try {
			const machine = QuickCHR.get(name);
			if (machine) await machine.remove();
			else QuickCHR.removeOrphan(name);
		} catch (e) {
			console.error(`quickchr remove ${name}: ${message(e)}`);
		}
		let gone = false;
		try {
			gone = absent(name);
		} catch {}
		if (gone) {
			owned.delete(name);
			instances.delete(name);
		}
		return gone;
	})();
	removals.set(name, p);
	return p;
}

/** Remove every owned machine and temp dir; return the machines still present. */
export async function cleanupAll(): Promise<string[]> {
	// A machine whose `add` is still running joins `owned` before `add`
	// starts; waiting lets `add` finish or roll back before removal.
	await Promise.allSettled([...provisioning]);
	const names = [...owned];
	const results = await Promise.all(names.map((n) => teardown(n)));
	for (const dir of tempDirs) {
		await rm(dir, { recursive: true, force: true });
		tempDirs.delete(dir);
	}
	return names.filter((_, i) => !results[i]);
}

/**
 * A signal stops work; the caller then removes machines and exits, so
 * removal never races a step still using a machine. `stop` kills the
 * running children and aborts `stopping`, which REST calls listen to.
 */
export const stopping = new AbortController();
export function stop(): void {
	stopping.abort();
	for (const child of children) child.kill("SIGTERM");
}

/* ------------------------------------------------------------- machines */

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Create a machine this process owns, named `<prefix>-<random>`, or throw having touched nothing. */
export function create(prefix: string, target: Target): Promise<string> {
	const p = provision(prefix, target);
	provisioning.add(p);
	p.finally(() => provisioning.delete(p)).catch(() => {});
	return p;
}

async function provision(prefix: string, target: Target): Promise<string> {
	if (stopping.signal.aborted)
		throw new Error("interrupted; not creating a machine");
	const name = `${prefix}-${randomBytes(4).toString("hex")}`;
	if (!absent(name)) throw new Error(`${name} already exists; not touching it`);
	const which: StartOptions = (CHANNELS as readonly string[]).includes(
		target.routeros,
	)
		? { channel: target.routeros as Channel }
		: { version: target.routeros };
	// Owned from here: the name was absent and is random, and `add` refuses
	// an existing name, so what `add` leaves behind is this process's. `add`
	// downloads the image under quickchr's own download budget.
	owned.add(name);
	try {
		await QuickCHR.add({ name, arch: target.arch, ...which, onProgress });
	} catch (e) {
		if ((e as { code?: string }).code === "MACHINE_EXISTS") owned.delete(name);
		throw new Error(`quickchr add ${name}: ${message(e)}`);
	}
	return name;
}

/** Boot an owned machine with quickchr's own boot budget; returns the boot time in ms. */
export async function start(name: string): Promise<number> {
	if (!owned.has(name)) throw new Error(`${name} is not this run's machine`);
	const t0 = Date.now();
	try {
		instances.set(
			name,
			await QuickCHR.start({ name, timeoutExtra: timeoutExtra(), onProgress }),
		);
	} catch (e) {
		throw new Error(`quickchr start ${name}: ${message(e)}`);
	}
	return Date.now() - t0;
}

function instance(name: string): ChrInstance {
	const chr = instances.get(name);
	if (!chr) throw new Error(`${name} was not started by this run`);
	return chr;
}

export interface Services {
	/** The REST base URL, ending in `/rest`. */
	restUrl: string;
	/** `user:password` for HTTP basic auth. */
	basic: string;
	sshPort?: number;
	auth?: { username: string; password: string };
}

/** The connection facts quickchr's descriptor gives for a running machine. */
export async function services(name: string): Promise<Services> {
	const { services: s } = await instance(name).descriptor();
	const rest = s["rest-api"];
	if (!rest.available || !rest.url || rest.auth?.basic === undefined)
		throw new Error("quickchr's descriptor has no rest-api service");
	const out: Services = {
		restUrl: rest.url,
		basic: rest.auth.basic,
		auth: {
			username: rest.auth.username,
			password: rest.auth.password ?? "",
		},
	};
	if (s.ssh.available) out.sshPort = s.ssh.port;
	return out;
}

/**
 * Copy the machine's QEMU log (and serial log, when quickchr kept one) to
 * `<dir>/<name>.<log>` before `teardown` deletes the machine's directory.
 * Returns the files written; a log that is not there is skipped.
 */
export async function saveLogs(name: string, dir: string): Promise<string[]> {
	const machineDir = QuickCHR.get(name)?.state.machineDir;
	if (!machineDir) return [];
	const saved: string[] = [];
	for (const log of ["qemu.log", "serial.log"]) {
		const to = join(dir, `${name}.${log}`);
		try {
			await copyFile(join(machineDir, log), to);
			saved.push(to);
		} catch {}
	}
	return saved;
}

/** The accelerator quickchr booted the machine with (`kvm`, `hvf`, `tcg`). */
export function accelerator(name: string): string {
	return QuickCHR.get(name)?.state.lastAccel ?? "unknown";
}

/** The quickchr version, as `quickchr 0.6.0`. */
export async function version(): Promise<string> {
	// The package's exports map has no `./package.json`, so read the file.
	const file = join(
		ROOT,
		"node_modules",
		"@tikoci",
		"quickchr",
		"package.json",
	);
	const { version: v } = JSON.parse(await readFile(file, "utf8")) as {
		version: string;
	};
	return `quickchr ${v}`;
}
