/**
 * CHR machines through quickchr's library, shared by the lab
 * (test/lab/tzsp-senders/) and the integration tier (test/integration/).
 *
 * Safety. Each machine is one this process creates and owns: a random name
 * with a fixed prefix, checked absent, then created with `QuickCHR.add`,
 * which refuses a name in use. Ownership is the name and the `createdAt`
 * that `add` returned, so a machine of the same name made by someone else
 * is never started or removed. A failed `add` owns nothing: quickchr
 * removes what it made itself (0.6.0, `QuickCHR.add`'s catch), and a
 * failure before its claim (`MACHINE_EXISTS`, `MACHINE_LOCKED`) made
 * nothing of this process's. Removal is verified (`teardown`).
 *
 * A signal stops the running children and REST calls (`stopping`), and no
 * new `add` or boot begins after it. A quickchr call already running in
 * this process cannot be interrupted, so `cleanupAll` waits for it first.
 */
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
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
 * What to boot: a channel or an exact version, and the guest architecture.
 * The architecture is always given: the budgets depend on it, and quickchr
 * 0.6.0's library default reads `process.arch`, which is `x64` under
 * Rosetta (`hostArch`).
 */
export interface Target {
	routeros: string;
	arch: "x86" | "arm64";
}

/**
 * The guest architecture of this machine's CPU, so the CHR is not under
 * cross-architecture emulation. x64 Bun under Rosetta on Apple Silicon
 * reports `x64`; `sysctl.proc_translated` says so, the check quickchr's
 * own `isAppleSiliconHost` makes (platform.ts). On Apple Silicon an arm64
 * CHR runs under TCG, not HVF (same file), still far quicker than an x86
 * guest under cross-architecture TCG. Not yet run on a Mac.
 */
export function hostArch(): Target["arch"] {
	if (process.arch === "arm64") return "arm64";
	if (process.platform === "darwin" && process.arch === "x64")
		try {
			const translated = execFileSync(
				"sysctl",
				["-n", "sysctl.proc_translated"],
				{ encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
			);
			if (translated.trim() === "1") return "arm64";
		} catch {}
	return "x86";
}

/* ---------------------------------------------------------------- budgets */

/*
 * What quickchr 0.6.0 itself waits for, so a caller's deadline outlives it
 * and a slow step fails inside quickchr with its evidence (tikoci-testing,
 * "Timeouts"). Only the boot budget is exported by quickchr; the others
 * are quoted from its source, by file.
 */

/** The image download in `add`: DOWNLOAD_MAX_ATTEMPTS (3) transfers of at most DOWNLOAD_NO_LENGTH_BUDGET_MS (15 min) each, with 2 s and 4 s between them (download.ts). Free when the image is cached. */
const DOWNLOAD_MS = 3 * 15 * 60_000 + 6_000;
/** The port allocator's lock, which `add` waits for (ALLOCATION_LOCK_WAIT_MS, quickchr.ts). */
const ALLOCATION_LOCK_MS = 60_000;
/**
 * After a boot times out, quickchr collects a failure report and stops
 * QEMU (`captureBootFailure`, `cleanupAfterBootFailure`, quickchr.ts): a
 * few monitor queries of 3 s each and a 5 s stop. An allowance from
 * reading the source, not a quickchr constant.
 */
const BOOT_FAILURE_MS = 60_000;
/** `stopQemu` (qemu.ts): SIGTERM, 5 s, then SIGKILL; plus deleting the machine directory. */
const STOP_MS = 30_000;

/**
 * quickchr's boot budget for `arch`, in ms: `defaultBootTimeout` at its
 * slowest accelerator (TCG). `start` passes no `timeoutExtra`: quickchr
 * 0.6.0 does not apply it when it boots a machine `add` created.
 */
export const bootBudget = (arch: Target["arch"]): number =>
	defaultBootTimeout(arch, false, "tcg");

/** The most `create` then `start` can take inside quickchr, a failed boot included. */
export const provisionBudget = (arch: Target["arch"]): number =>
	ALLOCATION_LOCK_MS + DOWNLOAD_MS + bootBudget(arch) + BOOT_FAILURE_MS;

/**
 * The most `teardown` can take: `remove` waits for the machine's lock up to
 * the boot budget (`lifecycleLockWaitMs`, quickchr.ts), then stops QEMU.
 */
export const teardownBudget = (arch: Target["arch"]): number =>
	bootBudget(arch) + STOP_MS;

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

/**
 * Machines this process created: the name, and the `createdAt` quickchr
 * recorded for it. Nothing else is started or removed.
 */
export const owned = new Map<string, string>();
/** Temporary directories to remove on exit (the lab's askpass helper). */
export const tempDirs = new Set<string>();
/** Removals in progress, so two callers share one; a finished one is dropped, so a later call tries again. */
const removals = new Map<string, Promise<boolean>>();
/** quickchr calls still running (`add`, `start`), which cleanup waits for. */
const inFlight = new Set<Promise<unknown>>();
/** Handles from `start`, by machine name. */
const instances = new Map<string, ChrInstance>();

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

function track<T>(p: Promise<T>): Promise<T> {
	inFlight.add(p);
	p.finally(() => inFlight.delete(p)).catch(() => {});
	return p;
}

/** quickchr knows nothing by this name: no machine, and no half-made directory. */
const absent = (name: string) =>
	QuickCHR.get(name) === null && !QuickCHR.listOrphans().includes(name);

/**
 * What an operator should do about a machine left behind. `quickchr remove`
 * is advised only for a machine this run created whose state quickchr can
 * read: on unreadable state it deletes the directory without stopping QEMU
 * (0.6.0, `cmdRemove` falls back to `removeOrphan`).
 */
const ADVICE = {
	foreign: "another machine of that name, not this run's; left in place",
	unreadable:
		"quickchr cannot read its state, and its QEMU may still run: stop that QEMU, then `quickchr remove <name>`",
	present: "`quickchr remove <name>` clears it",
};

/** Why each machine `teardown` could not remove is still there. */
const leftReasons = new Map<string, string>();

/**
 * The owned machine by this name, or why it cannot be touched: gone, its
 * state unreadable (QEMU may still run), or another machine of that name.
 */
function ownedMachine(
	name: string,
):
	| { machine: ChrInstance }
	| { gone: true }
	| { refused: string; advice: string } {
	const createdAt = owned.get(name);
	if (createdAt === undefined)
		return {
			refused: `${name} is not a machine this run created`,
			advice: ADVICE.foreign,
		};
	let machine: ChrInstance | null;
	try {
		machine = QuickCHR.get(name);
	} catch (e) {
		return {
			refused: `quickchr cannot read ${name}'s state (${message(e)})`,
			advice: ADVICE.unreadable,
		};
	}
	if (machine === null)
		return QuickCHR.listOrphans().includes(name)
			? {
					refused: `${name} has a directory with no readable state`,
					advice: ADVICE.unreadable,
				}
			: { gone: true };
	if (machine.state.createdAt !== createdAt)
		return {
			refused: `${name} is another machine than the one this run created`,
			advice: ADVICE.foreign,
		};
	return { machine };
}

/**
 * Remove one owned machine and confirm quickchr no longer knows it. A
 * machine whose state quickchr cannot read is left alone and reported: its
 * QEMU may still be running, which only the operator can check. `leftOver`
 * says what to do about a machine this returned false for.
 */
export function teardown(name: string): Promise<boolean> {
	const pending = removals.get(name);
	if (pending) return pending;
	const p = (async () => {
		const found = ownedMachine(name);
		if ("refused" in found) {
			console.error(`not removing: ${found.refused}`);
			leftReasons.set(name, found.advice);
			return false;
		}
		if ("machine" in found) {
			try {
				await found.machine.remove();
			} catch (e) {
				console.error(`quickchr remove ${name}: ${message(e)}`);
			}
		}
		let gone = false;
		try {
			gone = absent(name);
		} catch {}
		if (gone) {
			owned.delete(name);
			instances.delete(name);
			leftReasons.delete(name);
		} else leftReasons.set(name, ADVICE.present);
		return gone;
	})();
	removals.set(name, p);
	p.finally(() => removals.delete(name)).catch(() => {});
	return p;
}

/** A machine `teardown` left, and what to do about it, as one line. */
export const leftOver = (name: string): string =>
	`NOT REMOVED: ${name}: ${(leftReasons.get(name) ?? ADVICE.present).replace("<name>", name)}`;

/** Remove every owned machine and temp dir; return the machines still present (see `leftOver`). */
export async function cleanupAll(): Promise<string[]> {
	// An `add` or a boot still running cannot be stopped from here; once it
	// settles, a machine it made is in `owned`.
	while (inFlight.size > 0) await Promise.allSettled([...inFlight]);
	const names = [...owned.keys()];
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
 * running children and aborts `stopping`, which REST calls listen to and
 * `create` and `start` check before calling quickchr.
 */
export const stopping = new AbortController();
export function stop(): void {
	stopping.abort();
	for (const child of children) child.kill("SIGTERM");
}

/* ------------------------------------------------------------- machines */

/**
 * Create a machine this process owns, named `<prefix>-<random>`, or throw
 * having removed nothing. The name goes to stderr before `add`, so a run
 * killed during it says what to look for (`quickchr list <name>`).
 */
export function create(prefix: string, target: Target): Promise<string> {
	return track(provision(prefix, target));
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
	console.error(`machine: ${name}`);
	try {
		const state = await QuickCHR.add({
			name,
			arch: target.arch,
			...which,
			// Stated, not left to quickchr's defaults: the factory admin login
			// (no managed account, whatever the user's quickchr settings say),
			// and the qcow2 boot disk the quickchr CLI makes and the lab's
			// evidence was taken on.
			secureLogin: false,
			bootDiskFormat: "qcow2",
			onProgress,
		});
		owned.set(name, state.createdAt);
	} catch (e) {
		let left = true;
		try {
			left = !absent(name);
		} catch {}
		throw new Error(
			`quickchr add ${name}: ${message(e)}` +
				(left ? `; ${name} is still there and was not removed` : ""),
		);
	}
	return name;
}

/** Boot an owned machine with quickchr's own boot budget; returns the boot time in ms. */
export function start(name: string): Promise<number> {
	return track(boot(name));
}

async function boot(name: string): Promise<number> {
	if (stopping.signal.aborted)
		throw new Error(`interrupted; not booting ${name}`);
	const found = ownedMachine(name);
	if (!("machine" in found))
		throw new Error(
			"refused" in found ? found.refused : `${name} is gone; not booting it`,
		);
	const t0 = Date.now();
	try {
		instances.set(name, await QuickCHR.start({ name, onProgress }));
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
	const found = ownedMachine(name);
	if (!("machine" in found)) return [];
	const { machineDir } = found.machine.state;
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
	const found = ownedMachine(name);
	return ("machine" in found && found.machine.state.lastAccel) || "unknown";
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
