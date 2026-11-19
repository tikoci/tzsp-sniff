/**
 * CHR machines through the quickchr CLI, shared by the lab
 * (test/lab/tzsp-senders/) and the integration tier (test/integration/).
 *
 * The CLI, not quickchr's library: quickchr ships TypeScript source, and
 * this repo's tsc settings (exactOptionalPropertyTypes) reject it, so a
 * static import fails `bun run lint:types` (quickchr 0.5.6). The CLI is the
 * devDependency's own (`node_modules/.bin/quickchr`), run by this Bun.
 *
 * Safety. Each machine is one this process creates and owns: a random name
 * with a fixed prefix, checked absent, then created with `quickchr add`,
 * which refuses an existing name. Only owned machines are configured or
 * removed, and removal is verified (`teardown`). A signal stops the running
 * children and REST calls (`stopping`); the caller then removes its machines.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";

export const ROOT = join(import.meta.dir, "..", "..");
const QUICKCHR = join(ROOT, "node_modules", ".bin", "quickchr");

/**
 * Deadlines. `quickchr start` keeps quickchr's own boot budget (its
 * BOOT_TIMEOUT), so this module adds none. Teardown waits for quickchr,
 * which itself waits for a `start` of the same machine still in progress.
 */
export const TEARDOWN_MS = 180_000;
export const QUICKCHR_MS = 30_000;
/** quickchr 0.5.2 and 0.5.6 for a name it does not know: `Machine "<name>" not found.`, exit 1. */
const NOT_FOUND = /Machine "[^"]+" not found/;

/** What to boot: a channel or an exact version, and the guest architecture (default: the host's). */
export interface Target {
	routeros: string;
	arch?: "x86" | "arm64";
}

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

/** Run the quickchr CLI (the devDependency) under this Bun. */
export function quickchr(
	args: string[],
	opts: { timeoutMs?: number } = {},
): Promise<Ran> {
	return run([process.execPath, "--no-env-file", QUICKCHR, ...args], opts);
}

/* ------------------------------------------------- ownership and cleanup */

/** Machines this process created, by name. Nothing else is configured or removed. */
export const owned = new Set<string>();
/** Temporary directories to remove on exit (the lab's askpass helper). */
export const tempDirs = new Set<string>();
const removals = new Map<string, Promise<boolean>>();
/** `create` calls still running, so cleanup waits for a machine mid-`add`. */
const provisioning = new Set<Promise<unknown>>();

/** Remove one owned machine and confirm `quickchr list` no longer knows it. */
export function teardown(name: string): Promise<boolean> {
	const pending = removals.get(name);
	if (pending) return pending;
	const p = (async () => {
		await quickchr(["remove", name], { timeoutMs: TEARDOWN_MS });
		const left = await quickchr(["list", name, "--json"], {
			timeoutMs: QUICKCHR_MS,
		});
		const gone =
			left.code !== 0 &&
			!left.timedOut &&
			NOT_FOUND.test(left.stdout + left.stderr);
		if (gone) owned.delete(name);
		return gone;
	})();
	removals.set(name, p);
	return p;
}

/** Remove every owned machine and temp dir; return the machines still present. */
export async function cleanupAll(): Promise<string[]> {
	// A machine whose `add` is still running joins `owned` when it settles;
	// each `run` has a deadline, so this wait is bounded.
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

/** Create a machine this process owns, named `<prefix>-<random>`, or throw having touched nothing. */
export function create(prefix: string, target: Target): Promise<string> {
	const p = provision(prefix, target);
	provisioning.add(p);
	p.finally(() => provisioning.delete(p)).catch(() => {});
	return p;
}

const CHANNELS = ["stable", "long-term", "testing", "development"];

async function provision(prefix: string, target: Target): Promise<string> {
	if (stopping.signal.aborted)
		throw new Error("interrupted; not creating a machine");
	const name = `${prefix}-${randomBytes(4).toString("hex")}`;
	const exists = await quickchr(["list", name, "--json"], {
		timeoutMs: QUICKCHR_MS,
	});
	// Only quickchr's own "not found" proves the name is free; a timeout or
	// any other failure stops here, before `add`.
	if (exists.code === 0)
		throw new Error(`${name} already exists; not touching it`);
	if (exists.timedOut || !NOT_FOUND.test(exists.stdout + exists.stderr))
		throw new Error(
			`quickchr list ${name} ${exists.timedOut ? "timed out" : `exited ${exists.code}`}; not creating a machine`,
		);
	if (stopping.signal.aborted)
		throw new Error("interrupted; not creating a machine");
	// Owned from here: the name was absent and is random, and `add` refuses
	// an existing name, so what `add` leaves behind is this process's.
	owned.add(name);
	const added = await quickchr(
		[
			"add",
			"--name",
			name,
			CHANNELS.includes(target.routeros) ? "--channel" : "--version",
			target.routeros,
			...(target.arch ? ["--arch", target.arch] : []),
		],
		{ timeoutMs: QUICKCHR_MS },
	);
	if (added.code !== 0) {
		if (/MACHINE_EXISTS/.test(added.stdout + added.stderr)) owned.delete(name);
		throw new Error(
			`quickchr add ${name} exited ${added.code}: ${lastLine(added)}`,
		);
	}
	return name;
}

const lastLine = (r: Ran) =>
	(r.stderr.trim() || r.stdout.trim()).split("\n").at(-1) ?? "";

/** Boot an owned machine with quickchr's own boot budget; returns the boot time in ms. */
export async function start(name: string): Promise<number> {
	const t0 = Date.now();
	const started = await quickchr(["start", name]);
	if (started.code !== 0)
		throw new Error(
			`quickchr start exited ${started.code}: ${lastLine(started)}`,
		);
	return Date.now() - t0;
}

export interface Services {
	/** The REST base URL, ending in `/rest`. */
	restUrl: string;
	/** `user:password` for HTTP basic auth. */
	basic: string;
	sshPort?: number;
	auth?: { username: string; password: string };
}

/** The connection facts `quickchr inspect` gives for a running machine. */
export async function services(name: string): Promise<Services> {
	const inspect = await quickchr(["inspect", name, "--json"], {
		timeoutMs: QUICKCHR_MS,
	});
	const info = JSON.parse(inspect.stdout) as {
		services: Record<
			string,
			{
				url?: string;
				port?: number;
				auth?: { basic?: string; username: string; password: string };
			}
		>;
	};
	const rest = info.services["rest-api"];
	if (!rest?.url || rest.auth?.basic === undefined)
		throw new Error("quickchr inspect has no rest-api service");
	const out: Services = { restUrl: rest.url, basic: rest.auth.basic };
	const ssh = info.services.ssh?.port;
	if (ssh !== undefined) out.sshPort = ssh;
	out.auth = { username: rest.auth.username, password: rest.auth.password };
	return out;
}

/** The `-accel` QEMU was started with, read from its command line (Linux /proc). */
export async function accelerator(name: string): Promise<string> {
	const listed = await quickchr(["list", name, "--json"], {
		timeoutMs: QUICKCHR_MS,
	});
	try {
		const { pid } = JSON.parse(listed.stdout) as { pid?: number };
		const argv = (await readFile(`/proc/${pid}/cmdline`, "utf8")).split("\0");
		const i = argv.indexOf("-accel");
		return i >= 0 ? (argv[i + 1] ?? "unknown") : "unknown";
	} catch {
		return "unknown";
	}
}

/** The quickchr version, as `quickchr 0.5.6`. */
export async function version(): Promise<string> {
	const v = await quickchr(["--version"], { timeoutMs: QUICKCHR_MS });
	return v.stdout.split("\n")[0]?.trim() ?? "";
}
