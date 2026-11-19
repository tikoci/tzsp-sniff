/**
 * Integration tier: a real CHR streams TZSP to this process, and the
 * records it decodes are checked (DESIGN.md, "Testing"). Runs only with
 * TZSP_SNIFF_INTEGRATION set (`bun run test:integration`); plain `bun test`
 * boots nothing.
 *
 * One CHR, booted by quickchr (test/chr/), serves every test in this file
 * and is removed in `afterAll`, which bun:test runs after a failed or timed
 * out hook or test too. `afterAll` first waits for the setup to settle (a
 * timed-out hook keeps running), so removal never races `add` or `start`. Each test binds its own listener to 127.0.0.1 port
 * 0 and closes it in `finally`; the router sends to the SLIRP gateway at
 * that port, which QEMU delivers to the loopback listener.
 *
 * Knobs (test-only, never read by shipped code):
 * - TZSP_SNIFF_ROUTEROS: a channel or an exact version, default `stable`.
 * - TZSP_SNIFF_INTEGRATION_RESULTS: a file to write the results to (JSON):
 *   the RouterOS version and architecture the CHR reported, the quickchr
 *   version and accelerator, and each check that passed. The machine's QEMU
 *   log is copied beside it, as `<machine>.qemu.log`, before removal.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { openCapture } from "../../src/capture.ts";
import type {
	PacketRecord,
	StreamRecord,
	SummaryRecord,
} from "../../src/records.ts";
import {
	accelerator,
	bootBudget,
	childEnv,
	cleanupAll,
	create,
	hostArch,
	ROOT,
	saveLogs,
	services,
	start,
	TEARDOWN_MS,
	version,
} from "../chr/quickchr.ts";
import {
	GATEWAY,
	GUEST,
	PEER,
	REST_BASE_MS,
	Router,
	SETTLE,
	snifferStream,
} from "../chr/router.ts";

const LIVE = Boolean(process.env.TZSP_SNIFF_INTEGRATION);
const TARGET = process.env.TZSP_SNIFF_ROUTEROS || "stable";
const RESULTS = process.env.TZSP_SNIFF_INTEGRATION_RESULTS;
const BIN = join(ROOT, "src", "cli", "bin.ts");

/**
 * The setup hook's timeout outlives each budget quickchr enforces itself,
 * so a slow step fails inside quickchr with its evidence rather than being
 * cut off here (tikoci-testing, "Timeouts"). From quickchr 0.6.0:
 * - the image download in `add`: at most DOWNLOAD_NO_LENGTH_BUDGET_MS,
 *   15 min, when the server sends no length; with a length it is 30 s plus
 *   the size at 120 kB/s, about 6.5 min for a 43 MB image (download.ts).
 *   Free when the image is cached, as CI prefetches it;
 * - the boot: quickchr's exported `defaultBootTimeout` for the host's own
 *   architecture, which `hostArch` pins, at the TCG factor, plus
 *   QUICKCHR_TIMEOUT_EXTRA (`bootBudget`);
 * - the REST reads after boot, under REST_BASE_MS each.
 */
const DOWNLOAD_BUDGET_MS = 15 * 60_000;
const SETUP_MS = DOWNLOAD_BUDGET_MS + bootBudget(hostArch()) + 4 * REST_BASE_MS;
/** `afterAll` may wait out a setup still running, then removes the machine. */
const CLEANUP_MS = SETUP_MS + TEARDOWN_MS;
/** Each test: REST commands with their own budgets (router.ts), and a 3-packet ping. */
const TEST_MS = 120_000;
/** A capture that sees fewer packets than it waits for ends here, well inside TEST_MS. */
const CAPTURE_MS = 60_000;
/** Mangle rules this file adds carry this comment, and only those are removed. */
const COMMENT = "tzsp-it";

interface Results {
	target: string;
	quickchr: string;
	machine: string;
	accelerator?: string;
	bootMs?: number;
	router?: Awaited<ReturnType<Router["identity"]>>;
	/** ISO 8601, UTC. */
	date: string;
	passed: { test: string; packets: number }[];
}

const results: Results = {
	target: TARGET,
	quickchr: "",
	machine: "",
	date: new Date().toISOString(),
	passed: [],
};
let router: Router;
/** The setup, so `afterAll` can wait for it to settle before removing. */
let setup: Promise<void> | undefined;
/** A version as RouterOS reports it: `7.25.1`, `7.26beta5`. */
const VERSION = /^\d+\.\d+(\.\d+)?(beta\d+|rc\d+)?$/;

/** The ICMP type of a packet record with layers: 8 echo request, 0 reply. */
function icmpType(p: PacketRecord): number | undefined {
	const icmp = p.layers?.find((l) => l.protocol === "icmp");
	return icmp?.fields && "type" in icmp.fields
		? (icmp.fields as { type: number }).type
		: undefined;
}

const packets = (records: StreamRecord[]) =>
	records.filter((r): r is PacketRecord => r.type === "packet");
const summaryOf = (records: StreamRecord[]) =>
	records.at(-1) as SummaryRecord | undefined;

/** Echo requests GUEST -> PEER and replies PEER -> GUEST, by count. */
function echoes(list: PacketRecord[]) {
	return {
		requests: list.filter(
			(p) => icmpType(p) === 8 && p.src === GUEST && p.dst === PEER,
		).length,
		replies: list.filter(
			(p) => icmpType(p) === 0 && p.src === PEER && p.dst === GUEST,
		).length,
	};
}

/**
 * Open a capture on 127.0.0.1 port 0 that stops after `count` packets (or
 * CAPTURE_MS), run `arm(port)` against the router while it reads, and
 * return every record. The listener is closed in `finally`, whatever `arm`
 * did.
 */
async function capture(
	count: number,
	arm: (port: number) => Promise<void>,
): Promise<StreamRecord[]> {
	const abort = new AbortController();
	const stream = await openCapture({
		bind: "127.0.0.1",
		ports: [{ port: 0 }],
		count,
		durationMs: CAPTURE_MS,
		detail: "layers",
		signal: abort.signal,
	});
	const reading = Array.fromAsync(stream);
	try {
		const port = stream.listener.listeners[0]?.port ?? 0;
		expect(port).toBeGreaterThan(0);
		await arm(port);
		return await reading;
	} finally {
		abort.abort();
		await reading.catch(() => {});
		await stream.listener.closed;
	}
}

/** Stream ICMP to `port`, ping PEER `pings` times, and stop the sniffer however that went. */
const sniffAndPing = (port: number, pings: number) => async () => {
	await router.exec(snifferStream(port));
	await router.exec("/tool/sniffer/start");
	try {
		await router.sniffing();
		await router.exec(`/ping ${PEER} count=${pings}`);
	} finally {
		await router.exec("/tool/sniffer/stop");
	}
};

describe.skipIf(!LIVE)(`a ${TARGET} CHR streaming TZSP`, () => {
	beforeAll(async () => {
		setup = (async () => {
			results.quickchr = await version();
			results.machine = await create("tzsp-it", {
				routeros: TARGET,
				arch: hostArch(),
			});
			// Named before the boot, so a run killed later says what to remove.
			console.log(`machine: ${results.machine}`);
			results.bootMs = await start(results.machine);
			results.accelerator = accelerator(results.machine);
			const rest = await services(results.machine);
			router = new Router(rest.restUrl, rest.basic);
			results.router = await router.identity();
		})();
		await setup;
		// The record this tier promises: what the CHR itself reported.
		const r = results.router;
		expect(r?.version).toMatch(VERSION);
		expect(r?.architecture).toMatch(/\S/);
		if (VERSION.test(TARGET)) expect(r?.version).toBe(TARGET);
		console.log(
			`routeros: ${r?.version} ${r?.architecture} (${TARGET}), board ${r?.board}; ` +
				`${results.quickchr}, accel ${results.accelerator}, boot ${results.bootMs} ms`,
		);
	}, SETUP_MS);

	afterAll(async () => {
		await setup?.catch(() => {});
		if (RESULTS && results.machine)
			await saveLogs(results.machine, dirname(RESULTS));
		// Waits for any `add` still running, then removes and verifies.
		const left = await cleanupAll();
		if (RESULTS)
			await writeFile(RESULTS, `${JSON.stringify(results, null, "\t")}\n`);
		if (left.length > 0)
			throw new Error(
				`NOT REMOVED: ${left.join(", ")}; quickchr remove <name> clears it`,
			);
	}, CLEANUP_MS);

	test(
		"/tool/sniffer streaming, read through openCapture()",
		async () => {
			const records = await capture(6, (port) => sniffAndPing(port, 3)());
			const summary = summaryOf(records);
			expect(summary?.status).toBe("complete");
			expect(summary?.stoppedBy).toBe("count");
			expect(summary?.counters.invalid).toBe(0);
			const list = packets(records);
			expect(list).toHaveLength(6);
			for (const p of list) {
				expect(p.protocols).toEqual(["ethernet", "ipv4", "icmp"]);
				expect(p.layers?.[0]).toMatchObject({
					protocol: "tzsp",
					fields: { version: 1, type: "received", encapsulation: "ethernet" },
				});
			}
			expect(echoes(list)).toEqual({ requests: 3, replies: 3 });
			results.passed.push({
				test: "sniffer-opencapture",
				packets: list.length,
			});
		},
		TEST_MS,
	);

	test(
		"mangle action=sniff-tzsp, read through openCapture()",
		async () => {
			let counter = Number.NaN;
			const records = await capture(2, async (port) => {
				await router.exec(
					`/ip/firewall/mangle/add chain=output protocol=icmp dst-address=${PEER} ` +
						`action=sniff-tzsp sniff-target=${GATEWAY} sniff-target-port=${port} comment=${COMMENT}`,
				);
				try {
					await router.exec(SETTLE);
					await router.exec(`/ping ${PEER} count=2`);
					const rules = (await router.read(
						`/ip/firewall/mangle?comment=${COMMENT}`,
					)) as { packets?: string }[];
					counter = Number(rules[0]?.packets);
				} finally {
					await router.exec(
						`/ip/firewall/mangle/remove [find comment=${COMMENT}]`,
					);
				}
			});
			expect(counter).toBe(2);
			const summary = summaryOf(records);
			expect(summary?.status).toBe("complete");
			expect(summary?.stoppedBy).toBe("count");
			const list = packets(records);
			expect(list).toHaveLength(2);
			// The output chain sees only the requests (REPORT.md, mangle chains).
			expect(echoes(list)).toEqual({ requests: 2, replies: 0 });
			results.passed.push({ test: "mangle-opencapture", packets: list.length });
		},
		TEST_MS,
	);

	test(
		"/tool/sniffer streaming, read through the CLI's JSONL",
		async () => {
			// The CLI under Bun from src/; the built one runs under Node in test/node/.
			const proc = Bun.spawn(
				[
					process.execPath,
					"--no-env-file",
					BIN,
					"--bind",
					"127.0.0.1",
					"--port",
					"0",
					"--count",
					"6",
					"--duration",
					`${CAPTURE_MS}ms`,
					"--proto",
					"icmp",
					"--format",
					"jsonl",
					"--detail",
					"layers",
				],
				{ env: childEnv({ NO_COLOR: "1" }), stdout: "pipe", stderr: "pipe" },
			);
			const killer = setTimeout(() => proc.kill("SIGKILL"), TEST_MS - 10_000);
			try {
				const stderr = new Response(proc.stderr).text();
				const reader = proc.stdout.getReader();
				const decoder = new TextDecoder();
				let stdout = "";
				let armed: Promise<void> | undefined;
				for (;;) {
					const { value, done } = await reader.read();
					if (done) break;
					stdout += decoder.decode(value, { stream: true });
					if (!armed && stdout.includes("\n")) {
						const header = JSON.parse(stdout.split("\n")[0] as string) as {
							listeners: { port: number }[];
						};
						const port = header.listeners[0]?.port ?? 0;
						expect(port).toBeGreaterThan(0);
						armed = sniffAndPing(port, 3)();
						// A failed arm must not leave the read waiting for packets.
						armed.catch(() => proc.kill("SIGTERM"));
					}
				}
				await armed;
				expect(await proc.exited).toBe(0);
				expect(await stderr).toBe("");
				const records = stdout
					.trim()
					.split("\n")
					.map((l) => JSON.parse(l) as StreamRecord);
				expect(records[0]?.type).toBe("header");
				const summary = summaryOf(records);
				expect(summary?.status).toBe("complete");
				expect(summary?.stoppedBy).toBe("count");
				const list = packets(records);
				expect(list).toHaveLength(6);
				expect(echoes(list)).toEqual({ requests: 3, replies: 3 });
				results.passed.push({
					test: "sniffer-cli-jsonl",
					packets: list.length,
				});
			} finally {
				clearTimeout(killer);
				proc.kill("SIGKILL");
			}
		},
		TEST_MS,
	);
});
