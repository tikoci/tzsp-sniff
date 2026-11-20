/**
 * A CHR's REST API, and the SLIRP addresses and sniffer settings the lab
 * (test/lab/tzsp-senders/) and the integration tier (test/integration/)
 * both use. The facts here were grounded by the lab on 7.24.6 and 7.25.1
 * x86 CHRs under KVM (REPORT.md).
 */
import { stopping } from "./quickchr.ts";

/** Where pings go: SLIRP's DNS address, which answers ICMP echo. */
export const PEER = "10.0.2.3";
/** The CHR's address on its SLIRP NIC. */
export const GUEST = "10.0.2.15";
/**
 * The SLIRP gateway: QEMU delivers a datagram the guest sends to
 * `10.0.2.2:<port>` to the host's loopback at `<port>`, so a listener bound
 * to 127.0.0.1 port 0 receives it with no port forward.
 */
export const GATEWAY = "10.0.2.2";

/**
 * RouterOS reports a failed command in the text, with HTTP 200, ending in
 * its position: "bad parameter bogus (line 1 column 26)", "no such item
 * (/file/get; line 1)" (7.25.1 x86 CHR, by hand, 2026-11-19 UTC).
 */
const ROUTEROS_ERROR = /\((?:[^()]*; )?line \d+(?: column \d+)?\)$/;

/** A RouterOS command answers in ms on KVM, seconds under TCG; this is the base. */
export const REST_BASE_MS = 20_000;

/** How long a command may take: a base, plus what it waits for itself. */
export function commandBudget(command: string): number {
	let ms = REST_BASE_MS;
	const count = /\/ping .*count=(\d+)/.exec(command)?.[1];
	if (count) ms += Number(count) * 1000;
	for (const m of command.matchAll(/:delay (\d+)s/g)) ms += Number(m[1]) * 1000;
	return ms;
}

export interface Step {
	command: string;
	status: number;
	output: string;
}

export class StepError extends Error {}

/** Drop export header comments: they carry the CHR's software id. */
export const withoutComments = (s: string) =>
	s
		.split("\n")
		.filter((l) => !l.startsWith("#"))
		.join("\n");

export class Router {
	readonly url: string;
	private readonly basic: string;
	/** `url` is the REST base ending in `/rest`; `basic` is `user:password`. */
	constructor(url: string, basic: string) {
		this.url = url;
		this.basic = basic;
	}
	private async rest(
		path: string,
		init: { method?: string; body?: unknown; timeoutMs?: number } = {},
	): Promise<{ status: number; body: unknown }> {
		try {
			const res = await fetch(`${this.url}${path}`, {
				method: init.method ?? "GET",
				headers: {
					authorization: `Basic ${btoa(this.basic)}`,
					"content-type": "application/json",
				},
				...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
				signal: AbortSignal.any([
					AbortSignal.timeout(init.timeoutMs ?? REST_BASE_MS),
					stopping.signal,
				]),
			});
			const text = await res.text();
			let body: unknown = text;
			try {
				body = JSON.parse(text);
			} catch {}
			return { status: res.status, body };
		} catch {
			return { status: 0, body: undefined };
		}
	}
	/** A GET that must succeed; returns the parsed body. */
	async read(path: string): Promise<unknown> {
		const r = await this.rest(path);
		if (r.status !== 200)
			throw new StepError(`GET ${path}: status ${r.status}`);
		return r.body;
	}
	/** Run one RouterOS CLI command; a timeout, a non-200 or a RouterOS error fails it. */
	async exec(command: string): Promise<Step> {
		const { status, body } = await this.rest("/execute", {
			method: "POST",
			body: { script: command, "as-string": true },
			timeoutMs: commandBudget(command),
		});
		const output =
			typeof body === "object" && body !== null && "ret" in body
				? String((body as { ret: unknown }).ret)
				: "";
		const step = {
			command,
			status,
			output: withoutComments(output.replaceAll("\r\n", "\n")),
		};
		if (status !== 200 || ROUTEROS_ERROR.test(step.output.trim()))
			throw Object.assign(new StepError(`step failed: ${command}`), { step });
		return step;
	}
	/** Fail unless `/tool/sniffer` reports running; returns what it reported. */
	async sniffing(): Promise<string | undefined> {
		const s = (await this.read("/tool/sniffer")) as { running?: string };
		if (s.running !== "true") throw new StepError("the sniffer did not start");
		return s.running;
	}
	/** The version (the number only), architecture and board the router reports. */
	async identity(): Promise<{
		version: string;
		versionString: string;
		architecture: string;
		board: string;
	}> {
		const res = (await this.read("/system/resource")) as Record<string, string>;
		return {
			// "7.24.6 (long-term)": the number, then the channel the router names.
			version: (res.version ?? "").split(" ")[0] ?? "",
			versionString: res.version ?? "",
			architecture: res["architecture-name"] ?? "",
			board: res["board-name"] ?? "",
		};
	}
}

/**
 * `/tool/sniffer` streaming ICMP to or from PEER toward the gateway at
 * `port`. Every setting is given, so earlier experiments cannot leak in.
 */
export const snifferStream = (port: number) =>
	`/tool/sniffer/set streaming-enabled=yes streaming-server=${GATEWAY}:${port} ` +
	`filter-ip-address=${PEER}/32 filter-ip-protocol=icmp filter-operator-between-entries=and ` +
	`filter-stream=yes only-headers=no file-name=""`;

/** A precaution after adding a mangle rule over REST, so the ping meets a rule in effect. */
export const SETTLE = ":delay 2s";
