/**
 * Wireshark's reading of our pcapng (DESIGN.md, "`--write`": the claim that
 * Wireshark and TShark open it as `LINKTYPE_TZSP` and show the peer). The
 * file is written by the shipped `pcapngWriter` and `fileSink`, then read by
 * TShark as this (non-root) user; the test asserts an inner field, TZSP's
 * own fields, the interface and the peer comment.
 *
 * Gated by TZSP_SNIFF_TSHARK (`bun run test:tshark`), since TShark is not a
 * dependency; once set, a missing `tshark` fails rather than skips.
 * TZSP_SNIFF_TSHARK_VERSION pins the version: when set, the test fails on any
 * other, so a runner image that moves TShark shows here first. CI's `tshark`
 * job sets both.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileSink } from "../../src/file.ts";
import type { BoundListener, Capture } from "../../src/listen.ts";
import { pcapngWriter } from "../../src/pcapng.ts";
import { parseTzsp } from "../../src/tzsp.ts";
import { bytes, fixture } from "../unit/helpers.ts";

const LIVE = Boolean(process.env.TZSP_SNIFF_TSHARK);
const PINNED = process.env.TZSP_SNIFF_TSHARK_VERSION;

/** 7.25.1 x86_64 /tool/sniffer, an ICMP echo request 10.0.2.15 > 10.0.2.3. */
const REQUEST = fixture("7.25.1-x86-sniffer-stream")[0] as string;
const CONTROL = "01040000";

const LISTENERS: BoundListener[] = [
	Object.freeze({ address: "0.0.0.0", port: 37008, label: "router-a" }),
	Object.freeze({ address: "0.0.0.0", port: 37009, label: "router-b" }),
];

const capture = (
	seq: number,
	hex: string,
	listener: BoundListener,
	peer: string,
): Capture => {
	const datagram = bytes(hex);
	return {
		seq,
		time: 1_763_600_000_000 + seq,
		listener,
		peer: {
			address: peer,
			port: 41000 + seq,
			family: peer.includes(":") ? "IPv6" : "IPv4",
		},
		datagram,
		tzsp: parseTzsp(datagram),
	};
};

async function tshark(args: string[]) {
	const proc = Bun.spawn(["tshark", ...args], {
		stdout: "pipe",
		stderr: "pipe",
		env: { PATH: process.env.PATH ?? "", HOME: tmpdir(), LC_ALL: "C" },
	});
	const [stdout, stderr, code] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	return { stdout, stderr, code };
}

describe.skipIf(!LIVE)("TShark reads tzsp-sniff's pcapng", () => {
	const dir = mkdtempSync(join(tmpdir(), "tzsp-sniff-tshark-"));
	afterAll(() => rmSync(dir, { recursive: true, force: true }));
	const path = join(dir, "capture.pcapng");

	// Made once, for every test, so any one of them runs alone.
	beforeAll(async () => {
		const w = pcapngWriter(fileSink(path), { target: path });
		let failed = true;
		try {
			await w.open(LISTENERS);
			await w.write(
				capture(1, REQUEST, LISTENERS[0] as BoundListener, "10.0.2.15"),
			);
			await w.write(
				capture(2, CONTROL, LISTENERS[1] as BoundListener, "fe80::1"),
			);
			failed = false;
		} finally {
			// Closed however setup ends; after a failure, that failure is the
			// one reported, not the close's.
			const closing = w.close();
			if (failed) await closing.catch(() => {});
			else await closing;
		}
	});

	test("as a non-root user, at the pinned version", async () => {
		if (process.platform !== "win32") expect(process.getuid?.()).not.toBe(0);
		const { stdout, code } = await tshark(["--version"]);
		expect(code).toBe(0);
		const version = /^TShark \(Wireshark\) (\S+)/.exec(stdout)?.[1];
		expect(version).toBeDefined();
		console.log(`tshark: ${stdout.split("\n")[0]}`);
		if (PINNED) expect(version).toBe(PINNED);
	});

	test("an inner field, TZSP's fields, the interface and the peer, per packet", async () => {
		const fields = [
			"frame.number",
			"frame.interface_name",
			"frame.comment",
			"frame.time_epoch",
			"tzsp.version",
			"tzsp.type",
			"ip.src",
			"ip.dst",
			"icmp.type",
		];
		const { stdout, stderr, code } = await tshark([
			"-r",
			path,
			"-T",
			"fields",
			"-E",
			"separator=|",
			...fields.flatMap((f) => ["-e", f]),
		]);
		console.log(`tshark fields:\n${stdout}${stderr}`);
		expect(code).toBe(0);
		const rows = stdout
			.trimEnd()
			.split("\n")
			.map((line) =>
				Object.fromEntries(line.split("|").map((v, i) => [fields[i], v])),
			);
		expect(rows).toHaveLength(2);
		expect(rows[0]).toMatchObject({
			"frame.number": "1",
			"frame.interface_name": "router-a",
			"frame.comment": "peer=10.0.2.15:41001",
			"tzsp.version": "1",
			"ip.src": "10.0.2.15",
			"ip.dst": "10.0.2.3",
			"icmp.type": "8",
		});
		expect(Number(rows[0]?.["frame.time_epoch"])).toBeCloseTo(
			1_763_600_000.001,
			3,
		);
		expect(rows[1]).toMatchObject({
			"frame.number": "2",
			"frame.interface_name": "router-b",
			"frame.comment": "peer=[fe80::1]:41002",
			"tzsp.version": "1",
			"ip.src": "",
		});
	});

	test("the file's link type is TZSP", async () => {
		const { stdout, code } = await tshark([
			"-r",
			path,
			"-T",
			"fields",
			"-e",
			"frame.protocols",
		]);
		expect(code).toBe(0);
		const [first, second] = stdout.trimEnd().split("\n");
		expect(first).toMatch(/^tzsp:eth:ethertype:ip:icmp/);
		expect(second).toMatch(/^tzsp/);
	});
});
