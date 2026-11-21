/**
 * The MNDP lab's capture (test/lab/mndp/lab.ts), on loopback with a stand-in
 * router: what an experiment keeps as its own. The datagrams are the lab's
 * own evidence from RouterOS 7.25.1 x86_64.
 */
import { expect, test } from "bun:test";
import { createSocket } from "node:dgram";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Router } from "../chr/router.ts";
import {
	type Evidence,
	experiment,
	Listener,
	mndpView,
	UTF8_IDENTITY,
} from "../lab/mndp/lab.ts";
import { closeSocket, until } from "./helpers.ts";

const evidence = JSON.parse(
	readFileSync(
		join(import.meta.dir, "..", "lab", "mndp", "evidence", "7.25.1-x86.json"),
		"utf8",
	),
) as Evidence;
const datagrams = (name: string) =>
	evidence.experiments
		.find((e) => e.name === name)
		?.datagrams.map((d) => Buffer.from(d.hex, "hex")) ?? [];

test("ipv6-disabled keeps no announcement that arrived during its setup", async () => {
	// A packing announcement passes ipv6-disabled's check too: TLV 14 is the
	// finding, so the check cannot tell one sent before the setup took effect.
	const [early] = datagrams("packing");
	const later = datagrams("ipv6-disabled");
	if (!early || later.length !== 2) throw new Error("evidence changed");
	const listener = new Listener();
	const socket = createSocket("udp4");
	try {
		const port = await listener.open();
		const send = (d: Buffer) =>
			new Promise<void>((resolve, reject) =>
				socket.send(d, port, "127.0.0.1", (e) => (e ? reject(e) : resolve())),
			);
		const router = {
			exec: async () => {
				await send(early);
				// The early one is in before the setup returns.
				await until(() => listener.kept.length === 1);
				setTimeout(() => {
					for (const d of later) void send(d);
				}, 200);
				return { output: "" };
			},
		} as unknown as Router;
		const kept = await experiment(
			router,
			listener,
			UTF8_IDENTITY,
			"ipv6-disabled",
			["/ipv6/settings/set disable-ipv6=yes"],
			2,
		);
		expect(
			kept.datagrams.map(
				(d) => mndpView(Buffer.from(d.hex, "hex"))?.fields.header,
			),
		).toEqual(["08000000", "09000000"]);
	} finally {
		listener.close();
		await closeSocket(socket);
	}
}, 15_000);
