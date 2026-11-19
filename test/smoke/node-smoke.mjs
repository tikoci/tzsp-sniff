// Runs under Node, against the built dist/, because Bun passing proves nothing
// about Node (tikoci-testing). A smoke check, not a second test framework:
// it exits non-zero on the first wrong value and prints a marker on success.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createSocket } from "node:dgram";
import { once } from "node:events";
import {
	dissect,
	listen,
	openCapture,
	parseTzsp,
	TZSP_PORT,
} from "../../dist/index.js";

assert.equal(TZSP_PORT, 37008);
const input = Uint8Array.from([1, 0, 0, 1, 1, 0xaa]);
const d = parseTzsp(input);
assert.equal(d.kind, "packet");
assert.equal(d.encapsulationName, "ethernet");
assert.equal(d.payload.length, 1);
assert.equal(d.problem, undefined);
assert.equal(d.datagram, input);
assert.equal(parseTzsp(Uint8Array.from([1, 4, 0, 0])).kind, "control");

// 7.25.1 x86_64 /tool/sniffer, an ICMP echo request (test/fixtures/routeros/).
const REQUEST = Buffer.from(
	"010000010152550a0002030282574d9a0108004500003861b40000ff0141ff0a00020f0a00020308003154b200000080abaaaad62c5655010483ab5706872e6f5e8db5caceeb42ec99ba2e",
	"hex",
);
assert.deepEqual(dissect(parseTzsp(REQUEST).payload).protocols, [
	"ethernet",
	"ipv4",
	"icmp",
]);

async function sendTo(port) {
	const socket = createSocket("udp4");
	await new Promise((resolve, reject) =>
		socket.send(REQUEST, port, "127.0.0.1", (e) => (e ? reject(e) : resolve())),
	);
	socket.close();
}

// A real UDP round trip on Node's sockets: listen(), then the capture core.
const listener = await listen({ ports: [{ port: 0 }], bind: "127.0.0.1" });
await sendTo(listener.listeners[0].port);
for await (const capture of listener) {
	assert.equal(capture.tzsp.kind, "packet");
	assert.equal(Object.getPrototypeOf(capture.datagram), Uint8Array.prototype);
	break;
}
await listener.closed;

const stream = await openCapture({ ports: [{ port: 0 }], count: 1 });
const types = [];
for await (const record of stream) {
	types.push(record.type);
	if (record.type === "header") await sendTo(record.listeners[0].port);
}
assert.deepEqual(types, ["header", "packet", "summary"]);

// The built executable under Node.
const child = spawn(
	process.execPath,
	["dist/cli/bin.js", "--port", "0", "--count", "1", "--format", "jsonl"],
	{
		env: { PATH: process.env.PATH ?? "" },
		stdio: ["ignore", "pipe", "inherit"],
	},
);
let out = "";
child.stdout.setEncoding("utf8");
child.stdout.on("data", (chunk) => {
	const first = out === "" || !out.includes("\n");
	out += chunk;
	if (first && out.includes("\n"))
		sendTo(JSON.parse(out.split("\n")[0]).listeners[0].port);
});
// "close", not "exit": stdio is fully read by then.
const [code] = await once(child, "close");
assert.equal(code, 0);
const records = out
	.trimEnd()
	.split("\n")
	.map((l) => JSON.parse(l));
assert.deepEqual(
	records.map((r) => r.type),
	["header", "packet", "summary"],
);
assert.equal(records[2].status, "complete");

console.log(`node-smoke: ok (node ${process.version})`);
