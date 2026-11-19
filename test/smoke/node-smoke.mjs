// Runs under Node, against the built dist/, because Bun passing proves nothing
// about Node (tikoci-testing). A smoke check, not a second test framework:
// it exits non-zero on the first wrong value and prints a marker on success.
import assert from "node:assert/strict";
import { parseTzsp, TZSP_PORT } from "../../dist/index.js";

assert.equal(TZSP_PORT, 37008);
const input = Uint8Array.from([1, 0, 0, 1, 1, 0xaa]);
const d = parseTzsp(input);
assert.equal(d.kind, "packet");
assert.equal(d.encapsulationName, "ethernet");
assert.equal(d.payload.length, 1);
assert.equal(d.problem, undefined);
assert.equal(d.datagram, input);
assert.equal(parseTzsp(Uint8Array.from([1, 4, 0, 0])).kind, "control");
console.log(`node-smoke: ok (node ${process.version})`);
