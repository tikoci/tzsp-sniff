import { describe, expect, test } from "bun:test";
import { dissect } from "../../src/dissect.ts";
import type { Capture } from "../../src/listen.ts";
import {
	DETAILS,
	type Detail,
	datagramRecord,
	ENTRY_FIELDS,
	packetRecord,
	type PacketRecord,
	type SummaryRecord,
	selectFields,
	type WarningRecord,
} from "../../src/records.ts";
import { parseTzsp } from "../../src/tzsp.ts";
import { bytes, eth, ipv4, TZSP_HEADER, tcp } from "./helpers.ts";

/** `--fields` (DESIGN.md, "Output for agents"). */
describe("selectFields", () => {
	const packet: PacketRecord = {
		type: "packet",
		seq: 7,
		time: "2026-11-19T00:00:00.000Z",
		listener: "37008",
		line: "a > b",
		src: "10.0.2.15",
		dst: "10.0.2.3",
		protocols: ["ethernet", "ipv4", "icmp"],
	};
	const tables = {
		protocols: {},
		problems: {},
		senders: {
			top: [],
			otherEntries: 0,
			otherEntriesCapped: false,
			otherCount: 0,
		},
		conversations: {
			top: [],
			otherEntries: 0,
			otherEntriesCapped: false,
			otherCount: 0,
		},
	};
	const counters = {
		datagrams: 0,
		packets: 0,
		control: 0,
		unsupported: 0,
		invalid: 0,
		filtered: 0,
		dropped: 0,
		unread: 0,
		unsaved: 0,
	};

	test("only the named fields, in that order, after type; absent ones left out", () => {
		const out = selectFields(packet, ["dst", "srcPort", "seq", "type"]);
		expect(out).toEqual({ type: "packet", dst: "10.0.2.3", seq: 7 });
		expect(Object.keys(out)).toEqual(["type", "dst", "seq"]);
	});

	test("a summary keeps its status, and its error when it failed", () => {
		const ok: SummaryRecord = {
			type: "summary",
			status: "complete",
			stoppedBy: "count",
			durationMs: 5,
			counters,
			...tables,
		};
		expect(selectFields(ok, ["counters"])).toEqual({
			type: "summary",
			status: "complete",
			counters,
		});
		// Listed, status keeps its place.
		expect(Object.keys(selectFields(ok, ["stoppedBy", "status"]))).toEqual([
			"type",
			"stoppedBy",
			"status",
		]);
		const failed: SummaryRecord = {
			...ok,
			status: "error",
			error: { code: "capture/expect-unmet", message: "m" },
		};
		expect(selectFields(failed, ["durationMs"])).toEqual({
			type: "summary",
			status: "error",
			durationMs: 5,
			error: { code: "capture/expect-unmet", message: "m" },
		});
	});

	test("a header, warning or tip is returned whole", () => {
		const warning: WarningRecord = {
			type: "warning",
			code: "capture/all-filtered",
			message: "m",
			fix: "f",
		};
		expect(selectFields(warning, ["src"]) as unknown).toEqual(warning);
		expect(
			selectFields(
				{ type: "tip", code: "tip/default-duration", message: "m" },
				["src"],
			),
		).toEqual({ type: "tip", code: "tip/default-duration", message: "m" });
	});

	test("every field a packet or record carries is named, at the detail that adds it", () => {
		const datagram = bytes(
			TZSP_HEADER +
				eth(
					0x0800,
					ipv4({ proto: 6, payload: tcp({ sp: 1, dp: 2, flags: 2 }) }),
				),
		);
		// A transmitted record (unsupported here) with a channel tag.
		const tagged = bytes("010100011201060100");
		const at = (d: Uint8Array): Capture => ({
			seq: 1,
			time: 0,
			listener: { address: "0.0.0.0", port: 1, label: "1" },
			peer: { address: "127.0.0.1", port: 2, family: "IPv4" },
			datagram: d,
			tzsp: parseTzsp(d),
		});
		const fields = ENTRY_FIELDS as Record<string, Detail>;
		const seen = new Set<string>();
		for (const detail of DETAILS) {
			const p = at(datagram);
			const records = [
				packetRecord(p, dissect(p.tzsp.payload as Uint8Array), detail),
				datagramRecord(at(tagged), detail),
			];
			for (const record of records) {
				for (const key of Object.keys(record)) {
					if (key === "type") continue;
					seen.add(key);
					expect({ detail, key, at: fields[key] }).toEqual({
						detail,
						key,
						at: DETAILS.slice(0, DETAILS.indexOf(detail) + 1).find(
							(d) => d === fields[key],
						) as Detail,
					});
				}
			}
		}
		// The vectors reach every field but a problem and a VLAN.
		expect([...seen].sort()).toEqual(
			Object.keys(ENTRY_FIELDS)
				.filter((k) => k !== "vlan")
				.sort(),
		);
	});
});
