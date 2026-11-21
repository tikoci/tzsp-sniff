/**
 * The m2ir table generator (scripts/m2ir.ts, #31): what it keeps of m2ir's
 * scope and confidence, and what stops it. Each case changes the vendored
 * profile in memory; JSON is YAML, so a changed copy goes back in as JSON.
 * `bun run lint:m2ir` checks the committed table against the snapshot.
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { readMndp, VENDOR, writeTable } from "../../scripts/m2ir.ts";

const read = (p: string) => readFileSync(join(VENDOR, p), "utf8");
const PHYSICAL = read("physical/mndp.yaml");
const PROFILE = read("profiles/mndp/profile.yaml");
const parse = (y: string) => Bun.YAML.parse(y) as any;

/** The model from the vendored physical file and the profile after `change`. */
function model(change: (profile: any) => void = () => {}, physical = PHYSICAL) {
	const profile = parse(PROFILE);
	change(profile);
	return readMndp(physical, JSON.stringify(profile), "0".repeat(40));
}
const error = (f: () => unknown) => {
	try {
		f();
	} catch (e) {
		return (e as Error).message;
	}
	return "no error";
};

describe("m2ir generator", () => {
	test("reads the vendored MNDP files: TLVs 1 to 19 but 13, the header and the request rule", () => {
		const m = model();
		expect(m.port).toBe(5678);
		expect(m.tlvs.map((t) => t.type)).toEqual([
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17, 18, 19,
		]);
		expect(m.skipped).toEqual([]);
		expect(m.request).toMatchObject({
			headers: [0],
			tlvs: [{ type: 6, lengths: [0] }],
		});
		expect(m.header.orders).toBe(
			"little-endian on x86_64, arm, arm64; big-endian on mipsbe",
		);
		const ttl = m.tlvs.find((t) => t.type === 19);
		expect(ttl).toMatchObject({
			field: "ttl",
			encoding: "u8",
			length: 1,
			since: "7.24.5",
			introduced: "7.24",
			confidence: "observed-only",
		});
		expect(m.tlvs.find((t) => t.type === 15)).toMatchObject({
			field: "address6",
			repeat: true,
		});
		expect(m.tlvs.find((t) => t.type === 9)?.field).toBe("aggregatedSizeHex");
	});

	test("a TLV, value or bit m2ir marks guessed, inferred or superseded gets no name", () => {
		const m = model((p) => {
			p.tlvs[12].confidence = "guessed";
			p.tlvs[19].values[0].confidence = "inferred";
			p.tlvs[18].bits[1].confidence = "superseded";
		});
		expect(m.tlvs.find((t) => t.type === 12)).toBeUndefined();
		expect(m.tlvs.find((t) => t.type === 19)?.values).toEqual([]);
		expect(m.tlvs.find((t) => t.type === 18)?.bits?.map((b) => b.name)).toEqual(
			["capsman"],
		);
		expect(m.skipped).toEqual([
			"TLV 12 (board): guessed",
			"TLV 18 bits 2 (cmr): superseded",
			"TLV 19 values 0 (dying-gasp): inferred",
		]);
		// The table then names neither: TLV 12 would be read as an unknown type.
		const table = writeTable(m, parse(PROFILE).scope["versions-observed"]);
		expect(table).not.toContain('"board"');
		expect(table).toContain(" * - TLV 12 (board): guessed");
	});

	test("a named value or bit carries its own versions, exactly, and not the TLV's since", () => {
		const table = writeTable(
			model(),
			parse(PROFILE).scope["versions-observed"],
		);
		const decl = (field: string) =>
			table.split("\n").find((l) => l.trimStart().startsWith(`${field}: {`)) ??
			"";
		// dying-gasp was seen on 7.26beta5 only; TTL itself has since 7.24.5.
		expect(decl("ttlName")).toContain('versionsSeen: ["7.26beta5"]');
		expect(decl("ttlName")).not.toContain("since:");
		expect(decl("ttl")).toContain('since: "7.24.5"');
		expect(decl("runningFlags")).not.toContain("since:");
		// Each name's versions are listed, not a count and a range.
		expect(decl("ipv6EnabledName")).not.toMatch(/\d+ versions, /);
		expect(table).not.toMatch(/\d+ versions, \S+ to /);
	});

	test("`all` is every version m2ir observed, and a version outside them stops it", () => {
		const m = model();
		expect(m.tlvs.find((t) => t.type === 1)?.versionsSeen).toEqual(
			parse(PROFILE).scope["versions-observed"],
		);
		expect(
			error(() =>
				model((p) => {
					p.tlvs[5]["versions-seen"] = ["7.99"];
				}),
			),
		).toContain("7.99 is not in scope.versions-observed");
	});

	test("what the dissector cannot read stops it, rather than being left out", () => {
		const cases: [string, (p: any) => void][] = [
			["is not one the dissector reads", (p) => (p.tlvs[5].encoding = "u64be")],
			["does not fit mac48", (p) => (p.tlvs[1].length = 4)],
			["only a string encoding may repeat", (p) => (p.tlvs[10].repeat = true)],
			["unknown clause", (p) => p.requests.rule["any-of"].push({ hmm: 1 })],
			["expected one field", (p) => p.header.fields.push(p.header.fields[0])],
			["unknown label", (p) => (p.tlvs[7].confidence = "sure")],
			["is named twice", (p) => (p.tlvs[8].name = "identity")],
			["is named twice", (p) => (p.tlvs[8].name = "other-tlvs")],
		];
		for (const [message, change] of cases)
			expect(error(() => model(change))).toContain(message);
		// A TLV header that is not u16be type and length.
		expect(
			error(() =>
				model(undefined, PHYSICAL.replace("width: u16be }", "width: u8 }")),
			),
		).toContain("expected u16be type and length");
		// What the reader assumes of the physical file: a header of another
		// size, an encoding in another byte order or body, an unknown endian.
		const physical: [string, string, string][] = [
			[
				'size: 4\n        role: "profile-defined',
				'size: 8\n        role: "profile-defined',
				"expected a 4-byte header",
			],
			[
				'endian: le\n    role: "unsigned 32-bit integer, little',
				'endian: be\n    role: "unsigned 32-bit integer, little',
				"value-encodings.u32le.endian",
			],
			[
				'endian: be\n    role: "IPv4',
				'endian: le\n    role: "IPv4',
				"value-encodings.ipv4.endian",
			],
			["body: utf8", "body: latin1", "value-encodings.text.body"],
			["size: 6\n", "size: 8\n", "value-encodings.mac48.size"],
		];
		for (const [from, to, message] of physical) {
			expect(PHYSICAL).toContain(from);
			expect(
				error(() => model(undefined, PHYSICAL.replace(from, to))),
			).toContain(message);
		}
		expect(
			error(() =>
				model((p) => {
					p.header.fields[0]["byte-order-by-architecture"][0].endian = "middle";
				}),
			),
		).toContain("expected le or be: middle");
	});
});
