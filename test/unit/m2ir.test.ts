/**
 * The m2ir table generator (scripts/m2ir.ts, #31): what it keeps of m2ir's
 * scope and confidence, and what stops it. Each case changes the vendored
 * profile in memory; JSON is YAML, so a changed copy goes back in as JSON.
 * `bun run lint:m2ir` checks the committed table against the snapshot.
 */
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
	cpSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	FILES,
	readMndp,
	refresh,
	STAGED,
	TABLE,
	VENDOR,
	writeTable,
} from "../../scripts/m2ir.ts";

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
		expect(m.tlvs.find((t) => t.type === 19)?.values).toBeUndefined();
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

	test("a field declaration carries m2ir's confidence only; versions and since go to the facts", () => {
		const table = writeTable(
			model(),
			parse(PROFILE).scope["versions-observed"],
		);
		const decls = table.slice(table.indexOf("MNDP_TLV_FIELDS"));
		const decl = (field: string) =>
			decls.split("\n").find((l) => l.trimStart().startsWith(`${field}: {`)) ??
			"";
		for (const f of [
			"ttl",
			"ttlName",
			"runningFlags",
			"ipv6EnabledName",
			"macAddress",
		]) {
			expect(decl(f)).toContain("confidence:");
			expect(decl(f)).not.toContain("versionsSeen");
			expect(decl(f)).not.toContain("since");
			expect(decl(f)).not.toContain("seen on");
		}
		// The facts keep them: TTL since 7.24.5, its dying-gasp value on 7.26beta5 only.
		const facts = table.slice(
			table.indexOf("MNDP_M2IR_FACTS"),
			table.indexOf("MNDP_TLV_FIELDS"),
		);
		expect(facts).toContain(
			'"field":"ttl","tlv":19,"name":"ttl","confidence":"observed-only"',
		);
		expect(facts).toContain('"since":"7.24.5"');
		expect(facts).toContain(
			'{"value":0,"name":"dying-gasp","confidence":"observed-only","versionsSeen":["7.26beta5"]}',
		);
	});

	test("m2ir text in a generated comment cannot end it", () => {
		// An unnamed TLV keeps its m2ir name in the banner's list.
		const m = model((p) => {
			p.tlvs[12].confidence = "guessed";
			p.tlvs[12].name = "board */ export const x = 1; /*";
		});
		const table = writeTable(m, parse(PROFILE).scope["versions-observed"]);
		// The banner ends at the first */, before the first import.
		const banner = table.slice(0, table.indexOf("*/") + 2);
		expect(banner).toContain(
			" * - TLV 12 (board *\\/ export const x = 1; /*): guessed",
		);
		expect(table.indexOf("*/")).toBeLessThan(table.indexOf("import "));
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

	test("an enum whose values m2ir all leaves unnamed has no name field; a bitmask still lists its bits", () => {
		const m = model((p) => {
			for (const v of p.tlvs[19].values) v.confidence = "guessed";
			for (const b of p.tlvs[18].bits) b.confidence = "inferred";
		});
		expect(m.tlvs.find((t) => t.type === 19)?.values).toBeUndefined();
		const table = writeTable(m, parse(PROFILE).scope["versions-observed"]);
		expect(table).not.toContain("ttlName");
		// The reader names each set bit bit-0x01 and so on: the field stays,
		// with no confidence claimed for names it does not have.
		const flags = table.split("\n").find((l) => l.includes("runningFlags: {"));
		expect(flags).toContain("m2ir names none");
		expect(flags).not.toContain("confidence");
	});

	test("what the dissector cannot read stops it, rather than being left out", () => {
		const cases: [string, (p: any) => void][] = [
			["is not one the dissector reads", (p) => (p.tlvs[5].encoding = "u64be")],
			["does not fit mac48", (p) => (p.tlvs[1].length = 4)],
			["may repeat, not u32le", (p) => (p.tlvs[10].repeat = true)],
			// mndp.ts keeps one MAC: two would leave the second, not a list.
			["may repeat, not mac48", (p) => (p.tlvs[1].repeat = true)],
			// A request clause the reader would match more broadly than m2ir.
			[
				"unknown key tested-value-lengths",
				(p) => (p.requests.rule["any-of"][0]["tested-value-lengths"] = [0]),
			],
			[
				"unknown key has-tlv, tested-value-lengths, untested",
				(p) => (p.requests.rule["any-of"][1].header = 0),
			],
			// mndp.ts reads the header big-endian; 1 from a little-endian sender is 0x01000000.
			[
				"depends on the sender's byte order",
				(p) => (p.requests.rule["any-of"][0].header = 1),
			],
			// The reader looks up one bit at a time, and a value is a byte.
			["is not one bit of a byte", (p) => (p.tlvs[18].bits[0].mask = 3)],
			["is not one bit of a byte", (p) => (p.tlvs[18].bits[0].mask = 0)],
			["is not one bit of a byte", (p) => (p.tlvs[18].bits[0].mask = 0x100)],
			["is not a byte", (p) => (p.tlvs[19].values[0].value = 256)],
			// A name becomes a TypeScript identifier.
			["not a lower-case name", (p) => (p.tlvs[8].name = "a*/b")],
			// A bitmask's Flags field is taken even when m2ir names no bit.
			[
				"field runningFlags is named twice",
				(p) => {
					delete p.tlvs[18].bits;
					p.tlvs[8].name = "running-flags";
				},
			],
			["unknown clause", (p) => p.requests.rule["any-of"].push({ hmm: 1 })],
			["expected one field", (p) => p.header.fields.push(p.header.fields[0])],
			["unknown label", (p) => (p.tlvs[7].confidence = "sure")],
			["is named twice", (p) => (p.tlvs[8].name = "identity")],
			["is named twice", (p) => (p.tlvs[8].name = "other-tlvs")],
		];
		for (const [message, change] of cases)
			expect(error(() => model(change))).toContain(message);
		// A TLV header that is not u16be type and length, by value or by key.
		const records: [string, string][] = [
			["width: u16be }", "width: u8 }"],
			["{ name: type, width: u16be }", "{ name: type, size: u16be }"],
			['{ name: value, size: "length" }', '{ name: value, width: "length" }'],
		];
		for (const [from, to] of records) {
			expect(PHYSICAL).toContain(from);
			expect(
				error(() => model(undefined, PHYSICAL.replace(from, to))),
			).toContain("expected u16be type and length");
		}
		// The commit goes into the banner.
		expect(error(() => readMndp(PHYSICAL, PROFILE, "main */ x"))).toContain(
			"expected a 40-digit commit sha",
		);
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
		// The table's port is registered on UDP.
		expect(
			error(() =>
				model(undefined, PHYSICAL.replace("protocol: udp", "protocol: tcp")),
			),
		).toContain("expected udp");
		expect(
			error(() =>
				model((p) => {
					p.header.fields[0]["byte-order-by-architecture"][0].endian = "middle";
				}),
			),
		).toContain("expected le or be: middle");
	});

	describe("refresh", () => {
		const sha = "f".repeat(40);
		/** m2ir as GitHub serves it, with `change` applied to the files. */
		const github =
			(change: (path: string) => Response | undefined = () => undefined) =>
			async (url: string | URL | Request) => {
				const u = String(url);
				if (u.includes("/commits/"))
					return Response.json({
						sha,
						commit: { committer: { date: "2026-11-21T00:00:00Z" } },
					});
				if (u.includes("/compare/"))
					return Response.json({ status: "identical" });
				const path = FILES.find((p) => u.endsWith(`/${sha}/${p}`));
				if (!path) return new Response("not stubbed", { status: 599 });
				return change(path) ?? new Response(readFileSync(join(VENDOR, path)));
			};
		/** A copy of the snapshot and table, and every file's bytes in it. */
		function copy() {
			const dir = mkdtempSync(join(tmpdir(), "tzsp-m2ir-"));
			cpSync(VENDOR, join(dir, "vendor"), { recursive: true });
			cpSync(TABLE, join(dir, "table.ts"));
			const to = { vendor: join(dir, "vendor"), table: join(dir, "table.ts") };
			const bytes = () =>
				Object.fromEntries(
					[
						...readdirSync(to.vendor, { recursive: true, encoding: "utf8" }),
						"../table.ts",
					]
						.sort()
						.flatMap((p) => {
							try {
								return [[p, readFileSync(join(to.vendor, p), "hex")]];
							} catch {
								return []; // a directory
							}
						}),
				);
			return { dir, to, bytes };
		}

		test("a failed download or a refused schema leaves the snapshot and table as they were", async () => {
			const failures: [string, (p: string) => Response | undefined][] = [
				[
					"profiles/mndp/profile.yaml at",
					(p) =>
						p.endsWith("profile.yaml")
							? new Response("", { status: 500 })
							: p === "LICENSE"
								? new Response("changed\n")
								: undefined,
				],
				[
					"expected a 4-byte header",
					(p) =>
						p === "physical/mndp.yaml"
							? new Response(
									PHYSICAL.replace(
										'size: 4\n        role: "profile-defined',
										'size: 8\n        role: "profile-defined',
									),
								)
							: undefined,
				],
			];
			for (const [message, change] of failures) {
				const { dir, to, bytes } = copy();
				try {
					const before = bytes();
					expect(
						await refresh("main", to, github(change) as typeof fetch).catch(
							(e) => e.message,
						),
					).toContain(message);
					expect(bytes()).toEqual(before);
				} finally {
					rmSync(dir, { recursive: true, force: true });
				}
			}
		});

		test("another license, a write that fails, or another refresh writing leaves them as they were", async () => {
			const cases: [
				string,
				(p: string) => Response | undefined,
				(to: { vendor: string; table: string }, dir: string) => void,
			][] = [
				[
					"is not the CC0-1.0 text",
					(p) => (p === "LICENSE" ? new Response("changed\n") : undefined),
					() => {},
				],
				// The table's directory cannot be made: its parent is a file.
				[
					"mkdir",
					() => undefined,
					(to, dir) => {
						writeFileSync(join(dir, "file"), "");
						to.table = join(dir, "file", "table.ts");
					},
				],
				[
					"another refresh is writing",
					() => undefined,
					(to) => writeFileSync(to.table + STAGED, "theirs"),
				],
			];
			for (const [message, change, prepare] of cases) {
				const { dir, to, bytes } = copy();
				try {
					prepare(to, dir);
					const before = bytes();
					expect(
						await refresh("main", to, github(change) as typeof fetch).catch(
							(e) => `${e.code ?? ""} ${e.message}`,
						),
					).toContain(message);
					expect(bytes()).toEqual(before);
				} finally {
					rmSync(dir, { recursive: true, force: true });
				}
			}
		});

		test("a good refresh writes the files, SOURCE.json with the commit, and the table", async () => {
			const { dir, to } = copy();
			// A physical file other than the vendored one, so a skipped write shows.
			const physical = `${PHYSICAL}# changed upstream\n`;
			try {
				const source = await refresh(
					"main",
					to,
					github((p) =>
						p === "physical/mndp.yaml" ? new Response(physical) : undefined,
					) as typeof fetch,
				);
				expect(source.commit).toBe(sha);
				expect(
					readFileSync(join(to.vendor, "physical/mndp.yaml"), "utf8"),
				).toBe(physical);
				const written = JSON.parse(
					readFileSync(join(to.vendor, "SOURCE.json"), "utf8"),
				);
				expect(written).toMatchObject({
					commit: sha,
					committed: "2026-11-21T00:00:00Z",
					files: {
						"physical/mndp.yaml": createHash("sha256")
							.update(physical)
							.digest("hex"),
					},
				});
				expect(readFileSync(to.table, "utf8")).toContain(
					`M2IR_COMMIT = "${sha}"`,
				);
				// Nothing staged is left behind.
				expect(
					readdirSync(dir, { recursive: true, encoding: "utf8" }).filter((p) =>
						p.endsWith(STAGED),
					),
				).toEqual([]);
			} finally {
				rmSync(dir, { recursive: true, force: true });
			}
		});
	});

	test("the license README links ships in the package", () => {
		const pack = Bun.spawnSync(
			["bun", "pm", "pack", "--dry-run", "--ignore-scripts"],
			{
				cwd: join(VENDOR, "..", ".."),
			},
		);
		expect(pack.exitCode).toBe(0);
		expect(pack.stdout.toString()).toContain(" vendor/m2ir/LICENSE\n");
	});
});
