/**
 * Tables generated from m2ir (DESIGN.md, "Tables from m2ir, not by hand").
 *
 *   bun scripts/m2ir.ts                 # write src/dissect/mndp-table.ts from vendor/m2ir
 *   bun scripts/m2ir.ts --check         # offline: the snapshot is SOURCE.json's, the table is the snapshot's
 *   bun scripts/m2ir.ts refresh [ref]   # networked: vendor m2ir's files at ref (default main), then write
 *
 * The input is only the vendored snapshot in vendor/m2ir/, so generation and
 * `--check` (part of `bun run lint`) run offline. `refresh` is the one
 * networked step, and its output is a change to review: the snapshot, its
 * SOURCE.json, and the table. It takes only a commit on m2ir's `main`.
 *
 * What is generated keeps m2ir's scope and confidence: each field carries
 * its `confidence`, the versions it was seen on and `since`. A TLV, value or
 * bit m2ir marks `inferred`, `guessed` or `superseded` gets no name: its
 * bytes stay raw (maintainer, 2026-11-21, on #31). Anything in the YAML the
 * generator does not know (an encoding, a header shape, a request clause)
 * stops it, rather than being left out.
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const ROOT = join(import.meta.dir, "..");
export const VENDOR = join(ROOT, "vendor", "m2ir");
export const TABLE = join(ROOT, "src", "dissect", "mndp-table.ts");
const REPOSITORY = "tikoci/m2ir";
/** The m2ir files the table is generated from, and the licence they are under. */
export const FILES = [
	"LICENSE",
	"physical/mndp.yaml",
	"profiles/mndp/profile.yaml",
] as const;

export interface Source {
	repository: string;
	commit: string;
	/** The commit's date, as GitHub gives it. */
	committed: string;
	/** sha256 of each vendored file, by its path in m2ir. */
	files: Record<string, string>;
}

class GenerateError extends Error {}

// ── reading the YAML, checked ───────────────────────────────────────────────

type Yaml = Record<string, unknown>;

const fail = (where: string, what: string): never => {
	throw new GenerateError(`${where}: ${what}`);
};
const obj = (v: unknown, where: string): Yaml =>
	typeof v === "object" && v !== null && !Array.isArray(v)
		? (v as Yaml)
		: fail(where, "expected a mapping");
const list = (v: unknown, where: string): unknown[] =>
	Array.isArray(v) ? v : fail(where, "expected a list");
const str = (v: unknown, where: string): string =>
	typeof v === "string" ? v : fail(where, "expected a string");
const num = (v: unknown, where: string): number =>
	typeof v === "number" && Number.isInteger(v)
		? v
		: fail(where, "expected an integer");
const strings = (v: unknown, where: string): string[] =>
	list(v, where).map((s, i) => str(s, `${where}[${i}]`));

/** m2ir confidence labels a field is named from; the others stay raw. */
const NAMED = new Set(["documented", "observed-only"]);
const LABELS = new Set([
	"documented",
	"inferred",
	"observed-only",
	"guessed",
	"superseded",
]);
type Confidence = "documented" | "observed-only";

function confidence(v: unknown, where: string): string {
	const c = str(v, `${where}.confidence`);
	if (!LABELS.has(c)) fail(`${where}.confidence`, `unknown label ${c}`);
	return c;
}

/** The TLV value encodings the dissector reads, by m2ir's name. */
const ENCODINGS = {
	empty: "boolean",
	u8: "number",
	u32le: "number",
	mac48: "string",
	ipv4: "string",
	ipv6: "string",
	text: "string",
	bytes: "string",
	"bitmask-u8": "number",
} as const;
type Encoding = keyof typeof ENCODINGS;
const isEncoding = (e: string): e is Encoding => e in ENCODINGS;

/**
 * What src/dissect/mndp.ts assumes of each encoding m2ir defines: its size,
 * byte order and body. A change to any of them stops the generator, since
 * the reader would go on reading the old way.
 */
const ENCODING_PROPERTIES: Record<
	Encoding | "u32-sender-order",
	Record<string, unknown>
> = {
	empty: { size: 0 },
	u8: { size: 1 },
	"u32-sender-order": { size: 4, endian: "sender" },
	u32le: { size: 4, endian: "le" },
	mac48: { size: 6 },
	ipv4: { size: 4, endian: "be" },
	ipv6: { size: 16, endian: "be" },
	text: { size: null, body: "utf8" },
	bytes: { size: null },
	"bitmask-u8": { size: 1 },
};

const camel = (name: string) =>
	name.replace(/-([a-z0-9])/g, (_, c: string) => c.toUpperCase());

// ── the model the table is written from ─────────────────────────────────────

interface Named {
	value: number;
	name: string;
	confidence: Confidence;
	versionsSeen: string[];
}

interface Tlv {
	type: number;
	name: string;
	field: string;
	encoding: Encoding;
	length: number | "any";
	repeat: boolean;
	neighborField?: string;
	confidence: Confidence;
	versionsSeen: string[];
	receiverVersions: boolean;
	since?: string;
	introduced?: string;
	values?: Named[];
	bits?: Named[];
	notes: string[];
}

export interface Model {
	commit: string;
	port: number;
	header: { confidence: Confidence; versionsSeen: string[]; orders: string };
	request: {
		headers: number[];
		tlvs: { type: number; lengths: number[] }[];
		confidence: Confidence;
		versionsSeen: string[];
	};
	tlvs: Tlv[];
	/** TLVs, values and bits left unnamed for their confidence, for the file's header comment. */
	skipped: string[];
}

/** The m2ir MNDP files, read into what the table needs; throws on anything unexpected. */
export function readMndp(
	physicalYaml: string,
	profileYaml: string,
	commit: string,
): Model {
	const physical = obj(Bun.YAML.parse(physicalYaml), "physical/mndp.yaml");
	const profile = obj(
		Bun.YAML.parse(profileYaml),
		"profiles/mndp/profile.yaml",
	);
	if (physical.id !== "mndp" || profile.id !== "mndp")
		fail("profile", "expected id mndp in both files");

	// The datagram grammar the dissector is written for.
	const where = "physical/mndp.yaml structure.tlv";
	const tlvSeq = list(
		obj(obj(physical.structure, "structure").tlv, where).seq,
		where,
	);
	const shape = tlvSeq.map((s, i) => {
		const e = obj(s, `${where}.seq[${i}]`);
		return `${e.name}:${e.width ?? e.size}`;
	});
	if (shape.join(",") !== "type:u16be,length:u16be,value:length")
		fail(where, `expected u16be type and length, then the value: ${shape}`);
	const dWhere = "physical/mndp.yaml structure.datagram";
	const datagram = list(
		obj(obj(physical.structure, "structure").datagram, dWhere).seq,
		dWhere,
	).map((s, i) => obj(s, `${dWhere}.seq[${i}]`));
	const dShape = datagram.map((e) =>
		[e.name, e.size ?? "", e.kind ?? "", e.repeat ?? ""].join(":"),
	);
	if (dShape.join(",") !== "header:4::,records::tlv:eos")
		fail(dWhere, `expected a 4-byte header, then TLVs to the end: ${dShape}`);
	const port = num(
		obj(physical.transport, "physical transport").port,
		"physical transport.port",
	);
	const sizes = obj(physical["value-encodings"], "value-encodings");
	for (const [e, want] of Object.entries(ENCODING_PROPERTIES)) {
		const got = obj(sizes[e], `value-encodings.${e}`);
		for (const [k, v] of Object.entries(want))
			if (got[k] !== v)
				fail(
					`value-encodings.${e}.${k}`,
					`expected ${JSON.stringify(v)}, the reader assumes it: ${JSON.stringify(got[k])}`,
				);
	}

	const scope = obj(profile.scope, "scope");
	const observed = strings(
		scope["versions-observed"],
		"scope.versions-observed",
	);
	const order = (vs: Iterable<string>) => {
		const set = new Set(vs);
		for (const v of set)
			if (!observed.includes(v))
				fail("versions-seen", `${v} is not in scope.versions-observed`);
		return observed.filter((v) => set.has(v));
	};
	const versions = (v: unknown, where: string) =>
		v === "all" ? [...observed] : order(strings(v, where));
	const skipped: string[] = [];

	// The header: one counter in the sender's byte order, zero a request.
	const hFields = list(obj(profile.header, "header").fields, "header.fields");
	if (hFields.length !== 1) fail("header.fields", "expected one field");
	const h = obj(hFields[0], "header.fields[0]");
	if (h.offset !== 0 || h.encoding !== "u32-sender-order")
		fail("header.fields[0]", "expected a u32-sender-order at offset 0");
	const hConfidence = confidence(h.confidence, "header.fields[0]");
	if (!NAMED.has(hConfidence))
		fail("header.fields[0]", `confidence ${hConfidence}`);
	const orders = list(
		h["byte-order-by-architecture"],
		"header byte-order-by-architecture",
	)
		.map((o, i) => {
			const e = obj(o, `header byte-order-by-architecture[${i}]`);
			const endian = str(e.endian, "endian");
			if (endian !== "le" && endian !== "be")
				fail(
					`header byte-order-by-architecture[${i}].endian`,
					`expected le or be: ${endian}`,
				);
			const end = endian === "le" ? "little" : "big";
			return `${end}-endian on ${strings(e.architectures, "architectures").join(", ")}`;
		})
		.join("; ");

	// The request rule: framing, then any of a header value or a TLV of a length.
	const rule = obj(obj(profile.requests, "requests").rule, "requests.rule");
	if (rule.requires !== "framing-rule")
		fail("requests.rule", "expected requires: framing-rule");
	const request: Model["request"] = {
		headers: [],
		tlvs: [],
		confidence: confidence(
			obj(profile.requests, "requests").confidence,
			"requests",
		) as Confidence,
		versionsSeen: versions(
			obj(profile.requests, "requests")["versions-seen"],
			"requests.versions-seen",
		),
	};
	if (!NAMED.has(request.confidence))
		fail("requests", `confidence ${request.confidence}`);
	for (const [i, c] of list(rule["any-of"], "requests.rule.any-of").entries()) {
		const clause = obj(c, `requests.rule.any-of[${i}]`);
		if ("header" in clause) request.headers.push(num(clause.header, "header"));
		else if ("has-tlv" in clause)
			request.tlvs.push({
				type: num(clause["has-tlv"], "has-tlv"),
				lengths: list(
					clause["tested-value-lengths"],
					"tested-value-lengths",
				).map((n) => num(n, "tested-value-lengths")),
			});
		else fail(`requests.rule.any-of[${i}]`, "unknown clause");
	}

	const tlvs: Tlv[] = [];
	const entries = Object.entries(obj(profile.tlvs, "tlvs"));
	for (const [key, raw] of entries.sort(
		(a, b) => Number(a[0]) - Number(b[0]),
	)) {
		const at = `tlvs.${key}`;
		const t = obj(raw, at);
		const type = Number(key);
		if (!Number.isInteger(type) || type < 0 || type > 0xffff)
			fail(at, "a TLV type is a 16-bit number");
		const name = str(t.name, `${at}.name`);
		const c = confidence(t.confidence, at);
		if (!NAMED.has(c)) {
			skipped.push(`TLV ${type} (${name}): ${c}`);
			continue;
		}
		const encoding = str(t.encoding, `${at}.encoding`);
		if (!isEncoding(encoding))
			fail(`${at}.encoding`, `${encoding} is not one the dissector reads`);
		const e = encoding as Encoding;
		const size = obj(sizes[e], `value-encodings.${e}`).size;
		const length = t.length === "any" ? "any" : num(t.length, `${at}.length`);
		if (size !== null && length !== size)
			fail(at, `length ${length} does not fit ${e} (size ${size})`);
		const repeat = t.repeat === true;
		if (repeat && ENCODINGS[e] !== "string")
			fail(at, "only a string encoding may repeat");
		const tlv: Tlv = {
			type,
			name,
			field: camel(name) + (e === "bytes" ? "Hex" : ""),
			encoding: e,
			length,
			repeat,
			confidence: c as Confidence,
			versionsSeen: versions(t["versions-seen"], `${at}.versions-seen`),
			receiverVersions: t["versions-seen-of"] === "receiver",
			notes: [],
		};
		if (typeof t["neighbor-field"] === "string")
			tlv.neighborField = t["neighbor-field"];
		if (t.since !== undefined) tlv.since = str(t.since, `${at}.since`);
		if (t.introduced !== undefined)
			tlv.introduced = str(t.introduced, `${at}.introduced`);
		const named = (key: "values" | "bits", id: "value" | "mask") =>
			list(t[key], `${at}.${key}`).flatMap((v, i) => {
				const n = obj(v, `${at}.${key}[${i}]`);
				const nc = confidence(n.confidence, `${at}.${key}[${i}]`);
				const value = num(n[id], `${at}.${key}[${i}].${id}`);
				const vname = str(n.name, `${at}.${key}[${i}].name`);
				if (!NAMED.has(nc)) {
					skipped.push(`TLV ${type} ${key} ${value} (${vname}): ${nc}`);
					return [];
				}
				return [
					{
						value,
						name: vname,
						confidence: nc as Confidence,
						versionsSeen: versions(
							n["versions-seen"],
							`${at}.${key}[${i}].versions-seen`,
						),
					},
				];
			});
		if (t.values !== undefined) {
			if (e !== "u8") fail(at, "values on an encoding other than u8");
			tlv.values = named("values", "value");
		}
		if (t.bits !== undefined) {
			if (e !== "bitmask-u8")
				fail(at, "bits on an encoding other than bitmask-u8");
			tlv.bits = named("bits", "mask");
		}
		if (t["encoding-by-architecture"] !== undefined) {
			const parts = list(
				t["encoding-by-architecture"],
				`${at}.encoding-by-architecture`,
			).map((b, i) => {
				const x = obj(b, `${at}.encoding-by-architecture[${i}]`);
				return `${str(x.encoding, "encoding")} from ${strings(x.architectures, "architectures").join(", ")} senders (${confidence(x.confidence, "encoding-by-architecture")}, seen on ${versionText(versions(x["versions-seen"], "versions-seen"))})`;
			});
			tlv.notes.push(
				`m2ir reads it as ${parts.join(", ")}; other senders' byte order is not known, so it is kept as hex.`,
			);
		}
		if (t["meaning-by-version"] !== undefined) {
			const parts = list(
				t["meaning-by-version"],
				`${at}.meaning-by-version`,
			).map((m, i) => {
				const x = obj(m, `${at}.meaning-by-version[${i}]`);
				const from = str(x.from, "from");
				const range =
					x.to === null ? `from ${from}` : `on ${from} to ${str(x.to, "to")}`;
				return `${str(x.follows, "follows")} ${range} (${confidence(x.confidence, "meaning-by-version")})`;
			});
			tlv.notes.push(
				`What it follows depends on the sender's version (m2ir meaning-by-version): ${parts.join("; ")}.`,
			);
		}
		tlvs.push(tlv);
	}
	const fields = new Set<string>();
	for (const t of tlvs) {
		for (const f of [
			t.field,
			...(t.values ? [`${t.field}Name`] : []),
			...(t.bits ? [`${t.field}Flags`] : []),
		]) {
			if (fields.has(f) || HAND_FIELDS.includes(f))
				fail(`tlvs.${t.type}`, `field ${f} is named twice`);
			fields.add(f);
		}
	}
	return {
		commit,
		port,
		header: {
			confidence: hConfidence as Confidence,
			versionsSeen: versions(h["versions-seen"], "header.versions-seen"),
			orders,
		},
		request,
		tlvs,
		skipped,
	};
}

/** Fields mndp.ts writes by hand; a generated name may not take one. */
const HAND_FIELDS = [
	"header",
	"counterLe",
	"counterBe",
	"request",
	"otherTlvs",
];

// ── writing the table ───────────────────────────────────────────────────────

/** Every version, exactly: a range would claim the versions between. */
const versionText = (vs: readonly string[]) => vs.join(", ");

const WHAT: Record<Encoding, (t: Tlv) => string> = {
	empty: () => "true when the TLV is there; it carries no value",
	u8: () => "a number",
	u32le: () => "a number, read little-endian",
	mac48: () => "a MAC address",
	ipv4: () => "an IPv4 address, dotted",
	ipv6: (t) =>
		t.repeat
			? "every IPv6 address, one per TLV, in the order sent"
			: "an IPv6 address",
	text: () =>
		"UTF-8 text; not UTF-8 is malformed (text), read with replacement characters",
	bytes: () => "the value as hex, not interpreted",
	"bitmask-u8": () => "the flag byte, as a number",
};

function describe(t: Tlv): string {
	const neighbor = t.neighborField ? ` (/ip/neighbor ${t.neighborField})` : "";
	const parts = [
		`TLV ${t.type}, ${t.name}${neighbor}: ${WHAT[t.encoding](t)}.`,
	];
	if (t.length !== "any")
		parts.push(
			`A value other than ${t.length} bytes is malformed (tlv-length) and the TLV kept in otherTlvs.`,
		);
	if (!t.repeat) parts.push("A second one is kept in otherTlvs.");
	parts.push(...t.notes);
	if (t.introduced)
		parts.push(`Added in RouterOS ${t.introduced} (changelog).`);
	if (t.receiverVersions)
		parts.push(
			"Its versions are those of routers that answered it, not of senders.",
		);
	return parts.join(" ");
}

const namedText = (n: Named, id: (v: number) => string) =>
	`${n.name} (${id(n.value)}; ${n.confidence}, seen on ${versionText(n.versionsSeen)})`;
const hex2 = (v: number) => `0x${v.toString(16).padStart(2, "0")}`;

/** The weakest confidence of a field's values, and every version any was seen on. */
function sourceOf(ns: readonly Named[], observed: readonly string[]) {
	const seen = new Set(ns.flatMap((n) => n.versionsSeen));
	return {
		confidence: ns.every((n) => n.confidence === "documented")
			? "documented"
			: "observed-only",
		versionsSeen: observed.filter((v) => seen.has(v)),
	};
}

/** The TypeScript of src/dissect/mndp-table.ts, before formatting. */
export function writeTable(m: Model, observed: readonly string[]): string {
	const j = (v: unknown) => JSON.stringify(v);
	const src = (c: string, vs: readonly string[], since?: string) =>
		`confidence: ${j(c)}, versionsSeen: ${j(vs)}${since ? `, since: ${j(since)}` : ""}`;
	const iface: string[] = [];
	const decls: string[] = [];
	for (const t of m.tlvs) {
		const ts = ENCODINGS[t.encoding] + (t.repeat ? "[]" : "");
		const type = t.repeat ? "string[]" : ENCODINGS[t.encoding];
		iface.push(`\t/** TLV ${t.type}, ${t.name}. */\n\t${t.field}?: ${ts};`);
		decls.push(
			`\t${t.field}: { type: ${j(type)}, optional: true, description: ${j(describe(t))}, ${src(t.confidence, t.versionsSeen, t.since)} },`,
		);
		if (t.values) {
			const s = sourceOf(t.values, observed);
			iface.push(
				`\t/** The name of ${t.field}'s value. */\n\t${t.field}Name?: string;`,
			);
			decls.push(
				`\t${t.field}Name: { type: "string", optional: true, description: ${j(`The name of ${t.field}'s value: ${t.values.map((n) => namedText(n, String)).join(", ")}. Absent for another value.`)}, ${src(s.confidence, s.versionsSeen)} },`,
			);
		}
		if (t.bits) {
			const s = sourceOf(t.bits, observed);
			iface.push(
				`\t/** The names of the bits set in ${t.field}. */\n\t${t.field}Flags?: string[];`,
			);
			decls.push(
				`\t${t.field}Flags: { type: "string[]", optional: true, description: ${j(`The names of the bits set in ${t.field}, lowest first: ${t.bits.map((n) => namedText(n, hex2)).join(", ")}; a bit not named here is bit-0x04 and so on.`)}, ${src(s.confidence, s.versionsSeen)} },`,
			);
		}
	}
	const specs = m.tlvs.map((t) => {
		const spec: Record<string, unknown> = {
			type: t.type,
			name: t.name,
			field: t.field,
			encoding: t.encoding,
			length: t.length,
			repeat: t.repeat,
		};
		if (t.values)
			spec.values = t.values.map((n) => ({ value: n.value, name: n.name }));
		if (t.bits)
			spec.bits = t.bits.map((n) => ({ mask: n.value, name: n.name }));
		return `\t${j(spec)},`;
	});
	const skipped = m.skipped.length
		? m.skipped.map((s) => ` * - ${s}`).join("\n")
		: " * - none";
	return `/**
 * Generated by scripts/m2ir.ts from vendor/m2ir (${REPOSITORY} at
 * ${m.commit}): do not edit. Refresh with \`bun run m2ir:refresh\`;
 * \`bun run lint\` checks this file against the snapshot.
 *
 * MNDP's TLVs as m2ir's physical/mndp.yaml and profiles/mndp/profile.yaml
 * give them (CC0-1.0, vendor/m2ir/LICENSE). Left unnamed for their m2ir
 * confidence, so their bytes stay raw:
${skipped}
 */
import type { FieldDecls, FieldSource } from "./core.ts";

/** The m2ir commit this table is generated from. */
export const M2IR_COMMIT = ${j(m.commit)};

/** The UDP port MNDP is sent from and to (m2ir physical/mndp.yaml \`transport\`). */
export const MNDP_PORT = ${m.port};

/** How the dissector reads a TLV's value (m2ir physical/mndp.yaml \`value-encodings\`). */
export type MndpEncoding = ${Object.keys(ENCODINGS).map(j).join(" | ")};

/** One TLV type the table names. */
export interface MndpTlvSpec {
	type: number;
	/** m2ir's name. */
	name: string;
	/** The field it is read into. */
	field: keyof MndpTlvFields;
	encoding: MndpEncoding;
	/** The value length a decoder accepts, in bytes. */
	length: number | "any";
	/** One datagram can carry it more than once. */
	repeat: boolean;
	/** A u8's named values. */
	values?: readonly { value: number; name: string }[];
	/** A bitmask's named bits. */
	bits?: readonly { mask: number; name: string }[];
}

export const MNDP_TLVS: readonly MndpTlvSpec[] = [
${specs.join("\n")}
];

/**
 * m2ir's request rule: a datagram whose TLVs end at its end is a request when
 * its header is one of \`headers\`, or it carries a TLV of one of \`tlvs\`'
 * types with a value of one of its lengths.
 */
export const MNDP_REQUEST = ${j({ headers: m.request.headers, tlvs: m.request.tlvs })};

/** Where the header counter comes from: ${m.header.orders}. */
export const MNDP_HEADER_SOURCE: FieldSource = { ${src(m.header.confidence, m.header.versionsSeen)} };

/** Where the request rule comes from. */
export const MNDP_REQUEST_SOURCE: FieldSource = { ${src(m.request.confidence, m.request.versionsSeen)} };

/** The header counter's byte order by sender architecture, as m2ir gives it. */
export const MNDP_HEADER_ORDERS = ${j(m.header.orders)};

/** The fields MNDP's TLVs are read into, each absent when its TLV is. */
export interface MndpTlvFields {
${iface.join("\n")}
}

export const MNDP_TLV_FIELDS: FieldDecls<MndpTlvFields> = {
${decls.join("\n")}
};
`;
}

/** Biome's formatting of `code`, as \`bun run lint\` would leave it. */
async function format(code: string): Promise<string> {
	const biome = Bun.spawn(
		[
			join(ROOT, "node_modules", ".bin", "biome"),
			"format",
			`--stdin-file-path=${TABLE}`,
		],
		{ cwd: ROOT, stdin: new Blob([code]), stdout: "pipe", stderr: "pipe" },
	);
	const [out, err, status] = await Promise.all([
		new Response(biome.stdout).text(),
		new Response(biome.stderr).text(),
		biome.exited,
	]);
	if (status !== 0) throw new GenerateError(`biome format failed:\n${err}`);
	return out;
}

// ── the snapshot ────────────────────────────────────────────────────────────

const sha256 = (b: Uint8Array | string) =>
	createHash("sha256").update(b).digest("hex");

async function readSource(): Promise<Source> {
	return JSON.parse(
		await readFile(join(VENDOR, "SOURCE.json"), "utf8"),
	) as Source;
}

/** The table the snapshot gives, formatted. */
export async function generate(): Promise<string> {
	const source = await readSource();
	const read = (p: string) => readFile(join(VENDOR, p), "utf8");
	return tableFrom(
		await read("physical/mndp.yaml"),
		await read("profiles/mndp/profile.yaml"),
		source.commit,
	);
}

/** The table m2ir's two files at `commit` give, formatted; throws as readMndp. */
async function tableFrom(
	physicalYaml: string,
	profileYaml: string,
	commit: string,
): Promise<string> {
	const model = readMndp(physicalYaml, profileYaml, commit);
	const observed = strings(
		obj(obj(Bun.YAML.parse(profileYaml), "profile").scope, "scope")[
			"versions-observed"
		],
		"scope.versions-observed",
	);
	return format(writeTable(model, observed));
}

/** What is wrong with the snapshot or the table, if anything. */
export async function check(): Promise<string[]> {
	const problems: string[] = [];
	const source = await readSource();
	if (source.repository !== REPOSITORY)
		problems.push(`SOURCE.json names ${source.repository}, not ${REPOSITORY}`);
	for (const p of FILES) {
		const want = source.files[p];
		let got: string | undefined;
		try {
			got = sha256(await readFile(join(VENDOR, p)));
		} catch {
			problems.push(`vendor/m2ir/${p} is missing`);
			continue;
		}
		if (got !== want)
			problems.push(
				`vendor/m2ir/${p} is not the file SOURCE.json names (edited by hand?); run bun run m2ir:refresh`,
			);
	}
	const extra = Object.keys(source.files).filter(
		(p) => !(FILES as readonly string[]).includes(p),
	);
	if (extra.length) problems.push(`SOURCE.json lists ${extra.join(", ")}`);
	if (problems.length) return problems;
	const table = await readFile(TABLE, "utf8").catch(() => "");
	if (table !== (await generate()))
		problems.push(
			"src/dissect/mndp-table.ts is not what vendor/m2ir generates; run bun run m2ir:generate",
		);
	return problems;
}

/**
 * Vendor m2ir's files at `ref`, a commit on its main branch, and write the
 * table they give. Networked. Every file is fetched and the table made
 * before anything is written, so a failed fetch or a schema the generator
 * refuses leaves the snapshot and the table as they were.
 */
async function refresh(ref: string): Promise<Source> {
	const api = async (path: string) => {
		const r = await fetch(
			`https://api.github.com/repos/${REPOSITORY}/${path}`,
			{
				headers: { accept: "application/vnd.github+json" },
			},
		);
		if (!r.ok) throw new GenerateError(`GitHub ${path}: ${r.status}`);
		return obj(await r.json(), path);
	};
	const commit = await api(`commits/${encodeURIComponent(ref)}`);
	const sha = str(commit.sha, "sha");
	const compare = await api(`compare/${sha}...main`);
	// The commit is main's head or behind it: it is on main.
	if (compare.status !== "identical" && compare.status !== "ahead")
		throw new GenerateError(
			`${sha} is not on ${REPOSITORY} main (${compare.status}); only main is vendored`,
		);
	const bodies = new Map<string, Uint8Array>();
	for (const p of FILES) {
		const r = await fetch(
			`https://raw.githubusercontent.com/${REPOSITORY}/${sha}/${p}`,
		);
		if (!r.ok) throw new GenerateError(`${p} at ${sha}: ${r.status}`);
		bodies.set(p, new Uint8Array(await r.arrayBuffer()));
	}
	const text = (p: string) => new TextDecoder().decode(bodies.get(p));
	const table = await tableFrom(
		text("physical/mndp.yaml"),
		text("profiles/mndp/profile.yaml"),
		sha,
	);
	const files: Record<string, string> = {};
	for (const [p, body] of bodies) {
		await mkdir(dirname(join(VENDOR, p)), { recursive: true });
		await writeFile(join(VENDOR, p), body);
		files[p] = sha256(body);
	}
	const committer = obj(obj(commit.commit, "commit").committer, "committer");
	const source: Source = {
		repository: REPOSITORY,
		commit: sha,
		committed: str(committer.date, "date"),
		files,
	};
	await writeFile(
		join(VENDOR, "SOURCE.json"),
		`${JSON.stringify(source, null, "\t")}\n`,
	);
	await writeFile(TABLE, table);
	return source;
}

if (import.meta.main) {
	const [first, second] = process.argv.slice(2);
	try {
		if (first === "--check") {
			const problems = await check();
			for (const p of problems) console.error(`m2ir: ${p}`);
			process.exit(problems.length ? 1 : 0);
		}
		if (first === "refresh") {
			const source = await refresh(second ?? "main");
			console.error(`m2ir: vendored ${REPOSITORY} at ${source.commit}`);
		} else if (first !== undefined) {
			console.error("usage: bun scripts/m2ir.ts [--check | refresh [ref]]");
			process.exit(2);
		} else await writeFile(TABLE, await generate());
		console.error(`m2ir: wrote ${TABLE.slice(ROOT.length + 1)}`);
	} catch (error) {
		if (!(error instanceof GenerateError)) throw error;
		console.error(`m2ir: ${error.message}`);
		process.exit(1);
	}
}
