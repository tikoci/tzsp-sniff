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
 * its `confidence`, and m2irFacts() the versions it was seen on, `since` and
 * the rest (DESIGN.md, "Confidence goes in `dissectors`; version scope in
 * `m2irFacts()`"). A TLV, value or bit m2ir marks `inferred`, `guessed` or
 * `superseded` gets no name: its bytes stay raw (maintainer, 2026-11-21, on
 * #31). Anything in the YAML the generator does not know (an encoding, a
 * header shape, a request clause) stops it, rather than being left out.
 */
import { createHash } from "node:crypto";
import { mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const ROOT = join(import.meta.dir, "..");
export const VENDOR = join(ROOT, "vendor", "m2ir");
export const TABLE = join(ROOT, "src", "dissect", "mndp-table.ts");
const REPOSITORY = "tikoci/m2ir";
/** The m2ir files the table is generated from, and the license they are under. */
export const FILES = [
	"LICENSE",
	"physical/mndp.yaml",
	"profiles/mndp/profile.yaml",
] as const;
/**
 * sha256 of m2ir's LICENSE, the CC0-1.0 text the table's banner names. A
 * refresh that brings another license stops: read it, then change this and
 * the banner together.
 */
export const LICENSE_SHA256 =
	"a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499";

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
const u16 = (v: unknown, where: string): number => {
	const n = num(v, where);
	return n >= 0 && n <= 0xffff ? n : fail(where, `${n} is not a 16-bit number`);
};

/**
 * `seq` is exactly `want`, entry by entry: the same keys with the same
 * values, compared strictly, and no others but the annotations in `notes`.
 */
function exactly(
	seq: unknown[],
	want: Record<string, string | number>[],
	notes: string[],
	where: string,
): boolean {
	return (
		seq.length === want.length &&
		want.every((w, i) => {
			const e = obj(seq[i], `${where}[${i}]`);
			const keys = Object.keys(e).filter((k) => !notes.includes(k));
			return (
				keys.length === Object.keys(w).length &&
				keys.every((k) => Object.hasOwn(w, k) && e[k] === w[k])
			);
		})
	);
}

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
/** The encodings mndp.ts collects into a list when a TLV repeats (its `put`). */
const REPEATS = new Set<Encoding>(["ipv6", "text", "bytes"]);

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
/** A name a field is made from: it becomes a TypeScript identifier. */
const NAME = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
/** Text from m2ir kept inside a generated block comment. */
const commentText = (s: string) => s.replaceAll("*/", "*\\/");

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
	header: {
		/** m2ir's name for the counter. */
		name: string;
		confidence: Confidence;
		versionsSeen: string[];
		orders: string;
	};
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
	// It goes into the generated file's banner.
	if (!/^[0-9a-f]{40}$/.test(commit))
		fail("commit", `expected a 40-digit commit sha: ${commit}`);

	// The datagram grammar the dissector is written for.
	const where = "physical/mndp.yaml structure.tlv";
	const tlvSeq = list(
		obj(obj(physical.structure, "structure").tlv, where).seq,
		where,
	);
	const tlvRecord = [
		{ name: "type", width: "u16be" },
		{ name: "length", width: "u16be" },
		{ name: "value", size: "length" },
	];
	if (!exactly(tlvSeq, tlvRecord, ["role"], `${where}.seq`))
		fail(
			where,
			`expected u16be type and length, then the value: ${JSON.stringify(tlvSeq)}`,
		);
	const dWhere = "physical/mndp.yaml structure.datagram";
	const datagram = list(
		obj(obj(physical.structure, "structure").datagram, dWhere).seq,
		dWhere,
	);
	const datagramShape = [
		{ name: "header", size: 4 },
		{ name: "records", kind: "tlv", repeat: "eos" },
	];
	if (
		!exactly(
			datagram,
			datagramShape,
			["role", "profile-naming"],
			`${dWhere}.seq`,
		)
	)
		fail(
			dWhere,
			`expected a 4-byte header, then TLVs to the end: ${JSON.stringify(datagram)}`,
		);
	const transport = obj(physical.transport, "physical transport");
	// The table's port is registered as a UDP port (mndp.ts).
	if (transport.protocol !== "udp")
		fail(
			"physical transport.protocol",
			`expected udp, the dissector is registered on: ${transport.protocol}`,
		);
	const port = num(transport.port, "physical transport.port");
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
	const hName = str(h.name, "header.fields[0].name");
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
		const at = `requests.rule.any-of[${i}]`;
		const clause = obj(c, at);
		/** A clause has only the keys the reader matches on; `untested` is a note. */
		const only = (...keys: string[]) => {
			const extra = Object.keys(clause).filter((k) => !keys.includes(k));
			if (extra.length) fail(at, `unknown key ${extra.join(", ")}`);
		};
		if ("header" in clause) {
			only("header");
			// mndp.ts compares the header read big-endian, and the counter is in
			// the sender's byte order: only zero reads the same either way.
			const header = num(clause.header, `${at}.header`);
			if (header !== 0)
				fail(at, `a header of ${header} depends on the sender's byte order`);
			request.headers.push(header);
		} else if ("has-tlv" in clause) {
			only("has-tlv", "tested-value-lengths", "untested");
			request.tlvs.push({
				type: u16(clause["has-tlv"], `${at}.has-tlv`),
				lengths: list(
					clause["tested-value-lengths"],
					`${at}.tested-value-lengths`,
				).map((n, j) => u16(n, `${at}.tested-value-lengths[${j}]`)),
			});
		} else fail(at, "unknown clause");
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
		if (!NAME.test(name)) fail(`${at}.name`, `not a lower-case name: ${name}`);
		const encoding = str(t.encoding, `${at}.encoding`);
		if (!isEncoding(encoding))
			fail(`${at}.encoding`, `${encoding} is not one the dissector reads`);
		const e = encoding as Encoding;
		const size = obj(sizes[e], `value-encodings.${e}`).size;
		const length = t.length === "any" ? "any" : num(t.length, `${at}.length`);
		if (size !== null && length !== size)
			fail(at, `length ${length} does not fit ${e} (size ${size})`);
		const repeat = t.repeat === true;
		if (repeat && !REPEATS.has(e))
			fail(at, `only ${[...REPEATS].join(", ")} may repeat, not ${e}`);
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
				// A value is a byte; a mask is one bit of it, as mndp.ts reads them.
				if (
					id === "value"
						? value < 0 || value > 0xff
						: value < 1 || value > 0x80 || (value & (value - 1)) !== 0
				)
					fail(
						`${at}.${key}[${i}].${id}`,
						`${value} is not ${id === "value" ? "a byte" : "one bit of a byte"}`,
					);
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
			// None left: no name field, as for a value m2ir does not name.
			const values = named("values", "value");
			if (values.length) tlv.values = values;
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
				return `${str(x.encoding, "encoding")} from ${strings(x.architectures, "architectures").join(", ")} senders (${confidence(x.confidence, "encoding-by-architecture")})`;
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
			...(t.encoding === "bitmask-u8" ? [`${t.field}Flags`] : []),
		]) {
			if (fields.has(f) || HAND_FIELDS.includes(f))
				fail(`tlvs.${t.type}`, `field ${f} is named twice`);
			// The reader builds the fields on a plain object: `constructor` and
			// the like are already there.
			if (f in Object.prototype)
				fail(`tlvs.${t.type}`, `field ${f} is a name every object has`);
			fields.add(f);
		}
	}
	return {
		commit,
		port,
		header: {
			name: hName,
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
	return parts.join(" ");
}

const namedText = (n: Named, id: (v: number) => string) =>
	`${n.name} (${id(n.value)}; ${n.confidence})`;
const hex2 = (v: number) => `0x${v.toString(16).padStart(2, "0")}`;

/** The weakest confidence of a field's values. */
const weakest = (ns: readonly Named[]) =>
	ns.every((n) => n.confidence === "documented")
		? "documented"
		: "observed-only";

/** The TypeScript of src/dissect/mndp-table.ts, before formatting. */
export function writeTable(m: Model, observed: readonly string[]): string {
	const j = (v: unknown) => JSON.stringify(v);
	const iface: string[] = [];
	const decls: string[] = [];
	/** m2ir's facts for each field: what m2irFacts() returns. */
	const facts: Record<string, unknown>[] = [
		{
			field: "header",
			name: m.header.name,
			confidence: m.header.confidence,
			versionsSeen: m.header.versionsSeen,
			versionsSeenOf: "sender",
		},
		{
			field: "request",
			name: "requests",
			confidence: m.request.confidence,
			versionsSeen: m.request.versionsSeen,
			versionsSeenOf: "receiver",
		},
	];
	const namedFacts = (ns: readonly Named[]) =>
		ns.map((n) => ({
			value: n.value,
			name: n.name,
			confidence: n.confidence,
			versionsSeen: n.versionsSeen,
		}));
	for (const t of m.tlvs) {
		const ts = ENCODINGS[t.encoding] + (t.repeat ? "[]" : "");
		const type = t.repeat ? "string[]" : ENCODINGS[t.encoding];
		iface.push(
			`\t/** TLV ${t.type}, ${commentText(t.name)}. */\n\t${t.field}?: ${ts};`,
		);
		decls.push(
			`\t${t.field}: { type: ${j(type)}, optional: true, description: ${j(describe(t))}, confidence: ${j(t.confidence)} },`,
		);
		facts.push({
			field: t.field,
			tlv: t.type,
			name: t.name,
			confidence: t.confidence,
			versionsSeen: t.versionsSeen,
			versionsSeenOf: t.receiverVersions ? "receiver" : "sender",
			...(t.since ? { since: t.since } : {}),
			...(t.introduced ? { introduced: t.introduced } : {}),
			...(t.values?.length ? { values: namedFacts(t.values) } : {}),
			...(t.bits?.length ? { bits: namedFacts(t.bits) } : {}),
		});
		if (t.values?.length) {
			iface.push(
				`\t/** The name of ${t.field}'s value. */\n\t${t.field}Name?: string;`,
			);
			decls.push(
				`\t${t.field}Name: { type: "string", optional: true, description: ${j(`The name of ${t.field}'s value: ${t.values.map((n) => namedText(n, String)).join(", ")}. Absent for another value.`)}, confidence: ${j(weakest(t.values))} },`,
			);
		}
		// The reader lists the bits set whether or not m2ir names any.
		if (t.encoding === "bitmask-u8") {
			const bits = t.bits ?? [];
			const named = bits.length
				? `: ${bits.map((n) => namedText(n, hex2)).join(", ")}; a bit not named here is bit-0x04 and so on.`
				: ", each as bit-0x01 and so on: m2ir names none.";
			iface.push(
				`\t/** The names of the bits set in ${t.field}. */\n\t${t.field}Flags?: string[];`,
			);
			decls.push(
				`\t${t.field}Flags: { type: "string[]", optional: true, description: ${j(`The names of the bits set in ${t.field}, lowest first${named}`)}${bits.length ? `, confidence: ${j(weakest(bits))}` : ""} },`,
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
		? m.skipped.map((s) => ` * - ${commentText(s)}`).join("\n")
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
import type { FieldConfidence, FieldDecls } from "./core.ts";
import type { M2irFieldFacts } from "./m2ir.ts";

/** The m2ir repository and commit this table is generated from, and the files read. */
export const M2IR_REPOSITORY = ${j(REPOSITORY)};
export const M2IR_COMMIT = ${j(m.commit)};
export const MNDP_M2IR_FILES: readonly string[] = ${j(FILES.filter((f) => f !== "LICENSE"))};

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

/** How sure m2ir is of the header counter: ${commentText(m.header.orders)}. */
export const MNDP_HEADER_CONFIDENCE: FieldConfidence = ${j(m.header.confidence)};

/** How sure m2ir is of the request rule. */
export const MNDP_REQUEST_CONFIDENCE: FieldConfidence = ${j(m.request.confidence)};

/** The RouterOS versions m2ir observed MNDP on (its \`scope.versions-observed\`). */
export const MNDP_VERSIONS_OBSERVED: readonly string[] = ${j(observed)};

/** Entries m2ir has that the table leaves unnamed for their confidence. */
export const MNDP_UNNAMED: readonly string[] = ${j(m.skipped)};

/** m2ir's scope for each field: what m2irFacts() returns for MNDP. */
export const MNDP_M2IR_FACTS: readonly M2irFieldFacts[] = ${j(facts)};

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
		else if (p === "LICENSE" && got !== LICENSE_SHA256)
			problems.push(
				"vendor/m2ir/LICENSE is not the license the table's banner names (scripts/m2ir.ts LICENSE_SHA256)",
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

/** The suffix a refresh writes each output under before it takes its file's place. */
export const STAGED = ".m2ir-refresh";

/**
 * Vendor m2ir's files at `ref`, a commit on its main branch, and write the
 * table they give. Networked. Every file is fetched, the license checked and
 * the table made before anything is written, so a failed fetch, a schema the
 * generator refuses or another license leaves the snapshot and the table as
 * they were. A failed write does too: see `STAGED`.
 */
export async function refresh(
	ref: string,
	/** Where to write: the repo's snapshot and table, or a test's copies. */
	to: { vendor: string; table: string } = { vendor: VENDOR, table: TABLE },
	get: typeof fetch = fetch,
): Promise<Source> {
	const api = async (path: string) => {
		const r = await get(`https://api.github.com/repos/${REPOSITORY}/${path}`, {
			headers: { accept: "application/vnd.github+json" },
		});
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
		const r = await get(
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
	for (const [p, body] of bodies) files[p] = sha256(body);
	if (files.LICENSE !== LICENSE_SHA256)
		throw new GenerateError(
			`m2ir's LICENSE at ${sha} is not the CC0-1.0 text the table's banner names: read it, then change LICENSE_SHA256 and the banner together`,
		);
	const committer = obj(obj(commit.commit, "commit").committer, "committer");
	const source: Source = {
		repository: REPOSITORY,
		commit: sha,
		committed: str(committer.date, "date"),
		files,
	};
	const outputs: [string, Uint8Array | string][] = [
		...[...bodies].map(([p, body]): [string, Uint8Array] => [
			join(to.vendor, p),
			body,
		]),
		[join(to.vendor, "SOURCE.json"), `${JSON.stringify(source, null, "\t")}\n`],
		[to.table, table],
	];
	// Staged first, each created only if absent: a write that fails leaves
	// every old file, and a second refresh stops on the first file this one
	// holds. Then each takes its file's place.
	/** Staged files this refresh created and has not yet renamed. */
	const staged = new Set<string>();
	const unstage = () =>
		Promise.all([...staged].map((p) => rm(p, { force: true })));
	try {
		for (const [path, body] of outputs) {
			await mkdir(dirname(path), { recursive: true });
			let file: Awaited<ReturnType<typeof open>>;
			try {
				file = await open(path + STAGED, "wx");
			} catch (e) {
				if ((e as NodeJS.ErrnoException).code === "EEXIST")
					throw new GenerateError(
						`${path + STAGED} exists: another refresh is writing, or one stopped (remove it)`,
					);
				throw e;
			}
			// Ours from its creation, so a write that fails part way removes it.
			staged.add(path + STAGED);
			try {
				await file.writeFile(body);
			} finally {
				await file.close();
			}
		}
	} catch (e) {
		await unstage();
		throw e;
	}
	try {
		for (const [path] of outputs) {
			await rename(path + STAGED, path);
			staged.delete(path + STAGED);
		}
	} catch (e) {
		// What is renamed stays: `bun run lint` reports the mix, git restores it.
		await unstage();
		throw e;
	}
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
