/**
 * Text rendering of stream records, for people on a terminal. Plain text
 * only: no color, so nothing changes when stdout is not a terminal.
 */
import type { DissectorInfo, DissectorMatch, FieldInfo } from "../dissect.ts";
import { filterFlags } from "../filter.ts";
import type { RecordLayer } from "../records.ts";
import type { TzspTag } from "../tzsp.ts";
import type {
	AnyHeaderRecord,
	DatagramRecord,
	PacketRecord,
	SummaryRecord,
	TipRecord,
	WarningRecord,
} from "../records.ts";

const seconds = (ms: number) => `${Number((ms / 1000).toFixed(3))}s`;

export function headerText(h: AnyHeaderRecord): string {
	const flags = filterFlags(h.filters);
	const keeping = flags.length ? `, keeping ${flags.join(" ")}` : "";
	if (h.command === "decode") {
		const until =
			h.limits.count !== undefined ? `, until ${h.limits.count} packets` : "";
		return `decoding ${h.input.name} (${h.input.format})${until}${keeping}\n`;
	}
	const where = h.listeners
		.map(
			(l) =>
				`${h.bind}:${l.port}${l.label === String(l.port) ? "" : ` (${l.label})`}`,
		)
		.join(", ");
	const until: string[] = [];
	if (h.limits.count !== undefined) until.push(`${h.limits.count} packets`);
	if (h.limits.durationMs !== undefined)
		until.push(seconds(h.limits.durationMs));
	if (h.limits.idleMs !== undefined)
		until.push(`${seconds(h.limits.idleMs)} idle`);
	const limit = until.length
		? `until ${until.join(" or ")}`
		: "until interrupted";
	const saving = h.write ? `, saving every datagram to ${h.write}` : "";
	return `listening on UDP ${where}, ${limit}${keeping}${saving}\n`;
}

const value = (v: unknown): string => {
	if (Array.isArray(v)) {
		return v.every((x) => typeof x !== "object")
			? v.join(",")
			: JSON.stringify(v);
	}
	return typeof v === "object" && v !== null ? JSON.stringify(v) : String(v);
};

const layerText = (l: RecordLayer) => {
	const fields = l.fields
		? Object.entries(l.fields)
				.map(([k, v]) => `${k}=${value(v)}`)
				.join(" ")
		: "";
	const problem =
		"problem" in l && l.problem ? ` [${l.problem} ${l.reason}]` : "";
	return `  ${l.protocol} @${l.offset}+${l.length}${fields ? ` ${fields}` : ""}${problem}\n`;
};

/** The `summary` detail fields, in this order, when the record has them. */
const SUMMARY_KEYS = [
	"peer",
	"interface",
	"length",
	"kind",
	"tzspType",
	"protocols",
	"src",
	"srcPort",
	"dst",
	"dstPort",
	"vlan",
	"flags",
	"problem",
	"reason",
] as const;

const summaryFields = (r: PacketRecord | DatagramRecord) => {
	const fields = r as Partial<Record<(typeof SUMMARY_KEYS)[number], unknown>>;
	const parts = SUMMARY_KEYS.flatMap((key) => {
		const v = fields[key];
		if (v === undefined) return [];
		return [`${key}=${Array.isArray(v) ? v.join(",") : String(v)}`];
	});
	return parts.length ? `  ${parts.join(" ")}\n` : "";
};

/**
 * A packet or record: its time, its source when asked (the listener, or a
 * capture file's interface) and it has one, the line, then detail.
 */
export function entryText(
	r: PacketRecord | DatagramRecord,
	showSource: boolean,
): string {
	// A file's interface name can hold a space (`ether1 rx`): bracketed.
	const source = !showSource
		? undefined
		: (r.listener ??
			(r.interface === undefined ? undefined : `[${r.interface}]`));
	// From the T: a year past 9999 is written +275760-..., not at a fixed place.
	const clock = r.time?.slice(
		r.time.indexOf("T") + 1,
		r.time.indexOf("T") + 13,
	);
	const head = [clock, source, r.line].filter((part) => part !== undefined);
	let text = `${head.join(" ")}\n`;
	text += summaryFields(r);
	if (r.type === "packet" && r.layers) text += r.layers.map(layerText).join("");
	if (r.comment !== undefined)
		text += `  comment ${JSON.stringify(r.comment)}\n`;
	if (r.type === "record" && r.tags) {
		text += `  tags ${r.tags.map((t) => `${t.name}=${t.hex}`).join(" ")}\n`;
	}
	if (r.datagram) text += `  datagram ${r.datagram}\n`;
	return text;
}

/** Fields shown on lines of their own, after the `key=value` line. */
const BLOCK_FIELDS = new Set(["layers", "tags", "datagram"]);

/**
 * A record shaped by `--fields`, in the order named: its type, then each
 * run of fields as `key=value` on one line (the first on the type's line,
 * a later one indented), and layers, tags and the datagram on lines of
 * their own where they were named.
 */
export function fieldsText(r: Record<string, unknown>): string {
	let text = "";
	let run: string[] = [String(r.type)];
	let first = true;
	const flush = () => {
		if (run.length) text += `${first ? "" : "  "}${run.join(" ")}\n`;
		run = [];
		first = false;
	};
	for (const [k, v] of Object.entries(r)) {
		if (k === "type") continue;
		if (!BLOCK_FIELDS.has(k)) {
			run.push(`${k}=${value(v)}`);
			continue;
		}
		flush();
		if (k === "layers" && Array.isArray(v))
			text += (v as RecordLayer[]).map(layerText).join("");
		else if (k === "tags" && Array.isArray(v))
			text += `  tags ${(v as TzspTag[]).map((t) => `${t.name}=${t.hex}`).join(" ")}\n`;
		else if (k === "datagram") text += `  datagram ${String(v)}\n`;
	}
	flush();
	return text;
}

export function noticeText(r: WarningRecord | TipRecord): string {
	if (r.type === "tip") return `tip ${r.code}: ${r.message}\n`;
	return `warning ${r.code}: ${r.message}\n${r.fix ? `  fix: ${r.fix}\n` : ""}`;
}

export function errorText(e: {
	code: string;
	message: string;
	fix?: string | undefined;
}): string {
	return `error ${e.code}: ${e.message}\n${e.fix ? `  fix: ${e.fix}\n` : ""}`;
}

export function summaryText(
	s: SummaryRecord,
	command: "listen" | "decode" = "listen",
): string {
	const c = s.counters;
	const lines =
		command === "decode"
			? [
					`summary: ${s.status}, ${s.stoppedBy === "end" ? "read to the end" : `stopped by ${s.stoppedBy}`}; the packets span ${seconds(s.durationMs)}`,
					`  read ${c.datagrams}: packets ${c.packets}, filtered ${c.filtered}, control ${c.control}, unsupported ${c.unsupported}, invalid ${c.invalid}`,
				]
			: [
					`summary: ${s.status}, stopped by ${s.stoppedBy} after ${seconds(s.durationMs)}`,
					`  datagrams ${c.datagrams}: packets ${c.packets}, filtered ${c.filtered}, control ${c.control}, unsupported ${c.unsupported}, invalid ${c.invalid}, dropped ${c.dropped}, unread ${c.unread}${c.unsaved ? `, unsaved ${c.unsaved}` : ""}`,
				];
	if (s.written) {
		lines.push(
			`  written: ${s.written.datagrams} datagrams, ${s.written.bytes} bytes`,
		);
	}
	const counts = (o: Record<string, number>) =>
		Object.entries(o)
			.map(([k, n]) => `${k} ${n}`)
			.join(", ");
	if (Object.keys(s.protocols).length)
		lines.push(`  protocols: ${counts(s.protocols)}`);
	if (Object.keys(s.problems).length)
		lines.push(`  problems: ${counts(s.problems)}`);
	const other = (
		r: {
			otherEntries: number;
			otherEntriesCapped: boolean;
			otherCount: number;
		},
		unit: string,
	) =>
		r.otherEntries
			? [
					`    and ${r.otherEntries}${r.otherEntriesCapped ? " or more" : ""} more: ${r.otherCount} ${unit}`,
				]
			: [];
	if (s.conversations.top.length) {
		lines.push("  conversations:");
		for (const v of s.conversations.top) {
			lines.push(
				`    ${v.protocol} ${v.a} <> ${v.b}: ${v.packets} packets, ${v.bytes} bytes`,
			);
		}
		lines.push(...other(s.conversations, "packets"));
	}
	if (s.senders.top.length) {
		lines.push("  senders:");
		for (const v of s.senders.top) {
			const who =
				v.listener !== undefined && v.peer !== undefined
					? `${v.listener} from ${v.peer}`
					: (v.listener ?? `from ${v.peer}`);
			lines.push(`    ${who}: ${v.datagrams} datagrams`);
		}
		lines.push(...other(s.senders, "datagrams"));
	}
	return `${lines.join("\n")}\n`;
}

const matchText = (m: DissectorMatch) => `${m.by} ${m.value}`;

/**
 * Where a generated field comes from, in brackets after its description:
 * its confidence, the versions it was seen on (a range past three) and
 * `since`. Nothing for a field read from a standard.
 */
function sourceText(f: FieldInfo): string {
	const parts: string[] = [];
	if (f.confidence) parts.push(f.confidence);
	const vs = f.versionsSeen;
	if (vs?.length)
		parts.push(
			vs.length <= 3
				? `seen on ${vs.join(", ")}`
				: `seen on ${vs.length} versions, ${vs[0]} to ${vs[vs.length - 1]}`,
		);
	if (f.since) parts.push(`since ${f.since}`);
	return parts.length ? ` [${parts.join("; ")}]` : "";
}

/** One field line, and an `object[]` field's own fields under it as `name[].item`. */
function fieldLines(fields: readonly FieldInfo[], prefix = ""): string[] {
	return fields.flatMap((f) => [
		`  ${prefix}${f.name} (${f.type}${f.optional ? ", optional" : ""}): ${f.description}${sourceText(f)}`,
		...(f.items ? fieldLines(f.items, `${prefix}${f.name}[].`) : []),
	]);
}

/**
 * One dissector, for `tzsp-sniff dissectors`: its protocol, name and
 * reference, how it is matched, then a line per field.
 */
export function dissectorText(d: DissectorInfo): string {
	return `${[
		`${d.protocol}: ${d.name} (${d.reference})`,
		`  matched by ${d.matches.map(matchText).join(", ")}`,
		...fieldLines(d.fields),
	].join("\n")}\n`;
}
