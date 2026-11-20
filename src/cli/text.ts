/**
 * Text rendering of stream records, for people on a terminal. Plain text
 * only: no color, so nothing changes when stdout is not a terminal.
 */
import { filterFlags } from "../filter.ts";
import type { RecordLayer } from "../records.ts";
import type { TzspTag } from "../tzsp.ts";
import type {
	DatagramRecord,
	HeaderRecord,
	PacketRecord,
	SummaryRecord,
	TipRecord,
	WarningRecord,
} from "../records.ts";

const seconds = (ms: number) => `${Number((ms / 1000).toFixed(3))}s`;

export function headerText(h: HeaderRecord): string {
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
	const flags = filterFlags(h.filters);
	const keeping = flags.length ? `, keeping ${flags.join(" ")}` : "";
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

/** A packet or record: time, the listener when there are several, the line, then detail. */
export function entryText(
	r: PacketRecord | DatagramRecord,
	showListener: boolean,
): string {
	let text = `${r.time.slice(11, 23)}${showListener ? ` ${r.listener}` : ""} ${r.line}\n`;
	text += summaryFields(r);
	if (r.type === "packet" && r.layers) text += r.layers.map(layerText).join("");
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

export function summaryText(s: SummaryRecord): string {
	const c = s.counters;
	const lines = [
		`summary: ${s.status}, stopped by ${s.stoppedBy} after ${seconds(s.durationMs)}`,
		`  datagrams ${c.datagrams}: packets ${c.packets}, filtered ${c.filtered}, control ${c.control}, unsupported ${c.unsupported}, invalid ${c.invalid}, dropped ${c.dropped}, unread ${c.unread}`,
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
			lines.push(`    ${v.listener} from ${v.peer}: ${v.datagrams} datagrams`);
		}
		lines.push(...other(s.senders, "datagrams"));
	}
	return `${lines.join("\n")}\n`;
}
