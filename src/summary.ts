/**
 * Bounded summary tables (DESIGN.md, "Limits"): protocol and problem counts,
 * and top-N sender and conversation tables with an "other" bucket, so a long
 * capture holds constant memory. Each table keeps at most `track` keys; a
 * key first seen after that is folded straight into the bucket.
 */
import type { Dissection } from "./dissect.ts";
import type { Capture } from "./listen.ts";
import {
	formatPeer,
	type PacketView,
	type Ranked,
	type SummaryTables,
	viewPacket,
} from "./records.ts";

export interface SummaryOptions {
	/** Entries listed per ranked table (default 10). */
	top?: number;
	/** Keys tracked per table before new ones fold into "other" (default 1000). */
	track?: number;
}

class Table<T extends object> {
	readonly entries = new Map<string, T>();
	foldedEntries = new Set<string>();
	foldedCount = 0;
	/** A folded key arrived after `foldedEntries` was full: distinct counts are a lower bound. */
	foldedCapped = false;

	private readonly track: number;
	private readonly weight: (entry: T) => number;

	constructor(track: number, weight: (entry: T) => number) {
		this.track = track;
		this.weight = weight;
	}

	/** The entry for `key`, or undefined when the table is full and folds it. */
	get(key: string, create: () => T, amount: number): T | undefined {
		const found = this.entries.get(key);
		if (found) return found;
		if (this.entries.size < this.track) {
			const entry = create();
			this.entries.set(key, entry);
			return entry;
		}
		// Count distinct folded keys up to the same cap; past it, note only that there were more.
		if (this.foldedEntries.size < this.track) this.foldedEntries.add(key);
		else if (!this.foldedEntries.has(key)) this.foldedCapped = true;
		this.foldedCount += amount;
		return undefined;
	}

	ranked(top: number): Ranked<T> {
		const all = [...this.entries.values()].sort(
			(a, b) => this.weight(b) - this.weight(a),
		);
		const rest = all.slice(top);
		return {
			top: all.slice(0, top),
			otherEntries: rest.length + this.foldedEntries.size,
			otherEntriesCapped: this.foldedCapped,
			otherCount:
				rest.reduce((sum, e) => sum + this.weight(e), 0) + this.foldedCount,
		};
	}
}

type Sender = { listener: string; peer: string; datagrams: number };
type Conversation = {
	protocol: string;
	a: string;
	b: string;
	packets: number;
	bytes: number;
};

export interface StatsAccumulator {
	/** Count a datagram toward its sender, whatever its kind. */
	addDatagram(capture: Capture): void;
	/** Count a reported frame toward protocols, problems and conversations. */
	addPacket(dissection: Dissection, view?: PacketView): void;
	tables(): SummaryTables;
}

const endpoint = (host: string | undefined, port: number | undefined) =>
	host === undefined ? "?" : port === undefined ? host : formatPeer(host, port);

/** A summary accumulator for one capture. */
export function summarize(options: SummaryOptions = {}): StatsAccumulator {
	const top = options.top ?? 10;
	const track = options.track ?? 1000;
	const protocols: Record<string, number> = {};
	const problems: Record<string, number> = {};
	const senders = new Table<Sender>(track, (e) => e.datagrams);
	const conversations = new Table<Conversation>(track, (e) => e.packets);

	return {
		addDatagram(capture) {
			const listener = capture.listener.label;
			const peer = formatPeer(capture.peer.address, capture.peer.port);
			const entry = senders.get(
				`${listener} ${peer}`,
				() => ({ listener, peer, datagrams: 0 }),
				1,
			);
			if (entry) entry.datagrams += 1;
		},
		addPacket(d, view = viewPacket(d)) {
			// Protocols are a small fixed set, so this table needs no cap.
			for (const p of new Set(d.protocols))
				protocols[p] = (protocols[p] ?? 0) + 1;
			if (d.problem) {
				const key = `${d.problem.protocol}/${d.problem.reason}`;
				problems[key] = (problems[key] ?? 0) + 1;
			}
			// One conversation for both directions: endpoints in a fixed order.
			const one = endpoint(view.src, view.srcPort);
			const two = endpoint(view.dst, view.dstPort);
			const [a, b] = one <= two ? [one, two] : [two, one];
			const entry = conversations.get(
				`${view.protocol} ${a} ${b}`,
				() => ({ protocol: view.protocol, a, b, packets: 0, bytes: 0 }),
				1,
			);
			if (entry) {
				entry.packets += 1;
				entry.bytes += d.frame.length;
			}
		},
		tables() {
			return {
				protocols: { ...protocols },
				problems: { ...problems },
				senders: senders.ranked(top),
				conversations: conversations.ranked(top),
			};
		},
	};
}
