/**
 * The pcapng writer behind `--write` and `--format pcapng` (DESIGN.md,
 * "`--write`: capture now, look later"). Each packet block holds the TZSP
 * datagram byte for byte under `LINKTYPE_TZSP` (128): tags, control records
 * and malformed datagrams included, so a file can be decoded again after a
 * dissector improves. One interface block per listener carries its label
 * and port, a block's timestamp is the arrival time, and the UDP peer is
 * the block's comment (`peer=<address>:<port>`).
 *
 * Block layout from the pcapng specification
 * (https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html):
 * section header, interface description and enhanced packet blocks, written
 * little-endian. The writer streams: one sink write per block, each awaited,
 * so a slow sink slows the capture loop and the capture's bounded queue
 * absorbs the burst (drops are counted), and a sink that takes nothing for
 * `stallMs` ends the capture with `write/stalled`.
 */
import { TzspSniffError } from "./errors.ts";
import type { BoundListener, Capture } from "./listen.ts";
import { VERSION } from "./version.ts";

/** The longest delay timers take on Node and Bun (2^31 - 1 ms); as `MAX_TIMER_MS` in capture.ts. */
const MAX_TIMER_MS = 2_147_483_647;

/** tcpdump's `LINKTYPE_TZSP` (https://www.tcpdump.org/linktypes.html). */
export const LINKTYPE_TZSP = 128;

/** Block and option codes from the pcapng specification. */
const SHB = 0x0a0d0d0a;
const IDB = 0x00000001;
const EPB = 0x00000006;
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;
const OPT_END = 0;
const OPT_COMMENT = 1;
const SHB_USERAPPL = 4;
const IF_NAME = 2;
const IF_DESCRIPTION = 3;
const IF_TSRESOL = 9;

/** Where a writer's bytes go. */
export interface ByteSink {
	/** Called once, before the first write: create the file, for example. */
	open?(): Promise<void>;
	/**
	 * Take one block. Resolves once the bytes are handed on; rejects when
	 * they cannot be. A rejection with a {@link TzspSniffError} ends the
	 * capture with that error in its summary; any other error is thrown from
	 * the capture's iteration, as a consumer's own error would be.
	 */
	write(chunk: Uint8Array): Promise<void>;
	/** Called once, last, also after a failure: flush and release. */
	close?(): Promise<void>;
}

/** What a writer has taken: blocks for datagrams, and their bytes on the sink. */
export interface WrittenCounts {
	/** Datagrams written, each as one packet block. */
	datagrams: number;
	/** Bytes the sink took, headers included. */
	bytes: number;
}

/**
 * Saves datagrams as a capture reads them. `openCapture()` calls `open`
 * once the listeners are bound, `write` for each datagram it saves, and
 * `close` once when the capture ends, however it ends.
 */
export interface CaptureWriter {
	/** Where it writes, for the capture's header: a file path, or `stdout`. */
	readonly target: string;
	readonly written: Readonly<WrittenCounts>;
	open(listeners: readonly BoundListener[]): Promise<void>;
	write(capture: Capture): Promise<void>;
	close(): Promise<void>;
}

export interface PcapngWriterOptions {
	/** For the capture's header; default `pcapng`. */
	target?: string;
	/**
	 * How long one sink call may take before the capture ends with
	 * `write/stalled`; default 30 s. 0 turns the timer off, for a sink that
	 * times itself out.
	 */
	stallMs?: number;
}

export const DEFAULT_WRITE_STALL_MS = 30_000;

const encoder = new TextEncoder();
const pad4 = (n: number) => (n + 3) & ~3;

/** An option: code, length, value, padded to 32 bits. */
function option(code: number, value: Uint8Array): Uint8Array {
	if (value.length > 0xffff) {
		throw new TzspSniffError(
			"write/invalid-option",
			`A pcapng option holds at most 65535 bytes; this one has ${value.length}.`,
			"Use a shorter listener label.",
		);
	}
	const out = new Uint8Array(4 + pad4(value.length));
	const view = new DataView(out.buffer);
	view.setUint16(0, code, true);
	view.setUint16(2, value.length, true);
	out.set(value, 4);
	return out;
}

/** Options, ended by `opt_endofopt`, or nothing when there are none. */
function options(list: Uint8Array[]): Uint8Array {
	if (!list.length) return new Uint8Array(0);
	return concat([...list, option(OPT_END, new Uint8Array(0))]);
}

function concat(parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}

/** A block: type, total length, body (already padded), total length again. */
function block(type: number, body: Uint8Array): Uint8Array {
	const length = 12 + body.length;
	const out = new Uint8Array(length);
	const view = new DataView(out.buffer);
	view.setUint32(0, type, true);
	view.setUint32(4, length, true);
	out.set(body, 8);
	view.setUint32(length - 4, length, true);
	return out;
}

/** The section header: byte-order magic, version 1.0, length unknown (-1). */
export function sectionHeaderBlock(application: string): Uint8Array {
	const fixed = new Uint8Array(16);
	const view = new DataView(fixed.buffer);
	view.setUint32(0, BYTE_ORDER_MAGIC, true);
	view.setUint16(4, 1, true);
	view.setUint16(6, 0, true);
	view.setBigInt64(8, -1n, true);
	return block(
		SHB,
		concat([
			fixed,
			options([option(SHB_USERAPPL, encoder.encode(application))]),
		]),
	);
}

/**
 * One listener as an interface: `LINKTYPE_TZSP`, no snap length (0), its
 * label as the name, its port in the description, and millisecond
 * timestamps (`if_tsresol` 3), the precision of the arrival time.
 */
export function interfaceBlock(listener: BoundListener): Uint8Array {
	const fixed = new Uint8Array(8);
	const view = new DataView(fixed.buffer);
	view.setUint16(0, LINKTYPE_TZSP, true);
	view.setUint16(2, 0, true);
	view.setUint32(4, 0, true);
	return block(
		IDB,
		concat([
			fixed,
			options([
				option(IF_NAME, encoder.encode(listener.label)),
				option(
					IF_DESCRIPTION,
					encoder.encode(
						`TZSP on UDP ${listener.address.includes(":") ? `[${listener.address}]` : listener.address}:${listener.port}`,
					),
				),
				option(IF_TSRESOL, Uint8Array.of(3)),
			]),
		]),
	);
}

/** The peer as the comment carries it, `peer=10.0.2.15:37008` or `peer=[::1]:37008`. */
export const peerComment = (address: string, port: number) =>
	`peer=${address.includes(":") ? `[${address}]` : address}:${port}`;

/** One datagram: its interface, its arrival time in ms, its bytes, its peer. */
export function packetBlock(interfaceId: number, capture: Capture): Uint8Array {
	const data = capture.datagram;
	const fixed = new Uint8Array(20);
	const view = new DataView(fixed.buffer);
	const ms = BigInt(Math.max(0, Math.trunc(capture.time)));
	view.setUint32(0, interfaceId, true);
	view.setUint32(4, Number(ms >> 32n), true);
	view.setUint32(8, Number(ms & 0xffffffffn), true);
	view.setUint32(12, data.length, true);
	view.setUint32(16, data.length, true);
	const padded = new Uint8Array(pad4(data.length));
	padded.set(data);
	return block(
		EPB,
		concat([
			fixed,
			padded,
			options([
				option(
					OPT_COMMENT,
					encoder.encode(peerComment(capture.peer.address, capture.peer.port)),
				),
			]),
		]),
	);
}

/**
 * A pcapng writer over `sink`. Blocks are handed to the sink one at a
 * time, each a whole block, so a file cut short by an interrupt or a full
 * disk ends at a block boundary or inside the last block, never before
 * one that was acknowledged. After the first failure every call rejects
 * with that failure, and `close` still closes the sink, once any sink call
 * that timed out has settled (for up to another `stallMs`), so a late open
 * is closed too. `written` counts only what the sink acknowledged in time.
 */
export function pcapngWriter(
	sink: ByteSink,
	options: PcapngWriterOptions = {},
): CaptureWriter {
	const stallMs = options.stallMs ?? DEFAULT_WRITE_STALL_MS;
	if (!Number.isInteger(stallMs) || stallMs < 0 || stallMs > MAX_TIMER_MS) {
		throw new TzspSniffError(
			"write/invalid-option",
			`stallMs must be a whole number from 0 to ${MAX_TIMER_MS}, not ${stallMs}.`,
			"Leave stallMs unset for 30 s, or 0 to turn the timer off.",
		);
	}
	const target = options.target ?? "pcapng";
	const written: WrittenCounts = { datagrams: 0, bytes: 0 };
	const interfaces = new Map<BoundListener, number>();
	let state: "new" | "open" | "closed" = "new";
	let failure: unknown;
	/** The sink was asked to open, so it must be asked to close. */
	let touched = false;
	/** The last sink call, settled or not: close waits for one that timed out. */
	let inflight: Promise<void> | undefined;

	/** A call out of order, or an option too long: the caller's mistake, not the sink's. */
	const misuse = (message: string) =>
		new TzspSniffError(
			"write/invalid-option",
			message,
			"Open a writer once, write, then close it; a writer writes one capture.",
		);

	/** Wait for `work`, or reject with write/stalled after `ms` (0: no limit). */
	async function timed(work: Promise<void>, ms: number, what: string) {
		if (ms === 0) return work;
		let timer: ReturnType<typeof setTimeout> | undefined;
		try {
			await Promise.race([
				work,
				new Promise<never>((_, reject) => {
					timer = setTimeout(
						() =>
							reject(
								new TzspSniffError(
									"write/stalled",
									`${target} took no data for ${ms / 1000}s while ${what}.`,
									"Write to a local disk, or read --format pcapng's stdout as it comes.",
								),
							),
						ms,
					);
				}),
			]);
		} finally {
			clearTimeout(timer);
		}
	}

	/** One sink call, timed; its failure is the writer's failure from now on. */
	async function call(what: string, run: () => Promise<void>): Promise<void> {
		if (failure !== undefined) throw failure;
		// A sink that throws instead of rejecting fails the same way.
		const work = (async () => run())();
		inflight = work.then(
			() => {},
			() => {},
		);
		try {
			await timed(work, stallMs, what);
		} catch (error) {
			failure ??= error;
			throw failure;
		}
	}

	const put = async (chunk: Uint8Array, what: string) => {
		await call(what, () => sink.write(chunk));
		written.bytes += chunk.length;
	};

	return {
		target,
		written,
		async open(listeners) {
			if (state !== "new") {
				throw misuse(`${target} was already opened.`);
			}
			// Every block that open writes is made first: an option too long
			// for pcapng is refused before the sink is touched.
			const headers = [
				sectionHeaderBlock(`tzsp-sniff ${VERSION}`),
				...listeners.map(interfaceBlock),
			];
			state = "open";
			listeners.forEach((l, i) => {
				interfaces.set(l, i);
			});
			touched = true;
			if (sink.open) {
				const open = sink.open;
				await call("opening it", () => open.call(sink));
			}
			for (const [i, block] of headers.entries()) {
				await put(
					block,
					i === 0 ? "writing the section header" : "writing an interface block",
				);
			}
		},
		async write(capture) {
			if (state !== "open") {
				throw misuse(
					`${target} is ${state === "new" ? "not open yet" : "closed"}; open() comes first and close() last.`,
				);
			}
			let id = interfaces.get(capture.listener);
			if (id === undefined) {
				// A listener object this writer was not opened with: match its
				// port, which is unique among a capture's listeners.
				for (const [l, i] of interfaces) {
					if (l.port === capture.listener.port) id = i;
				}
			}
			if (id === undefined) {
				throw misuse(
					`Datagram ${capture.seq} came from port ${capture.listener.port}, which ${target} has no interface for.`,
				);
			}
			await put(packetBlock(id, capture), "writing a packet block");
			written.datagrams += 1;
		},
		async close() {
			if (state === "closed") return;
			state = "closed";
			if (!touched || !sink.close) {
				if (failure !== undefined) throw failure;
				return;
			}
			// A call that timed out may still be running (a slow open that
			// will hold a file): let it settle before closing the sink.
			const pending = inflight;
			let settled = true;
			if (pending) {
				settled = false;
				await timed(
					pending.then(() => {
						settled = true;
					}),
					stallMs,
					"finishing its last call",
				).catch((error: unknown) => {
					failure ??= error;
				});
			}
			const close = sink.close;
			// Still running after that wait: close the sink again once it
			// settles, so whatever it acquired late is released. Nothing is
			// written after it.
			if (pending && !settled) {
				void pending.then(() => close.call(sink)).catch(() => {});
			}
			// After a failure the sink is still closed, but the first failure is
			// the one reported.
			const before = failure;
			failure = undefined;
			try {
				await call("closing it", () => close.call(sink));
			} catch (error) {
				if (before === undefined) throw error;
			}
			if (before !== undefined) {
				failure = before;
				throw before;
			}
		},
	};
}
