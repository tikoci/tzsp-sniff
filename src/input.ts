// cspell:ignore tsresol tsoffset SPB FCS -- pcapng and pcap names
/**
 * Capture files and hex lines in, packets out, for `decode` (DESIGN.md,
 * "`decode` input"). Input is pulled a block at a time and every length is
 * checked against a cap before anything is allocated for it, so a corrupt
 * or hostile length is an error, not an allocation.
 *
 * Formats:
 *
 * - pcapng, from the specification
 *   (https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html):
 *   sections in either byte order; interface description, enhanced packet,
 *   simple packet and the obsolete packet block are read, any other block
 *   is skipped by its length.
 * - pcap (https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcap.html):
 *   either byte order, microsecond or nanosecond magic.
 * - hex: one TZSP datagram per line, as the RouterOS fixtures are stored;
 *   whitespace inside a line is ignored, and blank lines and lines starting
 *   with `#` are skipped. Never detected: given with `--input hex`.
 *
 * Structural problems end the input with `decode/malformed`; an input that
 * ends inside a block sets `truncated` and ends quietly, since every packet
 * before it was whole. A packet's own bytes are not checked here: they go
 * to the TZSP parser and the dissector, which never throw.
 */
import { TzspSniffError } from "./errors.ts";
import {
	LINKTYPE_TZSP,
	MAX_INTERFACE_NAME_BYTES,
	MAX_INTERFACES,
} from "./pcapng.ts";
import type { InputFormat } from "./records.ts";
import { toHex } from "./tzsp.ts";

/** The longest pcapng block or pcap record read (1 MiB); a longer one is `decode/malformed`. */
export const MAX_BLOCK_BYTES = 1024 * 1024;
// The interface budget is the writer's too (src/pcapng.ts): a file
// `--write` saves always decodes.
export { MAX_INTERFACE_NAME_BYTES, MAX_INTERFACES };
/** The longest hex line read, in bytes (128 KiB, a UDP datagram's 65,535 bytes as hex with room to spare). */
export const MAX_HEX_LINE = 128 * 1024;

/** The most of a source's chunk copied at once. */
const SPAN = 64 * 1024;
const EMPTY = new Uint8Array(0);

/** What `decode` reads: bytes in one piece, or in chunks as a file or stdin gives them. */
export type DecodeInput =
	| Uint8Array
	| AsyncIterable<Uint8Array>
	| Iterable<Uint8Array>;

/** The input was interrupted by the caller's signal. */
export class InputAborted extends Error {
	constructor() {
		super("decode was interrupted");
		this.name = "InputAborted";
	}
}

const isAsync = (x: object): x is AsyncIterable<Uint8Array> =>
	Symbol.asyncIterator in x;

/**
 * Pulls bytes from the input as they are needed, holding at most what the
 * current block needs plus one chunk.
 *
 * A `Uint8Array` input is read in place, as `parseTzsp` reads a datagram.
 * Chunks from an iterable are copied, since a source may reuse its buffer
 * for the next chunk: a span at a time, as the reader needs them, and the
 * source is not asked for the next chunk until this one is used up. One
 * huge chunk therefore costs what a block or a line needs, not its size.
 */
/** Settles when `work` does or `signal` aborts, whichever is first; never rejects. */
export async function untilAbort(
	work: Promise<unknown>,
	signal: AbortSignal,
): Promise<void> {
	if (signal.aborted) return;
	let onAbort = () => {};
	try {
		await Promise.race([
			work.then(
				() => {},
				() => {},
			),
			new Promise<void>((resolve) => {
				onAbort = resolve;
				signal.addEventListener("abort", onAbort, { once: true });
			}),
		]);
	} finally {
		signal.removeEventListener("abort", onAbort);
	}
}

export class ByteReader {
	/** Chunks not yet taken start at `head`, from `offset` in it. */
	private chunks: Uint8Array[] = [];
	private head = 0;
	private offset = 0;
	private buffered = 0;
	private iterator:
		| AsyncIterator<Uint8Array>
		| Iterator<Uint8Array>
		| undefined;
	/** The source's last chunk, from where the reader has not yet copied. */
	private rest: Uint8Array | undefined;
	private ended = false;
	/** A pull from the input has not settled (an abort stopped waiting for it). */
	private pulling = false;
	private readonly signal: AbortSignal | undefined;
	/**
	 * Stops a pull waiting on the input: the caller's abort, or close().
	 * The reader's own, so close() wakes a pull with no signal given too.
	 */
	private readonly halt = new AbortController();
	/** Reads under way (`read`, `peek`, `readLine`), which keep their bytes. */
	private reading = 0;
	/**
	 * On an abort a pull waiting on the input stops. With no pull running,
	 * the source is told to finish, so a caller that aborts and reads no
	 * further still releases it, and with no read under way the unread
	 * bytes go too. A pull running sees the abort itself and its caller
	 * closes the reader: return() then would land inside a sync generator
	 * still in next(). A read under way keeps its bytes, so it is not cut
	 * short; its caller closes the reader.
	 */
	private readonly onAbort = () => {
		this.halt.abort();
		if (this.pulling) return;
		void this.finish();
		if (!this.reading) this.drop();
	};
	/** Bytes taken so far: where the next read starts. */
	position = 0;

	constructor(input: DecodeInput, signal?: AbortSignal) {
		this.signal = signal;
		if (input instanceof Uint8Array) {
			if (input.length) this.push(input);
			this.ended = true;
			return;
		}
		// Made before the listener, so an iterator that cannot be made
		// leaves none on the caller's signal.
		this.iterator = isAsync(input)
			? input[Symbol.asyncIterator]()
			: input[Symbol.iterator]();
		if (signal) {
			signal.addEventListener("abort", this.onAbort, { once: true });
			// Aborted while the iterator was made: the event has fired.
			if (signal.aborted) this.onAbort();
		}
	}

	private push(chunk: Uint8Array) {
		this.chunks.push(chunk);
		this.buffered += chunk.length;
	}

	/** One more span of the input, copied; false at its end. */
	private async more(): Promise<boolean> {
		const signal = this.halt.signal;
		// First: after an abort or close() the source is released, which is
		// not its end.
		if (signal.aborted) throw new InputAborted();
		if (this.rest) {
			// A copy, as a plain Uint8Array: Buffer#slice would be a view.
			this.push(new Uint8Array(this.rest.subarray(0, SPAN)));
			this.rest =
				this.rest.length > SPAN ? this.rest.subarray(SPAN) : undefined;
			return true;
		}
		const iterator = this.iterator;
		if (this.ended || !iterator) return false;
		// Normalized: a promise from another realm, or any thenable, is raced
		// against the abort too, a sync iterator's result is one as well, and
		// a sync throw is a rejection. Pulling from before the call, so an
		// abort inside a sync next() does not call return() inside it.
		this.pulling = true;
		const next = (async () => iterator.next())();
		next.then(
			() => {
				this.pulling = false;
			},
			() => {
				this.pulling = false;
			},
		);
		let result: IteratorResult<Uint8Array>;
		let onAbort = () => {};
		try {
			result = await Promise.race([
				next,
				new Promise<never>((_, reject) => {
					onAbort = () => reject(new InputAborted());
					signal.addEventListener("abort", onAbort, { once: true });
					// Aborted while next() ran: the event has already fired.
					if (signal.aborted) onAbort();
				}),
			]);
		} catch (error) {
			// A source that rejects its read because of the abort: the abort.
			if (signal.aborted) throw new InputAborted();
			throw error;
		} finally {
			signal.removeEventListener("abort", onAbort);
		}
		// A pull that settled as the signal fired (a chunk or the end):
		// the abort still wins.
		if (signal.aborted) throw new InputAborted();
		if (result.done) {
			this.ended = true;
			return false;
		}
		const chunk = result.value;
		if (!(chunk instanceof Uint8Array)) {
			throw new TzspSniffError(
				"decode/read-failed",
				`The input gave a ${typeof chunk} where bytes were expected.`,
				"Pass a Uint8Array, or an iterable of them (a file or stdin stream without an encoding set).",
			);
		}
		if (chunk.length) this.rest = chunk;
		return true;
	}

	/** Buffer at least `n` bytes, or what is left; resolves to the bytes buffered. */
	private async fill(n: number): Promise<number> {
		while (this.buffered < n && (await this.more())) {}
		return this.buffered;
	}

	/** Move past `n` buffered bytes, dropping chunks used up. */
	private skip(n: number) {
		this.buffered -= n;
		this.position += n;
		this.offset += n;
		for (;;) {
			const chunk = this.chunks[this.head];
			if (!chunk || this.offset < chunk.length) break;
			this.offset -= chunk.length;
			// Released now; the array itself is compacted below.
			this.chunks[this.head] = EMPTY;
			this.head += 1;
		}
		// Many small chunks: drop the used ones now and then, not one by one.
		if (this.head > 64 && this.head * 2 > this.chunks.length) {
			this.chunks = this.chunks.slice(this.head);
			this.head = 0;
		}
	}

	/** Copy up to `n` buffered bytes from the front, without taking them. */
	private copy(n: number): Uint8Array {
		const out = new Uint8Array(Math.min(n, this.buffered));
		let at = 0;
		let offset = this.offset;
		for (let i = this.head; at < out.length; i++) {
			const chunk = this.chunks[i] as Uint8Array;
			const part = Math.min(chunk.length - offset, out.length - at);
			out.set(chunk.subarray(offset, offset + part), at);
			at += part;
			offset = 0;
		}
		return out;
	}

	/** Take `n` bytes from the buffer (n ≤ buffered), into one array. */
	private take(n: number): Uint8Array {
		const first = this.chunks[this.head];
		if (first && first.length - this.offset >= n) {
			const out = first.subarray(this.offset, this.offset + n);
			this.skip(n);
			return out;
		}
		const out = this.copy(n);
		this.skip(n);
		return out;
	}

	/** Up to `n` bytes without taking them. */
	async peek(n: number): Promise<Uint8Array> {
		return this.under(async () => {
			await this.fill(n);
			return this.copy(n);
		});
	}

	/** Run a read, counted, so an abort meanwhile keeps its bytes. */
	private async under<T>(read: () => Promise<T>): Promise<T> {
		this.reading += 1;
		try {
			return await read();
		} finally {
			this.reading -= 1;
		}
	}

	/**
	 * `n` bytes, or fewer when the input ends first. The caller checks `n`
	 * against its cap before asking.
	 */
	async read(n: number): Promise<Uint8Array> {
		return this.under(async () => this.take(Math.min(await this.fill(n), n)));
	}

	/**
	 * The next line without its end of line, `undefined` at the end, or
	 * `too-long` when `max` bytes pass with no newline. Each byte is scanned
	 * once, however the input is chunked.
	 */
	readLine(max: number): Promise<Uint8Array | undefined | "too-long"> {
		return this.under(() => this.line(max));
	}

	private async line(
		max: number,
	): Promise<Uint8Array | undefined | "too-long"> {
		let index = this.head;
		let from = this.offset;
		let scanned = 0;
		for (;;) {
			for (; index < this.chunks.length; index++, from = 0) {
				const chunk = this.chunks[index] as Uint8Array;
				// No further than the line may run, plus one byte for its
				// newline: a huge input in one piece is not scanned whole.
				const end = Math.min(chunk.length, from + max - scanned + 1);
				const found = chunk.subarray(from, end).indexOf(0x0a);
				if (found >= 0) {
					const line = this.take(scanned + found);
					this.skip(1);
					return line;
				}
				scanned += end - from;
				if (scanned > max) return "too-long";
			}
			if (!(await this.more())) {
				return this.buffered ? this.take(this.buffered) : undefined;
			}
		}
	}

	/**
	 * Stop reading: the input's iterator is told to finish (a file closes).
	 * `wait` false is an abort: `return()` is called but not waited for, so
	 * a source slow to clean up cannot hold the interrupted summary. A pull
	 * may also still be waiting on the input (stdin with nothing to read),
	 * and an async generator queues `return()` behind it, so then it is not
	 * waited for either: the source releases itself (the CLI destroys stdin
	 * there). An abort while it waits ends the wait as well, and an abort
	 * with the reader still open closes it, a pull running or not.
	 */
	async close(wait = true): Promise<void> {
		const done = this.finish();
		this.drop();
		// A pull still waiting on the input stops.
		this.halt.abort();
		if (!done || !wait || this.pulling) return;
		if (this.signal) await untilAbort(done, this.signal);
		else await done;
	}

	/** Let go of the bytes not yet taken. */
	private drop() {
		this.rest = undefined;
		this.chunks = [];
		this.head = 0;
		this.offset = 0;
		this.buffered = 0;
	}

	/** Tell the source to finish, once; settles when its return() does. */
	private finish(): Promise<void> | undefined {
		this.signal?.removeEventListener("abort", this.onAbort);
		const iterator = this.iterator;
		this.iterator = undefined;
		this.ended = true;
		if (!iterator?.return) return undefined;
		return (async () => iterator.return?.())().then(
			() => {},
			() => {},
		);
	}
}

/** The section header's block type, the same in either byte order. */
const SHB = 0x0a0d0d0a;
const IDB = 1;
const PB = 2;
const SPB = 3;
const EPB = 6;
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;
const OPT_COMMENT = 1;
const IF_NAME = 2;
const IF_TSRESOL = 9;
const IF_TSOFFSET = 14;

/** pcap magic numbers: microsecond and nanosecond timestamps. */
const PCAP_MICRO = 0xa1b2c3d4;
const PCAP_NANO = 0xa1b23c4d;

/** A packet as the input held it. */
export interface FilePacket {
	/** tcpdump's LINKTYPE_ value; TZSP (128) for hex lines. */
	linkType: number;
	/** The interface block's `if_name`, when it has one (pcapng). */
	interfaceName?: string;
	/** ms since the epoch, from the block's timestamp; absent for hex lines and simple packet blocks. */
	time?: number;
	/** The packet block's `opt_comment` values, in order. */
	comments: string[];
	data: Uint8Array;
}

/** What reading found besides packets. */
export interface InputState {
	/** The input ended inside a block, at this byte offset. */
	truncatedAt?: number;
}

const malformed = (message: string, fix?: string) =>
	new TzspSniffError(
		"decode/malformed",
		message,
		fix ??
			"Check that the file is a whole pcapng or pcap capture; the records before this point were decoded.",
	);

/** The format the first bytes name, or undefined when they name none. */
export function detectFormat(
	head: Uint8Array,
): Exclude<InputFormat, "hex"> | undefined {
	if (head.length < 4) return undefined;
	const view = new DataView(head.buffer, head.byteOffset, head.byteLength);
	const be = view.getUint32(0, false);
	const le = view.getUint32(0, true);
	if (be === SHB) return "pcapng";
	for (const magic of [PCAP_MICRO, PCAP_NANO])
		if (be === magic || le === magic) return "pcap";
	return undefined;
}

/** For hex lines: a leading byte-order mark is dropped, as an editor may add one. */
const decoder = new TextDecoder();
/** For pcapng names and comments: kept byte for byte, a leading U+FEFF included. */
const metadata = new TextDecoder("utf-8", { ignoreBOM: true });

/** The ms range a JavaScript Date holds (ECMA-262, "Time Values and Time Range"). */
const MAX_TIME_MS = 8_640_000_000_000_000n;

interface Options {
	options: Map<number, Uint8Array[]>;
}

/**
 * A block's options from `from` on. A list that runs past the block is read
 * up to where it stops making sense: options are metadata, and the packet
 * they annotate is still whole.
 */
function readOptions(
	view: DataView,
	from: number,
	little: boolean,
): Options["options"] {
	const options = new Map<number, Uint8Array[]>();
	let at = from;
	while (at + 4 <= view.byteLength) {
		const code = view.getUint16(at, little);
		const length = view.getUint16(at + 2, little);
		if (code === 0) break;
		if (at + 4 + length > view.byteLength) break;
		const value = new Uint8Array(view.buffer, view.byteOffset + at + 4, length);
		const list = options.get(code);
		if (list) list.push(value);
		else options.set(code, [value]);
		at += 4 + ((length + 3) & ~3);
	}
	return options;
}

interface Interface {
	linkType: number;
	snapLength: number;
	name?: string;
	/** `if_tsresol`: units per second as 10^-n, or 2^-n with the top bit set. */
	resolution: number;
	/** `if_tsoffset`, seconds. */
	offset: bigint;
}

/**
 * A pcapng timestamp in whole ms since the epoch, or undefined when it is
 * outside what a Date holds. Exact: the scale and the signed offset are
 * applied in BigInt, the range is checked before rounding (so both ends
 * hold, and a time just past either does not), and the result rounds down.
 */
function pcapngTime(units: bigint, iface: Interface): number | undefined {
	const exponent = BigInt(iface.resolution & 0x7f);
	const perSecond = iface.resolution & 0x80 ? 2n ** exponent : 10n ** exponent;
	// Units and the offset as one count of units, then to ms, rounding down.
	const scaled = (units + iface.offset * perSecond) * 1000n;
	const limit = MAX_TIME_MS * perSecond;
	if (scaled > limit || scaled < -limit) return undefined;
	let ms = scaled / perSecond;
	if (scaled < 0n && ms * perSecond !== scaled) ms -= 1n;
	return Number(ms);
}

async function* pcapng(
	reader: ByteReader,
	state: InputState,
): AsyncGenerator<FilePacket> {
	let little = true;
	let interfaces: Interface[] | undefined;
	/** Name bytes the section's interfaces hold. */
	let nameBytes = 0;
	/** Where the section ends, when its header says (-1 is unknown). */
	let sectionEnd: number | undefined;
	for (;;) {
		const start = reader.position;
		const head = await reader.read(8);
		if (head.length === 0) {
			// A section that said how long it is and stopped short was cut.
			if (sectionEnd !== undefined && start < sectionEnd)
				state.truncatedAt = start;
			return;
		}
		if (head.length < 8) {
			state.truncatedAt = start;
			return;
		}
		const headView = new DataView(head.buffer, head.byteOffset, 8);
		const isSection = headView.getUint32(0, false) === SHB;
		if (isSection) {
			const magic = await reader.read(4);
			if (magic.length < 4) {
				state.truncatedAt = start;
				return;
			}
			const m = new DataView(magic.buffer, magic.byteOffset, 4);
			if (m.getUint32(0, true) === BYTE_ORDER_MAGIC) little = true;
			else if (m.getUint32(0, false) === BYTE_ORDER_MAGIC) little = false;
			else {
				throw malformed(
					`The section header at byte ${start} has no byte-order magic (${toHex(magic)}).`,
				);
			}
		} else if (!interfaces) {
			throw malformed(
				`The pcapng input starts with block type ${headView.getUint32(0, little)}, not a section header.`,
			);
		}
		const type = headView.getUint32(0, little);
		const length = headView.getUint32(4, little);
		const least = isSection ? 28 : 12;
		if (length < least || length % 4 !== 0 || length > MAX_BLOCK_BYTES) {
			throw malformed(
				length > MAX_BLOCK_BYTES
					? `The block at byte ${start} declares ${length} bytes, over the ${MAX_BLOCK_BYTES}-byte limit.`
					: `The block at byte ${start} declares a length of ${length}, which is not a multiple of 4 of at least ${least}.`,
			);
		}
		if (sectionEnd !== undefined) {
			if (isSection && start !== sectionEnd) {
				throw malformed(
					`A section header starts at byte ${start}, and the section before it declared its end at byte ${sectionEnd}.`,
				);
			}
			if (!isSection && start + length > sectionEnd) {
				throw malformed(
					`The block at byte ${start} runs past the end of its section, which its header puts at byte ${sectionEnd}.`,
				);
			}
		}
		const consumed = isSection ? 12 : 8;
		const rest = await reader.read(length - consumed);
		if (rest.length < length - consumed) {
			state.truncatedAt = start;
			return;
		}
		const view = new DataView(rest.buffer, rest.byteOffset, rest.byteLength);
		const trailer = view.getUint32(rest.length - 4, little);
		if (trailer !== length) {
			throw malformed(
				`The block at byte ${start} declares ${length} bytes at its start and ${trailer} at its end.`,
			);
		}
		/** The block body: after type and length (and the magic, for a section), before the trailer. */
		const body = new DataView(
			rest.buffer,
			rest.byteOffset,
			rest.byteLength - 4,
		);
		if (isSection) {
			const major = body.getUint16(0, little);
			if (major !== 1) {
				throw malformed(
					`The section header at byte ${start} is pcapng version ${major}; only version 1 is read.`,
				);
			}
			const declared = body.getBigInt64(4, little);
			// -1 is unknown; any other length is whole blocks, so a multiple of 4.
			if (declared < -1n || (declared !== -1n && declared % 4n !== 0n)) {
				throw malformed(
					`The section header at byte ${start} declares a section length of ${declared}${declared < -1n ? "" : ", not a multiple of 4"}.`,
				);
			}
			// The length counts what follows the section header.
			sectionEnd =
				declared === -1n ? undefined : reader.position + Number(declared);
			interfaces = [];
			nameBytes = 0;
			continue;
		}
		const list = interfaces as Interface[];
		if (type === IDB) {
			if (body.byteLength < 8) {
				throw malformed(`The interface block at byte ${start} is too short.`);
			}
			const options = readOptions(body, 8, little);
			const iface: Interface = {
				linkType: body.getUint16(0, little),
				snapLength: body.getUint32(4, little),
				resolution: options.get(IF_TSRESOL)?.[0]?.[0] ?? 6,
				offset: 0n,
			};
			const name = options.get(IF_NAME)?.[0];
			nameBytes += name?.length ?? 0;
			if (
				list.length >= MAX_INTERFACES ||
				nameBytes > MAX_INTERFACE_NAME_BYTES
			) {
				throw malformed(
					`The interface block at byte ${start} passes the ${MAX_INTERFACES} interfaces or ${MAX_INTERFACE_NAME_BYTES} bytes of names one section may hold.`,
				);
			}
			if (name) iface.name = metadata.decode(name);
			const offset = options.get(IF_TSOFFSET)?.[0];
			if (offset?.length === 8) {
				iface.offset = new DataView(
					offset.buffer,
					offset.byteOffset,
					8,
				).getBigInt64(0, little);
			}
			list.push(iface);
			continue;
		}
		if (type !== EPB && type !== SPB && type !== PB) continue;
		const fixed = type === SPB ? 4 : 20;
		if (body.byteLength < fixed) {
			throw malformed(`The packet block at byte ${start} is too short.`);
		}
		const id =
			type === EPB
				? body.getUint32(0, little)
				: type === PB
					? body.getUint16(0, little)
					: 0;
		const iface = list[id];
		if (!iface) {
			throw malformed(
				`The packet block at byte ${start} names interface ${id}, and the section has ${list.length}.`,
			);
		}
		let captured: number;
		if (type === SPB) {
			// The block holds the original length, cut to the snap length, padded.
			const original = body.getUint32(0, little);
			captured = Math.min(original, iface.snapLength || original);
			// Math.ceil, not a 32-bit mask: a length near 2^32 would wrap to 0.
			if (body.byteLength !== 4 + Math.ceil(captured / 4) * 4) {
				throw malformed(
					`The simple packet block at byte ${start} holds ${body.byteLength - 4} bytes of data for a packet of ${captured}.`,
				);
			}
		} else {
			captured = body.getUint32(12, little);
			if (captured > body.byteLength - 20) {
				throw malformed(
					`The packet block at byte ${start} says it captured ${captured} bytes, more than the block holds.`,
				);
			}
			// Zero is no limit, as in pcap.
			if (iface.snapLength && captured > iface.snapLength) {
				throw malformed(
					`The packet block at byte ${start} says it captured ${captured} bytes, more than its interface's snap length of ${iface.snapLength}.`,
				);
			}
		}
		const data = new Uint8Array(body.buffer, body.byteOffset + fixed, captured);
		const packet: FilePacket = {
			linkType: iface.linkType,
			comments: [],
			data,
		};
		if (iface.name !== undefined) packet.interfaceName = iface.name;
		if (type !== SPB) {
			const units =
				(BigInt(body.getUint32(4, little)) << 32n) |
				BigInt(body.getUint32(8, little));
			const time = pcapngTime(units, iface);
			if (time === undefined) {
				throw malformed(
					`The packet block at byte ${start} has a timestamp outside the dates a record can hold.`,
				);
			}
			packet.time = time;
			const options = readOptions(body, 20 + ((captured + 3) & ~3), little);
			for (const c of options.get(OPT_COMMENT) ?? [])
				packet.comments.push(metadata.decode(c));
		}
		yield packet;
	}
}

async function* pcap(
	reader: ByteReader,
	state: InputState,
): AsyncGenerator<FilePacket> {
	const header = await reader.read(24);
	if (header.length < 24) {
		state.truncatedAt = 0;
		return;
	}
	const h = new DataView(header.buffer, header.byteOffset, 24);
	const magicLe = h.getUint32(0, true);
	const magicBe = h.getUint32(0, false);
	const isMagic = (m: number) => m === PCAP_MICRO || m === PCAP_NANO;
	// Checked here too: --input pcap skips detection.
	if (!isMagic(magicLe) && !isMagic(magicBe)) {
		throw malformed(
			`The input starts with ${toHex(header.subarray(0, 4))}, which is not a pcap magic number.`,
		);
	}
	const little = isMagic(magicLe);
	const nano = h.getUint32(0, little) === PCAP_NANO;
	const major = h.getUint16(4, little);
	if (major !== 2) {
		throw malformed(
			`The pcap header is version ${major}.${h.getUint16(6, little)}; only version 2 is read.`,
		);
	}
	/** 0 sets no limit. */
	const snapLength = h.getUint32(16, little);
	// The link type is the low 16 bits; the high bits can carry FCS details.
	const linkType = h.getUint32(20, little) & 0xffff;
	for (;;) {
		const start = reader.position;
		const head = await reader.read(16);
		if (head.length === 0) return;
		if (head.length < 16) {
			state.truncatedAt = start;
			return;
		}
		const v = new DataView(head.buffer, head.byteOffset, 16);
		const captured = v.getUint32(8, little);
		// The cap counts the record's header, as a pcapng block's length does.
		if (captured + 16 > MAX_BLOCK_BYTES) {
			throw malformed(
				`The record at byte ${start} declares ${captured} bytes, which with its header passes the ${MAX_BLOCK_BYTES}-byte limit.`,
			);
		}
		if (snapLength && captured > snapLength) {
			throw malformed(
				`The record at byte ${start} declares ${captured} bytes, more than the file's snap length of ${snapLength}.`,
			);
		}
		const seconds = v.getUint32(0, little);
		const fraction = v.getUint32(4, little);
		// A whole second or more in the fraction is not a time to round.
		const perSecond = nano ? 1e9 : 1e6;
		if (fraction >= perSecond) {
			throw malformed(
				`The record at byte ${start} has a fraction of ${fraction}, not under the ${perSecond} ${nano ? "ns" : "µs"} in a second.`,
			);
		}
		const data = await reader.read(captured);
		if (data.length < captured) {
			state.truncatedAt = start;
			return;
		}
		yield {
			linkType,
			// The fraction rounds down on its own: added first, 999,999 ns
			// would round up to the next ms in the sum.
			time: seconds * 1000 + Math.trunc(nano ? fraction / 1e6 : fraction / 1e3),
			comments: [],
			data,
		};
	}
}

async function* hex(reader: ByteReader): AsyncGenerator<FilePacket> {
	let lineNumber = 0;
	for (;;) {
		const raw = await reader.readLine(MAX_HEX_LINE);
		if (raw === undefined) return;
		lineNumber += 1;
		if (raw === "too-long") {
			throw malformed(
				`Line ${lineNumber} is longer than ${MAX_HEX_LINE} bytes.`,
				"Give one datagram per line as hex; a UDP datagram fits in 131,070 hex digits.",
			);
		}
		const text = decoder.decode(raw).replace(/\s+/g, "");
		if (!text || text.startsWith("#")) continue;
		if (!/^(?:[0-9a-fA-F]{2})+$/.test(text)) {
			throw malformed(
				`Line ${lineNumber} is not hex: ${JSON.stringify(text.slice(0, 40))}${text.length > 40 ? "…" : ""}.`,
				"Give one datagram per line as pairs of hex digits; lines starting with # are skipped.",
			);
		}
		const data = new Uint8Array(text.length / 2);
		for (let i = 0; i < data.length; i++)
			data[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
		yield { linkType: LINKTYPE_TZSP, comments: [], data };
	}
}

/** The packets of `reader`, read as `format`. */
export function readPackets(
	reader: ByteReader,
	format: InputFormat,
	state: InputState,
): AsyncGenerator<FilePacket> {
	if (format === "pcapng") return pcapng(reader, state);
	if (format === "pcap") return pcap(reader, state);
	return hex(reader);
}
