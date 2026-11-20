/**
 * A strict pcapng reader for tests: little-endian sections as our writer
 * makes them, every length checked, so a cut or malformed file fails the
 * test that reads it. Not a reader for files from elsewhere (`decode`,
 * slice 5, is that).
 */
export interface ReadOption {
	code: number;
	value: Uint8Array;
}

export interface ReadBlock {
	type: number;
	/** The body between the two length fields. */
	body: Uint8Array;
	offset: number;
}

export interface ReadInterface {
	linkType: number;
	snapLen: number;
	name?: string;
	description?: string;
	tsresol?: number;
}

export interface ReadPacket {
	interfaceId: number;
	/** Timestamp units since the epoch, at the interface's resolution. */
	timestamp: bigint;
	capturedLength: number;
	originalLength: number;
	data: Uint8Array;
	comments: string[];
}

export interface ReadFile {
	application?: string;
	version: [number, number];
	sectionLength: bigint;
	interfaces: ReadInterface[];
	packets: ReadPacket[];
	/** Bytes after the last whole block: a cut-off block, if any. */
	trailing: number;
}

const text = (b: Uint8Array) => new TextDecoder().decode(b);

function readOptions(body: Uint8Array, from: number): ReadOption[] {
	const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
	const list: ReadOption[] = [];
	let at = from;
	while (at < body.length) {
		if (at + 4 > body.length) throw new Error(`option header cut at ${at}`);
		const code = view.getUint16(at, true);
		const length = view.getUint16(at + 2, true);
		if (code === 0) {
			if (length !== 0) throw new Error("opt_endofopt with a length");
			if (at + 4 !== body.length) throw new Error("bytes after opt_endofopt");
			return list;
		}
		const end = at + 4 + length;
		if (end > body.length) throw new Error(`option ${code} overruns its block`);
		list.push({ code, value: body.subarray(at + 4, end) });
		at += 4 + ((length + 3) & ~3);
	}
	if (list.length) throw new Error("options without opt_endofopt");
	return list;
}

/** Every whole block, in order; `trailing` counts the bytes after them. */
export function blocks(file: Uint8Array): {
	blocks: ReadBlock[];
	trailing: number;
} {
	const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
	const list: ReadBlock[] = [];
	let at = 0;
	while (at + 12 <= file.length) {
		const type = view.getUint32(at, true);
		const length = view.getUint32(at + 4, true);
		if (length < 12 || length % 4 !== 0)
			throw new Error(`block at ${at}: bad length ${length}`);
		if (at + length > file.length) break;
		if (view.getUint32(at + length - 4, true) !== length)
			throw new Error(`block at ${at}: trailing length differs`);
		list.push({
			type,
			body: file.subarray(at + 8, at + length - 4),
			offset: at,
		});
		at += length;
	}
	return { blocks: list, trailing: file.length - at };
}

export function readPcapng(file: Uint8Array): ReadFile {
	const { blocks: list, trailing } = blocks(file);
	const first = list[0];
	if (first?.type !== 0x0a0d0d0a) throw new Error("no section header first");
	const shb = new DataView(
		first.body.buffer,
		first.body.byteOffset,
		first.body.byteLength,
	);
	if (shb.getUint32(0, true) !== 0x1a2b3c4d)
		throw new Error("not little-endian byte-order magic");
	const result: ReadFile = {
		version: [shb.getUint16(4, true), shb.getUint16(6, true)],
		sectionLength: shb.getBigInt64(8, true),
		interfaces: [],
		packets: [],
		trailing,
	};
	for (const o of readOptions(first.body, 16)) {
		if (o.code === 4) result.application = text(o.value);
	}
	for (const b of list.slice(1)) {
		const v = new DataView(b.body.buffer, b.body.byteOffset, b.body.byteLength);
		if (b.type === 1) {
			const i: ReadInterface = {
				linkType: v.getUint16(0, true),
				snapLen: v.getUint32(4, true),
			};
			for (const o of readOptions(b.body, 8)) {
				if (o.code === 2) i.name = text(o.value);
				if (o.code === 3) i.description = text(o.value);
				if (o.code === 9) i.tsresol = o.value[0] as number;
			}
			result.interfaces.push(i);
		} else if (b.type === 6) {
			const captured = v.getUint32(12, true);
			const dataEnd = 20 + ((captured + 3) & ~3);
			if (dataEnd > b.body.length) throw new Error("packet data overruns");
			const interfaceId = v.getUint32(0, true);
			if (interfaceId >= result.interfaces.length)
				throw new Error(`packet names interface ${interfaceId}`);
			result.packets.push({
				interfaceId,
				timestamp:
					(BigInt(v.getUint32(4, true)) << 32n) | BigInt(v.getUint32(8, true)),
				capturedLength: captured,
				originalLength: v.getUint32(16, true),
				data: b.body.subarray(20, 20 + captured),
				comments: readOptions(b.body, dataEnd)
					.filter((o) => o.code === 1)
					.map((o) => text(o.value)),
			});
		} else {
			throw new Error(`unexpected block type ${b.type}`);
		}
	}
	return result;
}
