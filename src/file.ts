/**
 * The file `--write` saves to (DESIGN.md, "Requirement, file lifecycle"):
 * a new inode, owner-only where the OS has permissions, written block by
 * block with no buffer in the process, so whatever the capture handed over
 * is in the OS when it stops, however it stops. A block that fails partway
 * is cut back off, so the file ends at a block boundary.
 */
import { randomBytes } from "node:crypto";
import {
	type FileHandle,
	lstat,
	open as openFile,
	rename,
	unlink,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { TzspSniffError } from "./errors.ts";
import type { ByteSink } from "./pcapng.ts";

export interface FileSinkOptions {
	/**
	 * Replace a regular file that is already there. The capture is written
	 * to a new owner-only file beside it, which is renamed over the old one
	 * before any packet is written: a reader that had the old file open keeps
	 * reading the old contents, and a symbolic link, a pipe or a device at
	 * the path is refused rather than written through.
	 */
	overwrite?: boolean;
}

export interface FileSink extends ByteSink {
	readonly path: string;
	open(): Promise<void>;
	close(): Promise<void>;
}

/** For tests only, not part of the package's API: the file opener. */
export interface FileSinkInternals {
	open?: typeof openFile;
}

/** Owner read and write: captures can hold credentials and private traffic. */
const OWNER_ONLY = 0o600;

const codeOf = (error: unknown) => (error as { code?: unknown }).code;

const failed = (message: string, cause: unknown) =>
	new TzspSniffError(
		"write/failed",
		`${message}: ${(cause as Error).message}`,
		"Check the path, its directory's permissions and the free space, then run again.",
		{ cause },
	);

/**
 * A sink that writes to `path`. Nothing touches the disk until `open()`,
 * which `pcapngWriter` calls once the capture's ports are bound, so a bind
 * that fails leaves no file. An existing file is `write/exists`, unless
 * `overwrite` is set.
 */
export function fileSink(
	path: string,
	options: FileSinkOptions = {},
	internals: FileSinkInternals = {},
): FileSink {
	const open = internals.open ?? openFile;
	let handle: FileHandle | undefined;
	/** Bytes of the chunks written whole: the file's length after each write. */
	let size = 0;

	/** Create `at` new, owner-only; an existing file is `write/exists`. */
	async function create(at: string): Promise<FileHandle> {
		try {
			return await open(at, "wx", OWNER_ONLY);
		} catch (error) {
			if (codeOf(error) === "EEXIST") {
				throw new TzspSniffError(
					"write/exists",
					`${at} already exists; --write does not replace a file unless asked.`,
					"Give another path, or add --overwrite to replace it.",
					{ cause: error },
				);
			}
			throw failed(`Could not create ${at}`, error);
		}
	}

	/** A new file beside `path`, renamed over it: never the old inode. */
	async function replace(): Promise<FileHandle> {
		let stat: Awaited<ReturnType<typeof lstat>> | undefined;
		try {
			stat = await lstat(path);
		} catch (error) {
			if (codeOf(error) !== "ENOENT")
				throw failed(`Could not check ${path}`, error);
		}
		if (stat && !stat.isFile()) {
			throw new TzspSniffError(
				"write/failed",
				`${path} is ${stat.isSymbolicLink() ? "a symbolic link" : stat.isDirectory() ? "a directory" : "not a regular file"}; --overwrite replaces only a regular file.`,
				"Give the path of a regular file, or a new one.",
			);
		}
		// Not named after the file: a name near the 255-byte limit would
		// make the temporary name too long.
		const temp = join(
			dirname(path),
			`.${randomBytes(6).toString("hex")}.tzsp-sniff`,
		);
		const h = await create(temp);
		try {
			await rename(temp, path);
		} catch (error) {
			await h.close().catch(() => {});
			await unlink(temp).catch(() => {});
			throw failed(`Could not replace ${path}`, error);
		}
		return h;
	}

	return {
		path,
		async open() {
			if (handle) return;
			handle = options.overwrite ? await replace() : await create(path);
		},
		async write(chunk) {
			const h = handle;
			if (!h) {
				throw new TzspSniffError(
					"write/failed",
					`${path} is not open.`,
					"Open the sink before writing to it.",
				);
			}
			try {
				let at = 0;
				while (at < chunk.length) {
					const { bytesWritten } = await h.write(chunk, at, chunk.length - at);
					at += bytesWritten;
				}
				size += chunk.length;
			} catch (error) {
				// A chunk cut short (a full disk, a file size limit) is cut off:
				// the file ends at the last whole block, not inside one.
				await h.truncate(size).catch(() => {});
				throw failed(`Writing ${path} failed`, error);
			}
		},
		async close() {
			const h = handle;
			handle = undefined;
			if (!h) return;
			try {
				await h.close();
			} catch (error) {
				throw failed(`Closing ${path} failed`, error);
			}
		},
	};
}
