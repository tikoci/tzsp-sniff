/**
 * The file `--write` saves to (DESIGN.md, "Requirement, file lifecycle"):
 * created exclusively, owner-only where the OS has permissions, and written
 * block by block with no buffer in the process, so whatever the capture
 * handed over is in the OS when it stops, however it stops.
 */
import { constants } from "node:fs";
import { type FileHandle, open } from "node:fs/promises";
import { TzspSniffError } from "./errors.ts";
import type { ByteSink } from "./pcapng.ts";

export interface FileSinkOptions {
	/**
	 * Replace a file that is already there. It is truncated in place, made
	 * owner-only first, and never followed through a symbolic link where the
	 * OS can refuse one (`O_NOFOLLOW`).
	 */
	overwrite?: boolean;
}

export interface FileSink extends ByteSink {
	readonly path: string;
	open(): Promise<void>;
	close(): Promise<void>;
}

/** Owner read and write: captures can hold credentials and private traffic. */
const OWNER_ONLY = 0o600;

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
): FileSink {
	let handle: FileHandle | undefined;
	return {
		path,
		async open() {
			if (handle) return;
			try {
				if (options.overwrite) {
					// Not O_TRUNC: the old contents go only once the file is
					// owner-only, so they are never readable by others as new
					// data arrives.
					const flags =
						constants.O_WRONLY |
						constants.O_CREAT |
						(constants.O_NOFOLLOW ?? 0);
					handle = await open(path, flags, OWNER_ONLY);
					const stat = await handle.stat();
					if (stat.isFile()) {
						await handle.chmod(OWNER_ONLY);
						await handle.truncate(0);
					}
				} else {
					handle = await open(path, "wx", OWNER_ONLY);
				}
			} catch (error) {
				const h = handle;
				handle = undefined;
				await h?.close().catch(() => {});
				if ((error as { code?: unknown }).code === "EEXIST") {
					throw new TzspSniffError(
						"write/exists",
						`${path} already exists; --write does not replace a file unless asked.`,
						"Give another path, or add --overwrite to replace it.",
						{ cause: error },
					);
				}
				throw failed(`Could not create ${path}`, error);
			}
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
			} catch (error) {
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
