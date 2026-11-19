/**
 * The UDP listener: one unconnected `node:dgram` socket per port, a bounded
 * queue between the sockets and the consumer, and an async iterator over what
 * arrived (DESIGN.md, "Data path", "Lifecycle", "Limits").
 *
 * No `reusePort` (DESIGN.md, "Decided: no reusePort"): a port belongs to one
 * listener, and a bind failure is an error that names it.
 */
import { createSocket, type Socket } from "node:dgram";
import { addAbortListener } from "node:events";
import { isIP } from "node:net";
import { TzspSniffError } from "./errors.ts";
import { parseTzsp, TZSP_PORT, type TzspDatagram } from "./tzsp.ts";

export interface ListenerSpec {
	/** 0 asks the OS for a free port; {@link Listener.listeners} has the one bound. */
	port: number;
	/** A name for the router behind this port; defaults to the bound port number. */
	label?: string;
}

export interface QueueLimits {
	datagrams: number;
	bytes: number;
}

/**
 * Between the sockets and the consumer. UDP cannot slow its sender, so when
 * either budget is full new datagrams are dropped and counted. 10,000 is a
 * few seconds of a busy `/tool/sniffer` stream; 16 MiB holds them at a full
 * Ethernet MTU, or 256 datagrams at the UDP maximum.
 */
export const DEFAULT_QUEUE: QueueLimits = {
	datagrams: 10_000,
	bytes: 16 * 1024 * 1024,
};

export interface ListenOptions {
	/** Defaults to one listener on {@link TZSP_PORT}. */
	ports?: readonly ListenerSpec[];
	/** A local IP address; `0.0.0.0` (the default) or `::` for all. */
	bind?: string;
	/** Aborting ends the capture; an already aborted signal opens nothing. */
	signal?: AbortSignal;
	queue?: Partial<QueueLimits>;
}

/** Frozen: shared by the listener and every datagram it received. */
export interface BoundListener {
	readonly address: string;
	readonly port: number;
	readonly label: string;
}

/** The UDP peer as received: observed metadata, not a router's identity. */
export interface Peer {
	address: string;
	port: number;
	family: string;
}

export interface Capture {
	/** Arrival order across all listeners, from 1. A dropped datagram uses a number too. */
	seq: number;
	/** Host arrival time, ms since the epoch (DESIGN.md, "time is host arrival time"). */
	time: number;
	listener: BoundListener;
	peer: Peer;
	/** The datagram, in a buffer of its own that the listener never reuses. */
	datagram: Uint8Array;
	tzsp: TzspDatagram;
}

export interface ListenerCounters {
	/** Every datagram a socket delivered, dropped ones included. */
	received: number;
	dropped: number;
	droppedBytes: number;
	/** Queued and not yet read; after the end, what was left unread. */
	queued: number;
}

/** How a listener ended: `close()`, its signal, or a socket error. */
export type ListenerEnd = "closed" | "aborted" | "error";

export interface Listener extends AsyncIterable<Capture> {
	readonly bind: string;
	readonly listeners: readonly BoundListener[];
	readonly queue: Readonly<QueueLimits>;
	readonly counters: Readonly<ListenerCounters>;
	/**
	 * When the last socket was bound. This and the other `…At` times are on
	 * the monotonic clock (`performance.now()`), so elapsed time and the
	 * capture's limits survive a wall-clock step; compare them with each
	 * other, not with `Date.now()`. A datagram's `time` is wall time.
	 */
	readonly boundAt: number;
	/** When the last datagram arrived, dropped or not (monotonic). */
	readonly lastArrival: number | undefined;
	readonly ended: ListenerEnd | undefined;
	/** When intake stopped (monotonic): the end of the capture's duration. */
	readonly endedAt: number | undefined;
	/**
	 * Resolves once every socket has closed. Its port can then be bound
	 * again, except that Windows frees it a few milliseconds later (about
	 * 10 ms measured on windows-latest under Bun 1.4.4).
	 */
	readonly closed: Promise<void>;
	/**
	 * Stop intake and close every socket. Datagrams still queued are not
	 * delivered; `counters.queued` keeps their count. A pending read ends.
	 */
	close(): void;
}

/**
 * For tests only, not part of the package's API: a socket factory, so a
 * test can inject a socket error at a chosen moment.
 */
export interface ListenInternals {
	createSocket?: typeof createSocket;
}

interface Pending {
	seq: number;
	time: number;
	listener: BoundListener;
	peer: Peer;
	datagram: Uint8Array;
}

const invalid = (message: string, fix: string) =>
	new TzspSniffError("listen/invalid-option", message, fix);

function checkOptions(options: ListenOptions) {
	// A copy: a caller that changes its array while a bind is awaited cannot
	// change what is validated or bound.
	const ports = (options.ports ?? [{ port: TZSP_PORT }]).map((p) => ({ ...p }));
	const bind = options.bind ?? "0.0.0.0";
	if (ports.length === 0) {
		throw invalid("No ports to listen on.", "Pass at least one port.");
	}
	if (isIP(bind) === 0) {
		throw invalid(
			`The bind address ${bind} is not an IP address.`,
			"Use 0.0.0.0 for every IPv4 address, :: for IPv6, or one of the host's addresses.",
		);
	}
	const seenPorts = new Set<number>();
	const seenLabels = new Set<string>();
	for (const { port, label } of ports) {
		if (!Number.isInteger(port) || port < 0 || port > 65535) {
			throw invalid(
				`Port ${port} is not a UDP port.`,
				"Use 1 to 65535, or 0 for any free port.",
			);
		}
		if (port !== 0 && seenPorts.has(port)) {
			throw invalid(
				`Port ${port} is given twice.`,
				"Give each port once; one listener owns a port.",
			);
		}
		seenPorts.add(port);
		if (label !== undefined) {
			if (label === "" || seenLabels.has(label)) {
				throw invalid(
					`The label "${label}" is empty or used twice.`,
					"Give each port its own label, one per router.",
				);
			}
			seenLabels.add(label);
		}
	}
	const queue = { ...DEFAULT_QUEUE, ...options.queue };
	for (const [name, value] of Object.entries(queue)) {
		if (!Number.isInteger(value) || value < 1) {
			throw invalid(
				`The queue's ${name} budget ${value} is not a positive integer.`,
				"Leave it unset for the default.",
			);
		}
	}
	return { ports, bind, queue };
}

function bindOne(socket: Socket, port: number, address: string) {
	return new Promise<void>((resolve, reject) => {
		const done = () => {
			socket.off("error", onError);
			socket.off("listening", onListening);
			socket.off("close", onClose);
		};
		const onError = (error: Error) => {
			done();
			reject(error);
		};
		const onListening = () => {
			done();
			resolve();
		};
		// Closed by the listener's own end while binding: no event follows.
		const onClose = () => {
			done();
			reject(new Error("closed while binding"));
		};
		socket.once("error", onError);
		socket.once("listening", onListening);
		socket.once("close", onClose);
		// Exclusive: a cluster worker binds its own socket rather than sharing the
		// primary's, so a port has one owner here too (DESIGN.md, "no reusePort").
		socket.bind({ port, address, exclusive: true });
	});
}

const bindFix = (error: unknown) => {
	const code = (error as { code?: unknown }).code;
	if (code === "EADDRINUSE") {
		return "Another process holds the port: stop it, or listen on another --port and point the router there.";
	}
	if (code === "EADDRNOTAVAIL") {
		return "The bind address is not on this host: use 0.0.0.0, or one of the host's own addresses.";
	}
	if (code === "EACCES") {
		return "The OS refused the port: use one above 1023, such as the TZSP default 37008.";
	}
	return "Check the port and bind address, then run the capture again.";
};

/**
 * Bind every port, then iterate what arrives. Resolves once all are bound; a
 * bind that fails closes the ones already open and rejects with
 * `listen/bind-failed` naming the port. An already aborted `signal` opens
 * nothing and rejects with the signal's reason.
 */
export async function listen(
	options: ListenOptions = {},
	internals: ListenInternals = {},
): Promise<Listener> {
	const makeSocket = internals.createSocket ?? createSocket;
	const { ports, bind, queue } = checkOptions(options);
	const { signal } = options;
	signal?.throwIfAborted();

	const type = isIP(bind) === 6 ? "udp6" : "udp4";
	const sockets: Socket[] = [];
	const closedPromises: Promise<void>[] = [];
	const items: (Pending | undefined)[] = [];
	let head = 0;
	let queuedBytes = 0;
	let seq = 0;
	let lastArrival: number | undefined;
	let ended: ListenerEnd | undefined;
	let failure: TzspSniffError | undefined;
	let failureThrown = false;
	// Every pending read waits here; a wake resolves them all and each one
	// looks at the queue again, so no concurrent read is stranded.
	const waiters: (() => void)[] = [];
	const counters: ListenerCounters = {
		received: 0,
		dropped: 0,
		droppedBytes: 0,
		queued: 0,
	};
	const bound: BoundListener[] = [];

	const wake = () => {
		for (const resolve of waiters.splice(0)) resolve();
	};
	const closeSockets = () => {
		for (const socket of sockets.splice(0)) socket.close();
	};
	// addAbortListener runs even when an earlier listener on a shared signal
	// stops propagation (checked on Node 22.0.0, Node 26 and Bun 1.4.4).
	let abortRegistration: Disposable | undefined;
	let endedAt: number | undefined;
	const end = (how: ListenerEnd, error?: TzspSniffError) => {
		if (ended) return;
		ended = how;
		endedAt = performance.now();
		failure = error;
		items.length = 0;
		head = 0;
		queuedBytes = 0;
		abortRegistration?.[Symbol.dispose]();
		closeSockets();
		wake();
	};

	const open = () => {
		const socket = makeSocket({ type });
		sockets.push(socket);
		closedPromises.push(
			new Promise((resolve) => socket.once("close", () => resolve())),
		);
		return socket;
	};

	/** Close everything opened so far, then fail with `error`. */
	const abandon = async (error: unknown): Promise<never> => {
		closeSockets();
		await Promise.all(closedPromises);
		throw error;
	};

	for (const spec of ports) {
		const socket = open();
		try {
			await bindOne(socket, spec.port, bind);
		} catch (error) {
			// A socket bound earlier failed and ended the listener, closing this
			// one mid-bind: that first failure is the one to report.
			if (failure) return abandon(failure);
			// An abort while this bind was pending is the outcome, as it is when
			// the bind succeeds.
			if (signal?.aborted) return abandon(signal.reason);
			return abandon(
				new TzspSniffError(
					"listen/bind-failed",
					`Could not bind UDP ${bind}:${spec.port}: ${(error as Error).message}`,
					bindFix(error),
					{ cause: error },
				),
			);
		}
		if (failure) return abandon(failure);
		// An abort between binds starts no further bind.
		if (signal?.aborted) return abandon(signal.reason);
		const port = socket.address().port;
		// Frozen: every datagram from this socket refers to it, so a caller
		// cannot relabel datagrams already queued or bypass the label check.
		const listener: BoundListener = Object.freeze({
			address: bind,
			port,
			label: spec.label ?? String(port),
		});
		bound.push(listener);
		socket.on("message", (message, remote) => {
			if (ended) return;
			const time = Date.now();
			seq += 1;
			counters.received += 1;
			lastArrival = performance.now();
			if (
				counters.queued >= queue.datagrams ||
				queuedBytes + message.length > queue.bytes
			) {
				counters.dropped += 1;
				counters.droppedBytes += message.length;
				return;
			}
			counters.queued += 1;
			queuedBytes += message.length;
			items.push({
				seq,
				time,
				listener,
				peer: {
					address: remote.address,
					port: remote.port,
					family: remote.family,
				},
				// A copy, so every record owns its bytes whatever the runtime does
				// with its receive buffer (DESIGN.md, "bytes in and records out").
				datagram: new Uint8Array(message),
			});
			wake();
		});
		socket.on("error", (error) => {
			end(
				"error",
				new TzspSniffError(
					"listen/socket-error",
					`The UDP socket on ${bind}:${port} failed: ${error.message}`,
					"Run the capture again; if it repeats, check the host's interfaces and firewall.",
					{ cause: error },
				),
			);
		});
	}

	// A signal that fired while the ports were binding opens nothing either.
	if (signal?.aborted) return abandon(signal.reason);
	// Labels are checked again once bound: a default label is the bound port,
	// which an explicit label on another port can repeat.
	const labels = new Set(bound.map((l) => l.label));
	if (labels.size < bound.length) {
		return abandon(
			invalid(
				`Two listeners have the same label: ${bound.map((l) => `${l.port}=${l.label}`).join(", ")}.`,
				"Give each port its own label; a port without one is named by its number.",
			),
		);
	}
	if (signal)
		abortRegistration = addAbortListener(signal, () => end("aborted"));
	const boundAt = performance.now();
	const closed = Promise.all(closedPromises).then(() => undefined);

	const iterator: AsyncIterator<Capture> = {
		async next() {
			for (;;) {
				if (ended) {
					if (failure && !failureThrown) {
						failureThrown = true;
						throw failure;
					}
					return { value: undefined, done: true };
				}
				const item = items[head];
				if (item) {
					items[head] = undefined;
					head += 1;
					if (head > 1024 && head * 2 > items.length) {
						items.splice(0, head);
						head = 0;
					}
					counters.queued -= 1;
					queuedBytes -= item.datagram.length;
					return {
						value: { ...item, tzsp: parseTzsp(item.datagram) },
						done: false,
					};
				}
				await new Promise<void>((resolve) => {
					waiters.push(resolve);
				});
			}
		},
		async return() {
			end("closed");
			return { value: undefined, done: true };
		},
	};

	return {
		bind,
		listeners: Object.freeze(bound),
		queue,
		counters,
		boundAt,
		closed,
		get lastArrival() {
			return lastArrival;
		},
		get ended() {
			return ended;
		},
		get endedAt() {
			return endedAt;
		},
		close: () => end("closed"),
		[Symbol.asyncIterator]: () => iterator,
	};
}
