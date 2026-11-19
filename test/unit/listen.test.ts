import { describe, expect, test } from "bun:test";
import { createSocket, type Socket, type SocketOptions } from "node:dgram";
import { TzspSniffError } from "../../src/errors.ts";
import { type Listener, listen } from "../../src/listen.ts";
import {
	bytes,
	closeSocket,
	expectPortFree,
	fixture,
	freePort,
	holdPort,
	send,
	until,
} from "./helpers.ts";

/**
 * The listener's lifecycle on loopback (DESIGN.md, "Lifecycle"): each way a
 * capture can end releases every socket, proven by binding the port again.
 */
const REQUEST = fixture("7.25.1-x86-sniffer-stream")[0] as string;
const KEEPALIVE = "01040000";

const portOf = (l: Listener, i = 0) => l.listeners[i]?.port as number;

async function expectCode(promise: Promise<unknown>, code: string) {
	const error = await promise.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(error).toBeInstanceOf(TzspSniffError);
	expect((error as TzspSniffError).code).toBe(code as TzspSniffError["code"]);
	return error as TzspSniffError;
}

describe("listen", () => {
	test("receives datagrams with arrival order, peer, label and parsed TZSP", async () => {
		const listener = await listen({
			ports: [{ port: 0, label: "chr" }],
			bind: "127.0.0.1",
		});
		try {
			const port = portOf(listener);
			expect(port).toBeGreaterThan(0);
			expect(listener.listeners).toEqual([
				{ address: "127.0.0.1", port, label: "chr" },
			]);
			await send(port, [REQUEST, KEEPALIVE]);
			const it = listener[Symbol.asyncIterator]();
			const first = (await it.next()).value;
			const second = (await it.next()).value;
			expect(first.seq).toBe(1);
			expect(second.seq).toBe(2);
			expect(first.listener.label).toBe("chr");
			expect(first.peer.address).toBe("127.0.0.1");
			expect(first.peer.port).toBeGreaterThan(0);
			expect(first.time).toBeGreaterThanOrEqual(listener.boundAt);
			expect(first.tzsp.kind).toBe("packet");
			expect(second.tzsp.kind).toBe("control");
			expect(Array.from(first.datagram)).toEqual(Array.from(bytes(REQUEST)));
			// A plain Uint8Array in a buffer of its own: not a Buffer, not shared.
			expect(Object.getPrototypeOf(first.datagram)).toBe(Uint8Array.prototype);
			expect(first.datagram.buffer).not.toBe(second.datagram.buffer);
			expect(first.datagram.byteOffset).toBe(0);
			expect(first.datagram.buffer.byteLength).toBe(first.datagram.length);
			expect(listener.counters).toMatchObject({
				received: 2,
				dropped: 0,
				queued: 0,
			});
			expect(listener.lastArrival).toBe(second.time);
		} finally {
			listener.close();
			await listener.closed;
		}
	});

	test("the default label is the bound port number", async () => {
		const listener = await listen({ ports: [{ port: 0 }] });
		listener.close();
		await listener.closed;
		expect(listener.listeners[0]?.label).toBe(String(portOf(listener)));
		expect(listener.bind).toBe("0.0.0.0");
	});

	test("a failed second bind closes the first and names the port", async () => {
		const held = await holdPort();
		const first = await freePort();
		try {
			const error = await expectCode(
				listen({ ports: [{ port: first }, { port: held.port }] }),
				"listen/bind-failed",
			);
			expect(error.message).toContain(`0.0.0.0:${held.port}`);
			expect(error.fix).toContain("Another process holds the port");
			await expectPortFree(first);
		} finally {
			await closeSocket(held.socket);
		}
	});

	test("an already aborted signal opens nothing: no bind is even tried", async () => {
		// A held port would fail a bind with listen/bind-failed; the abort comes first.
		const held = await holdPort();
		try {
			const error = await listen({
				ports: [{ port: held.port }],
				signal: AbortSignal.abort(),
			}).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(error).not.toBeInstanceOf(TzspSniffError);
			expect((error as Error).name).toBe("AbortError");
		} finally {
			await closeSocket(held.socket);
		}
	});

	test("an abort while the consumer waits wakes the read as done and frees the port", async () => {
		const controller = new AbortController();
		const listener = await listen({
			ports: [{ port: 0 }],
			signal: controller.signal,
		});
		const pending = listener[Symbol.asyncIterator]().next();
		controller.abort();
		expect(await pending).toEqual({ value: undefined, done: true });
		expect(listener.ended).toBe("aborted");
		await listener.closed;
		await expectPortFree(portOf(listener));
	});

	test("close() while the consumer waits ends the read", async () => {
		const listener = await listen({ ports: [{ port: 0 }] });
		const pending = listener[Symbol.asyncIterator]().next();
		listener.close();
		expect((await pending).done).toBe(true);
		expect(listener.ended).toBe("closed");
		await listener.closed;
		await expectPortFree(portOf(listener));
	});

	test("break from for-await closes every socket", async () => {
		const listener = await listen({ ports: [{ port: 0 }, { port: 0 }] });
		await send(portOf(listener, 1), [REQUEST]);
		for await (const capture of listener) {
			expect(capture.listener.port).toBe(portOf(listener, 1));
			break;
		}
		expect(listener.ended).toBe("closed");
		await listener.closed;
		await expectPortFree(portOf(listener, 0));
		await expectPortFree(portOf(listener, 1));
	});

	test("an error thrown in the consumer closes every socket", async () => {
		const listener = await listen({ ports: [{ port: 0 }] });
		await send(portOf(listener), [REQUEST]);
		const consume = async () => {
			for await (const _ of listener) throw new Error("consumer failed");
		};
		await expect(consume()).rejects.toThrow("consumer failed");
		await listener.closed;
		await expectPortFree(portOf(listener));
	});

	test("a full queue drops and counts; seq numbers show the gap; the end keeps what was unread", async () => {
		const listener = await listen({
			ports: [{ port: 0 }],
			queue: { datagrams: 2 },
		});
		try {
			await send(portOf(listener), [
				REQUEST,
				REQUEST,
				REQUEST,
				REQUEST,
				REQUEST,
			]);
			await until(() => listener.counters.received === 5);
			expect(listener.counters).toMatchObject({
				received: 5,
				dropped: 3,
				queued: 2,
			});
			expect(listener.counters.droppedBytes).toBe(3 * bytes(REQUEST).length);
			const it = listener[Symbol.asyncIterator]();
			expect((await it.next()).value.seq).toBe(1);
			expect(listener.counters.queued).toBe(1);
			await send(portOf(listener), [REQUEST]);
			await until(() => listener.counters.received === 6);
			// Room for one again: the sixth was queued, so seq 3, 4 and 5 are the gap.
			listener.close();
			expect(listener.counters.queued).toBe(2);
			expect((await it.next()).done).toBe(true);
		} finally {
			listener.close();
			await listener.closed;
		}
	});

	test("the byte budget drops too", async () => {
		const size = bytes(REQUEST).length;
		const listener = await listen({
			ports: [{ port: 0 }],
			queue: { bytes: size * 2 + 1 },
		});
		try {
			await send(portOf(listener), [REQUEST, REQUEST, REQUEST]);
			await until(() => listener.counters.received === 3);
			expect(listener.counters).toMatchObject({ dropped: 1, queued: 2 });
		} finally {
			listener.close();
			await listener.closed;
		}
	});

	test("invalid options are refused before anything opens", async () => {
		const cases = [
			{ ports: [] },
			{ ports: [{ port: 70000 }] },
			{ ports: [{ port: 1.5 }] },
			{ ports: [{ port: 40000 }, { port: 40000 }] },
			{
				ports: [
					{ port: 0, label: "a" },
					{ port: 0, label: "a" },
				],
			},
			{ ports: [{ port: 0, label: "" }] },
			{ bind: "localhost" },
			{ queue: { datagrams: 0 } },
		];
		for (const options of cases) {
			await expectCode(listen(options), "listen/invalid-option");
		}
	});
});

describe("listen: cross-review cases (#20)", () => {
	/** A socket factory that keeps every socket it made, so a test can fault one. */
	const recording = () => {
		const sockets: Socket[] = [];
		return {
			sockets,
			createSocket: ((options: SocketOptions) => {
				const socket = createSocket(options);
				sockets.push(socket);
				return socket;
			}) as typeof createSocket,
		};
	};

	test("two pending reads both end on close()", async () => {
		const listener = await listen({ ports: [{ port: 0 }] });
		const it = listener[Symbol.asyncIterator]();
		const first = it.next();
		const second = it.next();
		listener.close();
		expect((await first).done).toBe(true);
		expect((await second).done).toBe(true);
		await listener.closed;
	});

	test("a socket error while a read is pending: the read rejects with listen/socket-error, every port is freed", async () => {
		const factory = recording();
		const listener = await listen(
			{ ports: [{ port: 0 }, { port: 0 }] },
			factory,
		);
		const pending = listener[Symbol.asyncIterator]().next();
		factory.sockets[1]?.emit("error", new Error("injected"));
		const error = await expectCode(pending, "listen/socket-error");
		expect(error.message).toContain(`:${portOf(listener, 1)}`);
		expect(listener.ended).toBe("error");
		await listener.closed;
		await expectPortFree(portOf(listener, 0));
		await expectPortFree(portOf(listener, 1));
	});

	test("a socket error during a later bind is the error reported, and nothing stays open", async () => {
		const factory = recording();
		const first = await freePort();
		const create = factory.createSocket;
		factory.createSocket = ((options: SocketOptions) => {
			const socket = create(options);
			// The second socket is about to bind: fault the first one now.
			if (factory.sockets.length === 2)
				queueMicrotask(() =>
					factory.sockets[0]?.emit("error", new Error("injected")),
				);
			return socket;
		}) as typeof createSocket;
		const error = await expectCode(
			listen({ ports: [{ port: first }, { port: 0 }] }, factory),
			"listen/socket-error",
		);
		expect(error.message).toContain(`:${first}`);
		await expectPortFree(first);
	});

	test("a label that repeats another port's default label is refused after binding", async () => {
		const a = await holdPort();
		const b = await holdPort();
		await closeSocket(a.socket);
		await closeSocket(b.socket);
		await expectCode(
			listen({
				ports: [{ port: a.port, label: String(b.port) }, { port: b.port }],
			}),
			"listen/invalid-option",
		);
		await expectPortFree(a.port);
		await expectPortFree(b.port);
	});
});
