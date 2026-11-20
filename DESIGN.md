<!-- cspell:ignore Tvb epan usr recvfrom libuv EPB IDB LINKTYPE WTAP ENCAP winbox ipc tsoffset -- Wireshark, pcapng and system names -->

# Design

Why tzsp-sniff is built the way it is. Status, 2026-11-18: reviewed in #1
(the maintainer, then a Codex cross-review). Each part is marked:

- **Decided**: settled; changing it is a new decision recorded here.
- **Requirement**: what the implementation must do and test; the code and
  its tests become the record once they exist.
- **Unverified**: a claim waiting on evidence, with the issue that will
  settle it. Code does not rely on it until then.

Work with an end point is an issue; this file keeps the reasons.

## What it is, and what it is not

tzsp-sniff receives the TZSP streams RouterOS sends (`/tool/sniffer` with
`streaming-enabled=yes`, or a mangle rule with `action=sniff-tzsp`) on a plain
UDP socket and decodes them. A plain socket needs no root and no capture
privileges, which is the gap it fills: the usual receivers (`tshark -i any`,
Wireshark) capture from an interface and need them.

It is a tool for RouterOS work, including CHRs under quickchr, not a general
sniffer. Its users are agents first: output is sized so an agent can get a
targeted answer in few tokens, and a person on a terminal gets enough to
test and run it.

**Decided**, boundaries with other tikoci repos (tikoci-crossref):

| Concern | Owner | Here |
| --- | --- | --- |
| Arming the router (running `/tool/sniffer` commands) | centrs (device access), quickchr (CHRs) | prints the commands and exports a builder for them; never logs in to a router |
| RouterOS binary protocol knowledge | m2ir (YAML schemas) | consumes it: tables generated from m2ir at a pinned commit |
| How to use the sniffer on RouterOS | routeros-skills `routeros-sniffer` | links here once published |
| Booting CHRs for tests | quickchr | devDependency for the integration tier |
| An MCP server | centrs, if anyone | none: a CLI run with `npx` or `bunx` needs no MCP setup on top of the router setup |

The library is meant to be a dependency, of centrs (a later
`centrs tools tzsp` adapter) and of quickchr's CMR lab, whose
`examples/cmr/tool/tzsp.ts` was written to move into a package like this one.
Neither is a dependency of this repo's shipped code.

## Data path

```text
router   /tool/sniffer  or  mangle action=sniff-tzsp
           │ UDP to <host>:<port>
host     listener (node:dgram, one unconnected socket per port)
           │ { datagram, peer ip:port, listener label, arrival time }
         parseTzsp ─→ type 0, Ethernet? ─→ dissect ─→ filter ─→ format ─→ stdout
                         │ no                                   └─→ --write (every datagram)
                         └─→ control, unsupported or invalid record, counted, kept
```

What is known about RouterOS's side, and from where:

- **Both senders, seen on CHRs** (#5, 2026-11-19 UTC;
  `test/lab/tzsp-senders/REPORT.md`, fixtures in `test/fixtures/routeros/`):
  for ICMP echo, `/tool/sniffer` streaming and mangle `sniff-tzsp` on
  RouterOS 7.25.1 (stable) and 7.24.6 (long-term) x86_64 under KVM, and the
  sniffer on 7.25.1 arm64 under TCG, sent version 1, type 0 (received),
  encapsulation 1 (Ethernet) and the end tag alone, in every datagram
  received: no timestamp, sensor, interface or original-length tag. The
  first capture, 7.26beta5 x86 (quickchr `examples/cmr/FINDINGS.md`,
  "Wire"; bytes in `test/unit/tzsp.test.ts`), agrees.
  - The router's own echo requests, mirrored by mangle in `output` and
    `postrouting`, came behind an Ethernet header with all-zero MACs;
    replies mirrored in `prerouting` and `input` kept the link's MACs.
  - `only-headers=yes` sent a 1000-byte ping as its first 60 bytes of
    frame, with no tag giving the original length.
  - `sniff-id` added no tag: a `sniff-tzsp` rule does not keep it. It is
    kept by `action=sniff-pc`, which sends its own format, not TZSP: the id
    in 4 bytes, 8 more bytes, then the IPv4 packet at byte 12, then
    trailing bytes.
  - `filter-stream` reads `false` by default. With `no` and a filter that
    matches UDP, the sniffer captured its own stream, one TZSP layer per
    pass: over 800 datagrams from one ping before a scheduled stop, whole
    copies up to 30 layers, then IPv4 fragments.
- **Unverified**: physical routers, wireless encapsulations, VLAN tags,
  IPv6, traffic other than ICMP echo, mangle `forward`, other channels,
  mangle or `only-headers` on arm64, and whether any sender adds a tag in
  a case not tested.
- **Decided: dispatch on record type and encapsulation.** Only type 0 with
  encapsulation 1 goes to Ethernet dissection. Keepalive (4) and
  port-opener (5) records carry no tag list (Wireshark `packet-tzsp.c`,
  commit e0929ac4, `dissect_tzsp`); they and any other type or encapsulation
  are kept as records, counted apart from packets, and never dissected as a
  frame. `parseTzsp()` reports this as `kind` (#4).

Attribution:

- **Decided: time is host arrival time.** No timestamp tag was seen from
  the senders tested in #5 (both, on 7.24.6 and 7.25.1 x86_64; the
  sniffer only on 7.25.1 arm64). A tag 82 (`time-stamp`), if one appears,
  stays in the record's tags as raw hex until a capture shows its format;
  arrival time is used either way.
- **Decided: a sender is observed UDP metadata, not an identity.** Each
  record carries the peer address and port as received and the label of the
  listener that received it. Neither authenticates a router. Under QEMU
  user-mode networking every guest's datagrams arrive from a loopback peer,
  so the reliable label is the port: one listener port per router
  (`--port 37008=router-a --port 37009=router-b`), as quickchr's CMR lab does.
- **Decided: no capture interface unless the sender says so.** TZSP from
  RouterOS carries no interface. A frame's Ethernet source is whoever sent
  it on that link, an endpoint or the previous hop, and the same frame can
  appear at several capture points. quickchr's `dedupe()` combines router
  and source MAC as a heuristic for one lab's TCP and MNDP sightings; it is
  not general attribution, and this tool does not claim any.
- **Bind address**: `--bind` picks the local address (default all IPv4
  addresses; IPv6 with `--bind ::`). `setup --quickchr` targets the SLIRP
  gateway 10.0.2.2, which reaches the host's loopback; for a physical router
  `setup` targets the host address the user selects (see `setup`).
- **Sockets stay unconnected.** A socket connected to one peer receives only
  that peer's datagrams; a listener that must accept every router, or a
  SLIRP-rewritten peer it cannot predict, stays unconnected (`recvfrom`).
  quickchr's gateway recipe (`docs/networking-recipes.md`) is the CHR case.

**Decided: no `reusePort`.** The cross-review measured it on Linux 7.2.8
x86_64: two listeners with `reusePort` on one port got 32 and 0 datagrams
from one sending socket, under both Node 26.12.1 and Bun 1.4.4, and split
32 datagrams from distinct source ports 16/16 (Node) and 14/18 (Bun). A
second listener can silently take an entire TZSP flow. Node also added the
option only in 22.12.0, above the `engines.node` floor, and libuv's
load-balancing flag excludes Darwin. A port is owned by one listener; a
bind failure is an error that names the port. (MNDP broadcasts behave
differently, which is why centrs sets it for MNDP; that does not carry over.)

**Not quickchr's port map.** quickchr's service map creates `hostfwd`
listeners for host-to-guest traffic. TZSP flows guest to host, and
tzsp-sniff must own the host UDP socket, so adding TZSP to that map would
have QEMU hold the receiver's port. If quickchr wants to help, it advertises
a receiver endpoint per VM (BACKLOG.md).

## Library

The library never prints or exits (tikoci-cli-mcp, "Layers"). Proposed
exports, all usable from Node and Bun:

```typescript
parseTzsp(datagram: Uint8Array): TzspDatagram          // exists: kind, datagram, problem
dissect(frame: Uint8Array): Dissection                   // exists: layers, never throws
listen(options): Promise<Listener>                       // exists: ports, queue, signal
openCapture(options): Promise<CaptureStream>             // exists: limits, counters, records
summarize(): StatsAccumulator                            // exists: bounded, see Limits
createFilter(spec): PacketFilter                         // exists: (capture, dissection?) => boolean
selectFields(record, fields)                             // exists: --fields, for any surface
pcapngWriter(sink): CaptureWriter                        // exists: streaming, with backpressure
fileSink(path, { overwrite }): FileSink                  // exists: --write's file
openDecode(input, options): Promise<DecodeStream>        // exists: decode, the same records from a file
snifferCommands(options): string[]                       // RouterOS lines for /tool/sniffer or mangle
dissectors(): DissectorInfo[]                            // exists: the registry, as listed
```

**Requirement, bytes in and records out:**

- Every record keeps the complete datagram it came from, as a view of the
  received buffer, next to the inner frame and each layer's span. A consumer
  that keeps a record past the next one may hold that view; the listener
  allocates a new buffer per datagram and never reuses one.
- Every result says what went wrong, separately: `truncated` (the bytes end
  early), `malformed` (a field contradicts the format), `unsupported` (valid,
  not decoded here). Each comes with the bytes, so nothing is dropped.

A TUI, an MCP server or a centrs command is an adapter over these, not a
second implementation.

**Decided: `listen()` resolves once every port is bound** (first slice,
2026-11-19), rather than returning an iterable that binds lazily. A bind
failure then rejects before any record, and a caller that bound port 0
learns the port before the router is pointed at it. The `Listener` is the
async iterable, with the bound ports, its counters and a `closed` promise
that resolves when every socket has closed. `openCapture()` is the shared
core every surface uses: it adds the limits, dissection, counters and the
record stream (`src/records.ts` has the record types).

### Lifecycle

**Requirement.** The listener owns its sockets, timers and listeners, and
releases all of them on every way a capture can end:

- a bind that fails on the second of several ports closes the first, and the
  error names the failed port;
- an `AbortSignal` already aborted when `listen()` starts opens nothing;
- an abort, a limit or SIGINT while the consumer awaits `next()` wakes that
  read, stops intake and resolves it as done;
- an early `return()` or `break` from the consumer, an error thrown in the
  consumer, a closed stdout pipe and a failed `--write` each stop intake
  and close every socket;
- asynchronous `dgram` errors after bind end the capture with a coded error.

A closed stdout pipe is seen at the next write: a pipe gives no sign that
its reader left while nothing is written (on Linux, a zero-byte write to a
pipe returns before it checks for a reader), so a quiet `--follow | head`
ends at the next datagram, a limit or Ctrl-C. `--count` stops on its own.
A terminal that stops reading (Ctrl-S, an unread pane) must not hang the
capture. Node and Bun both write to a TTY with blocking `write()` calls on
the main thread, so a full terminal stops every timer and the SIGINT
handler, and the port stays bound (Node 26.12.1, Bun 1.4.4 and 1.4.5,
Linux x86_64). The CLI writes its terminal streams so the main thread
never blocks (`terminalStream` in `src/cli/sink.ts`): on Node by turning
off the handle's blocking mode, on Bun, which has no handle on a TTY
stream, through `fs.write` on the thread pool. `output/stalled` then
fires as it does for a pipe. Tests put stdout on a libc pseudo-terminal
that nobody reads, for Bun (`test/unit/bin.test.ts`) and for the built CLI
under Node (`test/node/`). Windows is not covered: its consoles are not
measured, and Node writes a Windows stdout pipe synchronously (BACKLOG.md).

Tests for each: fail the second bind, cancel an idle capture, break the
iteration, close the pipe, then bind the same port again to prove it was
released. On Windows the OS frees a UDP port a few milliseconds after the
socket's `close` event (about 10 ms on windows-latest under Bun 1.4.4, CI
run 44521692931), so there the rebind is retried for up to 500 ms; on Linux
and macOS it must succeed at once.

### Limits

**Requirement.** UDP cannot slow its sender, so every buffer is bounded:

- **Queue**: a default budget of datagrams and bytes between the socket and
  the consumer: 10,000 datagrams or 16 MiB, whichever fills first
  (`DEFAULT_QUEUE`; a few seconds of a busy stream, or 256 datagrams at the
  UDP maximum). When it is full, new datagrams are dropped and counted; a
  `capture/dropped` warning and the summary give the count. A capture with
  drops never reports itself as complete.
- **Summary**: conversation and sender tables are capped (a top-N plus an
  "other" bucket and a count of what was folded), so a long `--follow` holds
  constant memory.
- **No output holds the whole capture**: every format writes each record
  as it comes, which is why there is no `--format json` (see "Decided:
  JSONL, no `--format json`").
- **Writers stream** with backpressure; a sink that stalls past a timeout
  ends the capture with a coded error instead of growing the queue.
- **Parsers** are bounded too; see "Dissectors".

## CLI

One binary, `tzsp-sniff`, following tikoci-cli-mcp: stdout is the result,
everything else goes to stderr, errors carry a code from one registry.

| Command | Does |
| --- | --- |
| `listen` (the default) | receive and print, until a limit is met or forever with `--follow` |
| `decode <file\|->` | the same pipeline over a capture file or stdin; no network |
| `setup` | print the RouterOS commands that send to this listener |
| `dissectors` | list protocols, how each is matched (link type, EtherType, IP protocol) and its fields |

**Decided: `listen` is the default command**, so `tzsp-sniff --count 10`
works, which is what an agent guesses; `--help` lists `listen` and says it is
the default.

**Requirement, flags:**

- One registry declares each flag's arity, the commands it applies to, and
  the flags it conflicts with. A flag given to a command it does not apply to
  is refused with a code that names where it does apply (tikoci-cli-mcp,
  "Refuse, never drop"): `decode --follow` (`cli/wrong-command`, whose
  message names `listen`); `--fields` or `--stats` with
  `--format pcapng`; `--follow` with `--count`, `--duration` or
  `--idle`; `--detail` with `--stats`.
- `--help` is answered before dispatch; the scan stops at a bare `--`. Tests
  hold registry and help in step, and cover `--`.
- Every flag has a `TZSP_SNIFF_<KEY>` environment variable (not built yet:
  the first slice reads no environment variable, so a `.env` cannot reach
  it); a flag given on
  the command line replaces the variable entirely (a repeated `--port`
  replaces the variable's list, it does not extend it), and `--no-<flag>`
  overrides a variable that turned it on.
- **No limit given**: `listen` stops after 10 seconds, with a tip naming
  `--duration` and `--follow`, so an agent that guesses a bare command never
  hangs. `--follow` runs until a signal.

### Output for agents

Three knobs keep answers small, from cheapest to richest:

- `--stats`: no packets, only the summary.
- `--detail line|summary|layers|full`: `line` is one string per packet like
  tcpdump's; `summary` adds the fields an agent filters on (addresses, ports,
  protocol chain, flags, length); `layers` adds every dissector's fields;
  `full` adds the raw bytes as hex.
- `--fields a,b,c`: only the named fields, in that order. Record `type` and,
  on a summary, `status` cannot be removed.

**Decided, `--fields`** (second slice, 2026-11-19):

- It shapes the results: `packet`, `record` and `summary` records. A
  `header`, `warning` or `tip` stays whole: they frame the stream, and their
  codes are what a reader acts on. A summary also keeps its `error` when it
  has one, so a failed capture still says why on stdout.
- A field a record does not have (ports on ARP) is left out of that record,
  as it is without `--fields`.
- A name no record has is refused (`cli/invalid-value`, with the list in the
  fix). With `--stats` only summary fields are known, since nothing else is
  printed.
- Without `--detail`, the detail is raised to the least that carries every
  named field (`--fields datagram` reads at `full`). An explicit `--detail`
  below that is refused (`cli/flag-conflict`) rather than printing records
  without the field asked for.
- Text prints the record's type, then the fields in the order named:
  `key=value` runs on one line (the first on the type's line, a later one
  indented), and layers, tags and the datagram on lines of their own where
  they were named. Only on stdout: the start line, notices and (without
  `--stats`) the summary on stderr are unchanged, so in text a summary field
  is refused unless `--stats` makes the summary the result. `selectFields()` is exported, so an
  adapter shapes records the same way.

`--format text|jsonl|pcapng`. Text is the default, one line per packet,
plain when stdout is not a terminal or `NO_COLOR` is set. `jsonl` is one
record per line, the machine-readable form; `pcapng` writes the file format
below to stdout.

**Decided: JSONL, no `--format json`** (maintainer, first slice,
2026-11-19). tikoci-cli-mcp's rule stands: a tool offers a `--json` mode
that keeps everything in one document unless there are reasons not to.
Here there are:

- A capture is a stream of UDP datagrams, and a JSON document is valid only
  once it is complete. It must hold every record until the end, so it needed
  its own limit rule, a refusal of `--follow`, an entry and byte cap with
  its own stop reason, and a writer that never builds one string, and a
  capture cut off by a kill or a broken pipe left nothing parseable. A cut
  JSONL stream keeps every line written, and the missing `summary` says it
  was cut.
- Wrapping is one command after the fact: `jq` reads JSONL as it is, and
  `jq -s .` makes one array.
- A library caller adapts the record stream to whatever shape it needs, an
  MCP tool's bounded result included, so no surface needs the CLI to build
  a document.
- The JSONL records already carry what the house rule wants kept together:
  the `header`, `warning` and `tip` records with their codes, and the
  `summary` with its status and error, all on stdout.

`--format json` is refused as `cli/invalid-value` with a fix that names
`--format jsonl` and `jq -s .`, so an agent that tries it out of habit
learns the format in one step. The first slice shipped json behind
`--count` or `--duration` and was changed before release.

**Decided: the output shape is this tool's own.** It is not centrs's envelope
(`ok`, `data`, `warnings`, `tips`, `error`), which fits centrs's
explain-retrieve-execute flow. A centrs adapter maps our records to whatever
its `tools` commands return; `tools btest` has the same question there.

### Counters and `--expect`

**Requirement.** The summary counts, separately: datagrams received,
control records, unsupported records, invalid datagrams (truncated or
malformed TZSP, the `invalid` kind), packets removed by filters, datagrams
dropped by the queue, datagrams still queued when a limit stopped the
capture (`unread`), datagrams read whose save to `--write` or `--format
pcapng` failed (`unsaved`, at most one: the capture ends there), and
packets reported; all but the first add up to it.
The summary also says what stopped the capture (`stoppedBy`: `count`,
`duration`, `idle`, `interrupt` or `error`, and `end` for `decode`): whichever
ended intake first, and nothing later changes it. `--count`
and `--expect` count **packets reported** (after filters). `--idle` is time
since the last datagram received, of any kind, starting when the sockets
are bound.

A capture that ends with no packets reported is a read with an empty result:
exit 0 and a warning, whose code says which case it is, because each has a
different fix:

| Case | Warning | Tip names |
| --- | --- | --- |
| nothing arrived | `capture/no-datagrams` | `tzsp-sniff setup`, and checking the router's sniffer is running |
| only control, unsupported or malformed records | `capture/no-frames` | `--detail full` (in text or jsonl) to see them |
| frames arrived, filters removed all | `capture/all-filtered` | the filter flags in effect |

**Decided:** `--expect N` turns fewer than N packets reported into exit 1
with error `capture/expect-unmet`, also when the capture ended by SIGINT;
the error carries the same case as the table. Without `--expect`, SIGINT
ends a capture normally (summary written, exit 0). SIGINT before the
sockets are bound exits 130, the shell's code for it: no header or summary
was written, so it is not reported as an empty capture. A second SIGINT
also exits 130, at once and without the summary; the stream may already
hold a header and records, and its missing summary marks it cut off.

### Stream termination

**Requirement.** Every JSONL stream starts with a `header` record
(`schemaVersion`, ports, bind address, filters, limits) and, once started,
ends with exactly one `summary` record whose `status` is `complete`,
`interrupted`, `incomplete` (records dropped) or `error`, with the error
code when there is one. Between them: `packet`, `record` (control,
unsupported or malformed), `warning` and `tip`, as they happen. A stream
with no `summary` was cut off (the process was killed or the pipe broke)
and a reader treats it as failed. In text and pcapng formats, warnings, tips, errors and
the summary go to stderr, except that text with `--stats` writes the summary to
stdout as the result. Tests read each stream to EOF and check the last
record, not only the ones before it.

### `--write`: capture now, look later

`--write <file>` saves every datagram as received, whatever `--format`,
`--detail` and the filters print. With `--stats`, the first look costs a
few lines:

```sh
tzsp-sniff --duration 30s --write cmr.pcapng --stats
tzsp-sniff decode cmr.pcapng --proto tcp --port-match 54321 --detail layers
```

The summary says whether the file is worth reading and which filter to
start with, and `decode` drills in without capturing again, with no `tee`,
`jq` or a script in between.

**Decided: the file is pcapng with link type `LINKTYPE_TZSP` (128)**
([tcpdump link types](https://www.tcpdump.org/linktypes.html)), so each
packet block holds the TZSP datagram byte for byte: tags, control records
and malformed datagrams included, and decodable again after a dissector
improves. One interface block per listener carries its label and port;
the block timestamp is the arrival time; the UDP peer goes in a per-packet
option. `--format pcapng` writes the same representation. Filters never
apply to `--write`; they apply to `--format pcapng` on stdout.
**Verified** (slice 4, 2026-11-19): TShark 4.2.2 (Ubuntu 24.04's
`4.2.2-1.1build3`), run as a non-root user, reads a file `pcapngWriter`
made as TZSP: `frame.protocols` starts `tzsp:eth:ethertype:ip:icmp`, the
inner `ip.src`, `ip.dst` and `icmp.type` are there, `frame.interface_name`
is the listener's label, `frame.comment` is the peer and
`frame.time_epoch` the arrival time (`test/tshark/pcapng.test.ts`, run
locally in a Docker image of Ubuntu 24.04 and by CI's `tshark` job, which
pins that version).

**Decided, the file's shape** (maintainer, slice 4, 2026-11-19):

- **The peer is the packet block's `opt_comment`**, as
  `peer=<address>:<port>` (an IPv6 address in brackets, with its zone if it has one: `peer=[fe80::1%eth0]:5000`). pcapng has no
  standard option for a packet's sender, and a custom option needs an IANA
  Private Enterprise Number this project does not have; Wireshark and
  TShark show a comment as `frame.comment` with no setup, and `decode`
  reads it back. The cost: it shares the slot people annotate with.
- **Blocks**: little-endian; a section header with `shb_userappl`
  `tzsp-sniff <version>` and an unknown section length (-1); one interface
  block per listener in `--port` order, with `if_name` its label,
  `if_description` `TZSP on UDP <bind>:<port>`, no snap length (0) and
  `if_tsresol` 3, milliseconds, the precision of the arrival time; one
  enhanced packet block per datagram, captured and original length both
  the datagram's.
- **One sink write per block, each awaited.** A slow sink slows the
  capture loop and the bounded queue absorbs the burst (drops are
  counted); a sink call that takes longer than 30 s is `write/stalled`.
  stdout's own sink times itself out (`output/stalled`), so the writer
  behind `--format pcapng` adds no timer. A call that timed out may still
  finish: `close` waits for it (up to another 30 s) before closing the
  sink; still running then, the stall is reported and the sink's one
  `close` runs when that call settles, never alongside it, so a slow
  open's file is closed too (final review of ecd23b1), and `written` counts only
  blocks the sink acknowledged in time. An option over 65535 bytes (a
  long label), or listeners past what one section holds and `decode`
  reads back (`MAX_INTERFACES`, `MAX_INTERFACE_NAME_BYTES`: one budget
  for writer and reader, so a file `--write` saved always decodes; final
  review of 71d400c), is `write/invalid-option` before the sink is
  touched. Sink
  calls run one at a time in the order made, so a library caller that
  writes without awaiting still gets whole blocks in order, and the first
  failure sticks whatever its value, `undefined` included (Copilot review
  of cdcd610).
- **The writers sit in `openCapture()`**: `write` (every datagram the
  capture reads, before filters) and `writeReported` (each datagram the
  stream reports: the frames the filters keep, and every control,
  unsupported and invalid record). A datagram is saved, then counted, then
  handed over: a record the caller sees is already in the file, and a
  datagram whose save failed is counted once, as `unsaved` (cross-review
  of 52e53d5). A write failure does not change `stoppedBy` when a limit or
  signal had already ended intake: after a signal it stays `interrupt`
  (final review of ecd23b1). A writer opens after the bind (a port
  that fails leaves no file) and before the header (a file that cannot be
  made opens no capture), with the limits already running from the bind;
  a failed open closes every writer this capture began to open, even one
  whose sink failed with `write/invalid-option`, and one close that throws
  does not skip the next; only a writer refused because it was already
  open is left to whoever opened it (final review of ecd23b1). Writers close on every way out:
  when intake ends and the datagram being saved is saved, even while
  nobody reads or the reader is paused, and at the end of the stream,
  `return()` and `throw()`, each after a write in flight. A close failure
  makes the summary an error, or rejects `return()` when the caller
  stopped early. A sink error that is a `TzspSniffError` ends the capture
  with it in the summary; any other is thrown from the iteration, as a
  consumer's own error is (the CLI's closed stdout is one: it stops
  quietly, as in text), unless a writer then fails to close, whose coded
  error is thrown instead, so the CLI exits 1 for a file that is not
  whole; the same holds when stdout closes while the writers open, and
  when the CLI's own write to stdout fails (it leaves its loop normally,
  so the stream's `return()` can report the file). A sink that throws
  instead of rejecting fails the same way, and a sink call still running
  when `close` stops waiting is followed by the sink's one `close` once it
  settles (CodeRabbit on 6065e1c; made a single call in the final review
  of ecd23b1).
- **The header names the file** (`write`), and the summary counts what
  was written (`written`: datagrams and bytes, headers included), so the
  first look says whether the file is worth reading.
- **`--format pcapng` is refused on a terminal** (`cli/binary-to-terminal`,
  exit 2, before the bind), and with `--fields`, `--stats` or `--detail`
  (`cli/flag-conflict`): none of them changes a capture file, so they are
  refused rather than ignored. Its header, warnings, tips and summary go to
  stderr as text. `--write -` is refused with a fix naming it, and so is
  a `--write` path that is the file stdout or stderr is redirected to
  (`cli/write-to-output`, by device and inode, whatever the target is: a
  file, a FIFO or a device), since both would write the same inode.

**Requirement, file lifecycle:** the file is created exclusively (an
existing file is an error naming `--overwrite`), with owner-only
permissions where the OS supports them, because captures can hold
credentials and private traffic. Blocks are flushed as they are written,
so a SIGINT leaves a valid file up to the last whole block. A write or
close failure (disk full) ends the capture with a coded error and a
non-zero exit, even if packets were already printed. The examples use a
path in the working directory, not a shared `/tmp`.

How it is met (`src/file.ts`): created with `O_CREAT|O_EXCL` and mode
0600 (`write/exists` when it is there). `--overwrite` never opens the old
file: it refuses anything at the path that is not a regular file (a
symbolic link, a directory, a pipe, a device: `write/failed`), creates a
new 0600 file beside it with `O_EXCL` (a short random name, not derived
from the file's, so a name near the 255-byte limit still works), and
renames it over the old one before the first block. A process that had the old file open keeps
reading the old inode and never sees the capture, and a pipe cannot block
the open (cross-review of 52e53d5: changing the mode does not revoke a
descriptor opened before, and `O_NOFOLLOW` is missing on Windows). Each
block goes to the OS with its own `write()`, with no buffer in the
process, so whatever the capture handed over survives the process; the
file is not `fsync`ed. A block the OS takes only part of (a full disk, a
file size limit: `EFBIG` in the final review of ecd23b1) is cut off with
`ftruncate`, so the file ends at the last whole block. Nothing touches the disk until the ports are bound.
On Windows the mode is only the read-only bit, and the rename replaces the
old file there too, except while another process holds it open: Windows
refuses that rename (`EPERM` on windows-latest, Bun 1.4.4, CI run
44650284299), so `--overwrite` fails with `write/failed` and the old file
is left as it was.

### `decode` input

**Requirement.** `decode` reads a pcapng or pcap file, or stdin. The format
is detected from the first bytes (the pcapng section header, a pcap magic
number), or set with `--input pcapng|pcap|hex`; `hex` (one datagram per
line) is never guessed. The link type decides what a record holds:
`LINKTYPE_TZSP` is a datagram (our files), Ethernet is an inner frame (a
file RouterOS saved, which has no TZSP peer or listener label: those fields
are absent, not invented), and IP or Ethernet captures of UDP to the TZSP
port are unwrapped to the datagram. Other link types are refused with a
code. Input size is bounded before allocation: a hex line and a declared
block length over the limit are errors, not allocations. The file
`/tool/sniffer` saved with `file-name=tzsp-lab-capture` (no extension) on
a one-NIC CHR, 7.24.6 and 7.25.1 x86_64, is pcapng: little-endian, two
Ethernet interfaces named `ether1 rx` and `ether1 tx` (one per
direction), nanosecond timestamps, and a `cpu:0 fp:0` comment on each
packet (#5; fixtures in `test/fixtures/routeros/`). MikroTik's
[Packet Sniffer](https://help.mikrotik.com/docs/spaces/ROS/pages/8323088/Packet%20Sniffer)
page dates pcapng from 7.20. Unlike TZSP, such a file does carry an
interface, a direction and the router's time.

**Decided, `decode`** (maintainer, slice 5, 2026-11-19; recorded on #14):

- **Unwrapping is per packet.** A frame that is UDP to a TZSP port is
  unwrapped to its datagram, with the IP source and UDP source port as its
  peer and the port as its listener, as `listen` labels a port; any other
  Ethernet frame is an inner frame. The ports are 37008 unless the
  decode-only, repeatable `--tzsp-port` names others, so one port per
  router stays apart. Link types read: TZSP (128), Ethernet (1), raw IP
  (101), IPv4 (228), IPv6 (229), Linux cooked SLL (113) and SLL2 (276),
  which `tshark -i any` writes. A packet in an IP or cooked capture that is
  not UDP to a TZSP port has no frame to dissect: it is an `unsupported`
  record, `link/not-tzsp`. IP fragments are not reassembled (BACKLOG.md):
  a first fragment unwraps to a datagram cut short, a later one is not UDP.
- **`--write` and `--format pcapng` are refused under `decode`**
  (`cli/wrong-command`, naming `listen`). Filtering a TZSP file down to a
  smaller one is in BACKLOG.md.
- **A file's own metadata is kept**: records gain `interface` (the
  interface block's name, for link types other than TZSP) at `summary`
  detail and `comment` (the packet block's comments, other than a peer) at
  `layers`; both are `--fields` names under `decode`, and refused under
  `listen`, whose records never have them. `time` is the file's timestamp. No
  filter reads the interface yet (BACKLOG.md).
- **Bad files**: a corrupt structure (a block length over the cap,
  not a multiple of 4 or disagreeing with its trailer; a packet block
  naming an interface the section lacks or holding less than it says; a
  section header with no byte-order magic; a hex line that is not hex)
  ends the stream after the records before it, with a summary whose status
  is `error` and code `decode/malformed` (exit 1). An input that ends inside
  a block warns `decode/truncated`, and the summary is `incomplete` (exit
  0 unless `--expect` fails): every packet before it was whole, and a file
  still being written looks like this. Caps: 1 MiB per pcapng block or
  pcap record (`MAX_BLOCK_BYTES`), 128 KiB per hex line (`MAX_HEX_LINE`),
  checked before anything is allocated for them.

How it is met (`src/input.ts`, `src/decode.ts`; where #14 left a choice
open, it was made in the slice, and each is tested in
`test/unit/decode.test.ts`):

- **Records are made from an `Entry`**: a datagram with its TZSP parse,
  or a bare frame, plus whatever the source says (time, listener, peer,
  interface, comment). A listener's `Capture` is one, so `packetRecord()`,
  `datagramRecord()`, filters and `summarize()` serve both commands. A
  field the input does not have is absent: a file RouterOS saved has no
  listener or peer, a hex line no time. At `full` detail `datagram` is the
  bytes the layers' offsets index: the TZSP datagram, or the frame when
  there is no TZSP.
- **Our own files decode to what was printed.** A TZSP packet's interface
  name is the listener label and a `peer=<address>:<port>` comment the
  peer; any other comment stays a `comment`. `seq` is the position in the
  input, so a capture with no drops round-trips exactly (a unit test
  through `openCapture` with a writer, and one through the CLI with
  `--write`, compare the records at `full`).
- **The stream**: a `decode` header (`command`, `input` with its name and
  format, `tzspPorts`, `limits` with `count` and `expect`, filters,
  detail); a `listen` header carries `command: "listen"` too. `stoppedBy`
  is `end` when the input was read to its end; `durationMs` is the span of
  the input's timestamps; `dropped`, `unread` and `unsaved` stay 0. An
  input with no packets warns `decode/empty`; `capture/no-frames` and
  `capture/all-filtered` keep their meaning. Senders count entries that
  name a listener or a peer.
- **Input is pulled a block at a time** (`ByteReader`), so stdin and large
  files hold one block plus one chunk, besides the section's interfaces
  (below). Chunks from an iterable are copied, since a source may reuse
  its buffer, into plain `Uint8Array`s (`Buffer#slice` is a view), 64 KiB
  at a time as the reader needs them; the source is asked for its next
  chunk only once this one is used up, so one huge chunk costs what a
  block or a line needs, not its size. Used chunks are released as they
  are passed. A `Uint8Array` input is read in place. A hex line is
  scanned once however it is chunked, and no further than the cap plus
  its newline, so a huge buffer with no newline is not searched whole.
  `--count` and an early stop close the input. An abort ends a read
  waiting on the input, whatever the pull returned (a promise from
  another realm, any thenable), also when the source aborts from inside
  `next()`, also when that pull settled as the signal fired (a chunk
  or the end), and also when the source rejects the pull, or a sync
  `next()` throws, because of the abort (final reviews of 5ea61d0 and
  e06fc6a): the stream ends `interrupted` (or `openDecode` rejects,
  during detection, rather than call the input empty). The signal is
  checked before each packet is asked for, so bytes already buffered (a
  bad hex line) cannot turn an abort into `decode/malformed`, and an
  abort seen when the input has ended is `interrupted` too, not `end`;
  a `count` already reached stays the reason. On an abort the source's
  `return()` is called but not awaited, during detection too, and with
  no pull running (a caller that aborts before reading a record still
  releases the input). With a pull running, the pull's caller closes the
  reader once `next()` has returned, so a sync generator that aborts
  inside `next()` still runs its `finally`; buffered bytes are not
  dropped on an abort, so a read under way is never reported as cut
  short. The iterator is made before the reader listens on the signal,
  and an abort while it is made rejects `openDecode`. A wait on
  `return()` that began before the abort ends at the abort too, in the
  reader and the stdin adapter, and after the input's end that makes
  the stream `interrupted` (a `count` reached stays the reason; final
  reviews of 5ea61d0 and e06fc6a). The reader stops a waiting pull with
  its own signal, fired by the caller's abort and by `close()`, so
  closing a decode (`return()`) settles while a read waits on a quiet
  input, with no signal given too. An abort keeps its reason as given
  (`null` too), also when it comes as the format is told or as the
  iterator is made; a buffered bad record parsed as the signal fires is
  the interrupt, not `decode/malformed`; and an interrupted stream never
  warns `decode/empty`, `capture/no-frames` or `capture/all-filtered`,
  since it has not seen all the input holds (final review of 888b9b5).
  A source
  slow to clean up cannot hold the summary, and an async generator
  queues `return()` behind a read still pending. The CLI's stdin adapter destroys the
  stream there, so Ctrl-C ends `decode -` while the producer still holds
  the pipe open (`bin.test.ts` under Bun, `test/node/` under Node;
  cross-review of 7d0d428); a stdin with no `destroy()` (an async
  generator, in tests) has its `return()` called instead (CodeRabbit
  review of 64ff141), awaited only on a normal stop with no read pending,
  and a throw from it is dropped (final review of 71d400c).
  Options, and an input whose first bytes name no format, are refused
  before the first record (`decode/invalid-option`,
  `decode/unknown-format`, whose fix names `--input hex` when the bytes
  look like hex); a file that cannot be opened is `decode/read-failed`
  (exit 1), as is a read that fails part way.
- **A path must be a regular file.** A `FileHandle` read on a named pipe
  or a device cannot be cancelled, so Ctrl-C printed the interrupted
  summary and then waited for the producer to close the pipe (final
  review of 71d400c, on Node with a FIFO held open). The file is opened
  non-blocking (`O_NONBLOCK` where the platform has it), so a FIFO opens
  without waiting for a writer, and the kind is checked on the open
  descriptor, not the path, so nothing can swap the path between the
  check and the read (CodeQL `js/file-system-race` on f3e1d01); anything
  else is `decode/read-failed`, whose fix says to
  pipe it to `decode -`, where stdin is a stream that can be destroyed.
  Reading a FIFO through a cancellable stream is in BACKLOG.md.
- **pcapng** is read in either byte order, with new sections resetting
  the interfaces; enhanced, simple and obsolete packet blocks are read,
  other blocks skipped by their length. A section that declares its
  length is held to it: a block crossing its end, or a section header
  that does not start there, is malformed, and an input that ends before
  it is cut short; a declared length that is not a multiple of 4
  (whole blocks) is malformed (Copilot review of 10ada3c). A section
  holds at most 4,096 interfaces with 1 MiB of names (`MAX_INTERFACES`, `MAX_INTERFACE_NAME_BYTES`), since they are
  kept until it ends. A simple packet block must hold its original length,
  cut to the snap length, padded (computed without a 32-bit mask, which
  wraps a length near 2^32 to 0), and nothing else; an enhanced or
  obsolete one may not capture more than its interface's snap length,
  when that is set (0 is no limit, and the writer's files use 0).
  A captured length over the packet's original length is read as
  captured, not refused: libpcap keeps such a record (tcpdump 4.99.7 on
  libpcap 1.11.0 prints `[Invalid header: len(33) < caplen(34)]` and reads
  the next), so one contradictory packet does not end the decode (final
  review of 5ea61d0, which undid 5ea61d0's refusal). The same holds for
  pcap. Timestamps apply `if_tsresol` (both bases) and the signed `if_tsoffset`
  exactly, in BigInt; the exact time is checked against what a Date holds
  before it rounds down to the ms, so both ends hold and a time a
  microsecond past either is malformed. Names and comments keep a leading U+FEFF, so a label round
  trips byte for byte. An option list that runs past its block is read up
  to where it stops: options annotate a packet that is still whole.
- **pcap** in either byte order, microsecond or nanosecond, version 2
  only; the magic number is checked also under `--input pcap`. A record
  over the header's snap length (when it sets one), or over 1 MiB with its
  16-byte header, is malformed. The link type is the low 16 bits of the
  header's field. The fraction is rounded down to the ms before the
  seconds are added: in the sum, 999,999 ns would round up a ms. A
  fraction of a whole second or more (1e9 ns, 1e6 µs) is malformed,
  rather than moving the time on by a second.
- **A UDP header marked malformed is not unwrapped** (its length
  contradicts the packet, so its payload cannot be trusted): an Ethernet
  frame is reported as it is, with its `udp/length` problem, and a raw IP
  or cooked packet is `link/not-tzsp`. A payload cut short (a snap length,
  a first fragment) is still unwrapped.
- **A live capture's records keep their types**: `openCapture()` yields
  `CaptureRecord`, whose packets and records always have `time` and
  `listener`, and whose summary's sender rows always have both; only
  `decode`'s types make them optional (`test/unit/types.test.ts`, checked
  by `tsc`).

### Filters

**Requirement.** Simple and flag-shaped rather than BPF: `--proto`,
`--host`, `--net`, `--port-match`, `--mac`, `--ether-type`, `--sender`.

- Repeating a flag ORs its values; different flags AND.
- `--not-<flag>` excludes packets that have that field with that value. A
  packet without the field (no ports on an ARP frame, a later IP fragment,
  a truncated header) does not match a positive filter and is not excluded
  by a negated one.
- `--host`, `--net`, `--mac` and `--port-match` match either endpoint;
  `--src-` and `--dst-` forms fix the direction.
- `--proto` matches any layer in the packet's protocol chain (`tcp`, `ipv6`,
  `mndp`).
- `--sender` matches the outer UDP peer or the listener label, never a
  field inside the captured packet.

**Decided, filters** (second slice, 2026-11-19; `src/filter.ts`):

- **Filters select frames.** Control, unsupported and invalid TZSP records
  are not frames: no filter applies to them, and they are still reported, so
  a router problem is not hidden by `--proto tcp`. `filtered` counts the
  frames removed. Applying `--sender` to those records too is in
  BACKLOG.md.
- **A negated term is the plain negation of the positive one**, and a
  packet without the field never matches. That gives the rule above:
  `--port-match 22` drops an ARP frame, a later IP fragment and a TCP header
  cut short, and `--not-port-match 22` keeps them. Unit vectors cover each.
- **`--proto` also matches the protocol the IP header names**, so `--proto
  ospf` or `gre` works before a dissector for it exists, and a later
  fragment of a TCP datagram matches `--proto tcp`. Names are the dissector's
  layers (`data` excluded) and the IP protocols it names; any other is
  refused.
- **Values are checked once**, when the filter is made: an unknown term or
  a value that does not parse is `filter/invalid-value`, naming the flag, and
  the CLI exits 2 before any socket opens. Matching never throws.
- **Values have one canonical form**: addresses in RFC 5952 or dotted form,
  a prefix with its host bits cleared, a lowercase colon MAC, a four-digit
  EtherType, a port as a number. A `--sender` value is kept as given, since
  a label matches exactly; its address, if it is one, is compared parsed. The header's `filters` is that canonical
  spec (`{}` for none), and the text start line lists it as flags
  (`keeping --proto tcp --not-host 10.0.0.1`), each value one POSIX shell
  word, quoted when it is not one (a library label such as `'router west'`),
  and joined with `=` when it starts with `-` (`--sender=--help`, which
  `--help` dispatch does not see). Such a flag pastes back into the CLI
  when the CLI takes its value; a library-only label (a space, a comma,
  edge whitespace) shows as a quoted display of the spec.
- **A comma list is the same as repeating the flag** (`--proto tcp,udp`),
  since agents try both.
- **`--sender` takes a label, an address or `address:port`.** A peer
  reported as IPv4-mapped IPv6 (a listener bound to `::`) matches its IPv4
  address. A value that is both a label and an address matches either. The
  library takes any label `listen()` does; the CLI refuses a value that is
  neither `--port`'s label grammar nor an address, as a typo.
- **`--proto` also matches an IPv6 extension that is a protocol** (`ah`),
  and the IP protocol number the header names when what follows is
  malformed or cut short (an AH header too short), which leaves no name.
- **`--host` and `--net` read the IP header and ARP's sender and target
  addresses**, as tcpdump's `host` does; `--mac` reads the Ethernet header.
- **The summary's tables follow the filters**: protocols, problems and
  conversations count the packets reported; senders count every datagram
  the capture read, filtered frames and non-frame records included (not
  dropped or unread ones), so it still shows who sent what was filtered out.
- **`capture/all-filtered` needs every frame read.** With datagrams dropped
  or unread, one of them might have matched, so the loss is the empty case
  (`capture/dropped`, `capture/unread`, which then says how many frames the
  filters removed), and `--expect` names that case, not the filters.

### `setup`

**Requirement.** `setup` prints RouterOS commands that send to this
listener, for `/tool/sniffer` (the default) or `--mangle` (`sniff-tzsp`,
with `--chain`).

- **Destination**: `--quickchr` uses 10.0.2.2 and the listener's port. Otherwise
  it uses `--target <address>`; without one it lists the host's candidate
  addresses and asks for `--target`, because it cannot know which one the
  router reaches. One block of commands per listener port, labelled.
- **Values are quoted** for RouterOS, and every block has its matching stop
  or remove command, printed with it.
- **Filter translation is limited to flags with a proven router
  equivalent**, one AND-ed rule or one sniffer setting each. `--sender`,
  application protocols, negations and OR lists that would need several
  overlapping mangle rules (which could mirror a packet twice) are refused
  with a code that says to filter on the host instead. Which flags translate
  is decided by CHR tests of both senders, not by matching names (#8). #5 did
  not test translation; it saw that `filter-operator-between-entries`
  defaults to `or`, and that with `and`, `filter-ip-protocol=icmp,udp`
  streamed nothing.
- **Decided: `setup` does not force `filter-stream=yes`** (maintainer,
  2026-11-19). #5 saw it default to `no`, and with `no` and a UDP filter the
  sniffer captured its own stream. `--help`, and `setup`'s output when a
  filter could match the stream, explain `filter-stream` and the filtering
  options instead of setting it silently.
- A broad mangle rule must not match its own TZSP output; `setup` adds the
  exclusion. In #5 (7.24.6 and 7.25.1 x86_64), an `output` rule matching
  UDP to the sniff target counted none of the TZSP datagrams another rule
  sent there; a `postrouting` rule counted them, and the sniffer's stream,
  and no further copy arrived. Only rules whose target was that same
  address and port were tested; why no copy arrives is #9.

## Dissectors

**Requirement.** A dissector is a pure function from bytes to one layer:
named fields, the next protocol to try, the layer's span, and a problem
(`truncated`, `malformed` or `unsupported`) when it cannot finish. It never
throws and keeps the bytes, so an unknown field can still be read and a
record can be decoded again after the dissector improves. A registry
dispatches on EtherType, IP protocol and UDP or TCP port, with a heuristic
hook for protocols on unusual ports.

Untrusted input, so the contract is enforced, not hoped for:

- a child span lies within its parent's declared length (an IPv4 total
  length shorter than the frame trims the frame; a longer one is
  `truncated`);
- every loop advances by at least one byte or stops;
- caps on work per packet: tags, IPv6 extension headers, nested tunnels
  and layers each have a maximum, and hitting one is `unsupported`;
- IP fragments: the first is dissected to its transport header, later ones
  are marked fragments and not dissected further; no reassembly;
- vectors in unit tests for each truncation and malformation, asserting both
  the problem and the preserved bytes.

**Decided: a dissector registry** (maintainer, slice 6, 2026-11-20, on
issue #15; built in #25). Each protocol is a module under `src/dissect/` that
exports a registration: its `protocol` (the layer name in records and the
name `--proto` takes), a name and reference, how it is reached (the frame's
link type, an EtherType, an IP protocol), the function that reads it there,
and its fields. `src/dissect/registry.ts` lists the registrations and
builds the dispatch tables from their matches, and a layer reaches the
next one only through them; `dissectors()`, the `dissectors` command and
`FILTER_PROTOCOLS` read the same list. The alternative, declarations kept
beside the hand-written switches with tests to hold them together, was
smaller but left two lists to drift; a registry is what DESIGN.md asked for
from the start, and the dissectors after 0.1.0 (DNS, DHCP, OSPF …) each
become a module and a line.

- **Fields are declared against the fields interface.** A declaration is
  keyed by the interface's keys (`FieldDecls<F>`), so a field added to the
  interface and not declared, a wrong type, a wrong `optional`, a list item
  missing a field or a list of anything but strings or objects does not
  compile (`test/unit/registry.test.ts` holds that with `@ts-expect-error`
  cases). A declared key not in the interface is caught by TypeScript's
  excess-property check only in an object literal written in place, not one
  spread in or passed as a variable (cross-review of 043ac64); the run-time
  check below catches it, since no vector produces such a field. At run
  time, every field a vector in `test/unit/dissect.test.ts` produces must be
  declared with its type, every declared field must be produced by one, and
  every layer and list item a vector produces must carry each field not
  declared optional: the first run found ICMP (v4) declared with ICMPv6's
  neighbor-discovery target.
- **Each match is checked by dispatch**: a minimal frame per declared
  EtherType (under Ethernet and a VLAN tag) and per IP protocol (in IPv4
  and IPv6) reaches the dissector that declares it; every other EtherType
  and IP protocol is `data`; no match is claimed twice.
- **Not built until a dissector needs them:** matches on a UDP or TCP port,
  and the heuristic hook for protocols on unusual ports. No 0.1.0 dissector
  is reached either way. #25 as filed had the registry accept a port match;
  the maintainer agreed to leave it out (2026-11-20, on PR #27), so it comes
  with its first user, DNS or DHCP after 0.1.0 (BACKLOG.md).
- **How port matches fit, when they come.** The additions: `udpPort` and
  `tcpPort` variants of `Match` and `DissectorMatch`, two dispatch maps,
  and, where UDP and TCP now pass their payload to a `data` layer, a lookup
  by port, as IP looks up by protocol number. The duplicate guard,
  `dissectors()` and its text already take any match kind, and no existing
  dissector changes. The one contract that changes: today a dissector the
  registry picks always takes the bytes, which suits EtherTypes and IP
  protocol numbers. A port is a convention (a port two protocols share, DNS
  on UDP and TCP, other traffic on a well-known port), so a dissector
  reached by port, or by the heuristic hook on a broader scope than a port,
  may need to decline: an optional check on its match, and the layers a
  declined attempt pushed dropped. Kept apart from this registry until a
  dissector needs it, as the matches are now. Open until then: which port
  is tried first, what counts as a clash when declining is allowed, a TCP
  segment that does not start a message, and a first IP fragment, which
  dispatches with its payload cut short.
- **`dissectors` prints text or JSONL**, one `dissector` record per
  protocol with no `header` or `summary`: it is a fixed list, not a
  capture, so it has no stream to frame. `--format json` is refused as on
  `listen` (see "Decided: JSONL, no `--format json`"); #15's "Done when"
  had listed it by mistake.
- The `data` layer and TZSP itself are not listed: `data` is bytes no
  dissector reads, and TZSP is the record around the frame, read by
  `parseTzsp`.

**Decided: LLDP as named fields** (#26; maintainer, 2026-11-20). What
RouterOS sends is in test/lab/lldp/REPORT.md (7.25.1 and 7.24.6 x86_64,
7.25.1 arm64 CHRs).

- **Named fields, not a TLV list.** Each basic TLV is a field of its own
  (`chassisId`, `portId`, `ttl`, `systemName` …), so `jq` reaches it by
  name in `--detail layers` records (`--fields` picks packet record fields,
  not layer fields); management addresses are a list. Every other TLV goes
  in `otherTlvs` as type, length and hex, an organizationally specific one
  with its OUI and subtype, named for IEEE 802.1, IEEE 802.3 and LLDP-MED
  (TIA-1057). LLDP-MED and the 802.1 and 802.3 TLVs are not decoded further.
  The order of TLVs on the wire is not kept.
- **Repeats follow the standard's words.** Chassis id, port id and TTL
  "shall" appear exactly once, first and in that order: out of order is
  `malformed` (`order`), a second one `malformed` (`repeated`). Port
  description, system name, system description and capabilities "should
  not" appear more than once (802.1AB-2005, each TLV's clause), so a second
  is kept raw in `otherTlvs` and is not a problem; the first is the field.
  The maintainer had first chosen `malformed` for these too, before the
  wording was checked.
- **Problems.** A TLV header or value past the frame is `truncated`
  (`tlv`); bytes that end with no End TLV are `truncated` (`end`); a TLV
  whose length is wrong for its type (an End with a value, a MAC id other
  than 6 bytes, an address other than its family's length) is `malformed`
  (`tlv-length`) and kept raw; an id subtype or string TLV that is not UTF-8 is `malformed`
  (`text`), read with replacement characters; a management address OID that
  does not parse is `malformed` (`oid`). Two "shall" rules of 802.1AB-2009:
  a capability enabled but not supported makes the TLV one to discard
  (8.5.8.3), so it is `malformed` (`capabilities`) and kept raw; unknown
  interface numbering with a number other than 0 (8.5.9.6) is `malformed`
  (`interface-number`), the address still listed. After 64 TLVs (`MAX_LLDP_TLVS`;
  RouterOS sends 11 to 14) the layer is `unsupported` (`tlv-limit`).
- **The layer ends at End.** Bytes after it are not LLDP's and get no
  layer, as Ethernet padding after ARP or IPv4 gets none.
- **Text is UTF-8.** RouterOS sends a system identity of `lab-café` as
  UTF-8 (the lab's `identity-utf8`), so UTF-8 is checked rather than ASCII.
- **Sources.** Types, subtypes, capability bits and organizationally
  specific subtypes are from IEEE 802.1AB, IEEE 802.1Q Annex D, IEEE 802.3
  clause 79 and TIA-1057, checked against Wireshark's
  `epan/dissectors/packet-lldp.c` at ffc784d8541a (numbers only).

**Decided: one packet at a time; no TCP stream reassembly yet.** TCP can
split a length prefix across segments or carry several messages in one,
and WinBox adds its own chunking above TCP (m2ir
`profiles/winbox-ipc/transport.yaml`). A per-packet dissector can decode an
application message only when it starts at the start of a segment and fits
in it; anything else is reported as TCP payload. A per-direction flow layer
(gaps, retransmission, joining mid-stream, eviction) is a separate design
before WinBox, CMR or BGP message decoding goes past that.

**Proposed order**, by what RouterOS work needs first:

1. TZSP records, Ethernet and 802.1Q, ARP, IPv4, IPv6 (extension headers,
   capped), ICMP and ICMPv6, UDP, TCP (flags, sequence numbers), LLDP.
2. DNS, DHCP, OSPF, VRRP, BGP message headers (per packet), GRE and EoIP.
3. RouterOS protocols, routed through routeros-proprietary-protocols: the
   MAC-Telnet and MAC-WinBox header (UDP 20561), RoMON (EtherType 0x88bf),
   bandwidth test (TCP 2000), CMR (TCP 54321, framing only), and WinBox
   `nv::message` (TCP 8291) from m2ir's `physical/nv-message.yaml`, per
   packet as above, plaintext sessions only.
4. MNDP (UDP 5678). Later than its size suggests: centrs already listens for
   MNDP. It starts as raw TLVs named from m2ir's grounded wire map
   (`work/2026-11-mndp-grounding/`), with every TLV's bytes kept; it moves
   to generated tables when m2ir's MNDP profile has canonical YAML, and does
   not wait for quickchr.

**Tables from m2ir, not by hand.** Where m2ir has a schema, field names and
enums are generated from its YAML (tikoci-data-contracts). m2ir's dissector
proposal asks for this: "Generate semantic tables from YAML and keep
Wireshark stream handling in the consumer." A finding made here goes back
to m2ir as evidence, not into a second catalog. **Requirement:**

- the input is a vendored snapshot of the m2ir files used, with the m2ir
  commit, in one directory; generation and its `--check` run offline from
  that snapshot, and refreshing it is a separate, networked command and a
  reviewed change;
- generated tables keep m2ir's scope and confidence: a field scoped to a
  handler or RouterOS version is labelled that way, and an unconfirmed
  meaning is not presented as fact;
- **Unverified, licensing:** m2ir's README says its schema content is
  CC0-1.0, but the repo has no LICENSE file (GitHub's license API returns
  404). Nothing is generated from m2ir until it has one (BACKLOG.md).

## Decided: no embedded Lua or Wireshark

The question was whether to run Wireshark's Lua dissectors (through Lua over
FFI) for full coverage instead of writing TypeScript ones. No:

- **A Wireshark Lua dissector is not portable Lua.** It is written against
  Wireshark's own API (`Proto`, `ProtoField`, `Tvb`, `TreeItem`, dissector
  tables, reassembly, preferences), which is C in `epan`. A Lua VM alone runs
  none of it; we would be hosting or rewriting that API.
- **Wireshark's coverage is mostly C**, not Lua, so even a perfect Lua host
  would not bring Wireshark's coverage.
- **FFI does not reach the runtime floor.** `bun:ffi` is Bun-only, and
  Node's `node:ffi` is experimental and new in Node 26.1, far above the
  Node 22 floor; it would also need native Lua and Wireshark libraries on
  every user's machine.
- **Licensing.** Wireshark and most of its dissectors are GPL-2.0-or-later;
  this package is MIT. Protocol numbers are facts and are cited; code is not
  copied.

Wireshark's dissectors are still reachable with no root and no FFI, by
handing it a finished capture:

```sh
tzsp-sniff --duration 30s --format pcapng > capture.pcapng
tshark -r capture.pcapng -T json
```

Reading a file needs no capture privileges. TShark can also read a pipe
(`-r -`), but then cannot make two passes. A Lua plugin works only in a
Wireshark build with Lua and the plugin installed, and the Cisco-Talos
WinBox dissector covers non-secure sessions only. **Unverified**: the exact
commands above, as a non-root user, against our pcapng (see `--write`),
asserting an inner field; a test pins the TShark version it ran.

Our own dissectors are TypeScript: typed results for the library, fields
chosen for agents, tests on captured RouterOS bytes, and no dependency. A
RouterOS protocol described in m2ir YAML can feed both a TypeScript dissector
here and a Lua one for Wireshark, which keeps the knowledge neutral without
embedding either in the other.

## Decided: Node and `npx`

Shipped code runs on Node 22 or later and on Bun, so both `npx
@tikoci/tzsp-sniff` and `bunx @tikoci/tzsp-sniff` work, and a Node project
can import it. This is tikoci-toolchain's "Node only where shipped code runs
on Node" case:

- `src/` uses `node:dgram`, `Uint8Array` and `DataView`, and no `Bun.*` or
  `bun:*` import; `tsconfig.src.json` type-checks it with Node's types only,
  so a Bun call fails `bun run lint`.
- `bun run build` writes `dist/` (`bun build --target node` plus `tsc`
  declarations); the package exports only `dist/`.
- `test/smoke/node-smoke.mjs` loads `dist/` under Node, in CI on Node 22 and
  the current LTS.
- Bun still runs everything else: tests, scripts, the build, CI.

**Launcher and runtime are different things.** The bin will start
`#!/usr/bin/env node`. `npx` runs it with Node. `bunx` honors a Node
shebang when Node is installed ([Bun docs](https://bun.sh/docs/pm/bunx#shebangs))
and runs it with Bun only with `bunx --bun` or when Node is absent. Node does
not load `.env`; Bun does unless told not to, so the Bun path must not let a
working directory's `.env` set `TZSP_SNIFF_*` (tikoci-toolchain, "A shipped
CLI does not read the working directory's `.env`"). **Requirement**, when the
bin ships: test the packed tarball through `npx` and `bunx` with Node
present and `bunx --bun` with Node absent, asserting the runtime that ran,
the CLI's result, and that a `.env` in the working directory changed
nothing.

The cost is a build step and a `dist/` that must match `src/`; the release
workflow's packed-tarball smoke test (tikoci-release) is what proves it.

## Testing

- **Unit** (`test/unit`, every PR, Linux, macOS and Windows): parsers and
  dissectors on captured RouterOS bytes with their provenance (version,
  architecture, date, capture), malformed and truncated vectors, filters,
  formatters, stream termination, the flag registry and help, and the
  listener's lifecycle cases on loopback with port 0.
- **Node smoke** (`test/smoke`): the built package under Node 22 and the
  current LTS; once the listener ships, also a real UDP round trip on
  loopback under Node, because Bun passing proves nothing about Node's
  sockets.
- **Integration** (`test/integration`, `bun run test:integration`, which
  sets `TZSP_SNIFF_INTEGRATION=1`): boot a CHR with quickchr, arm the sender
  toward the SLIRP gateway on a listener bound to port 0, generate traffic,
  assert the decoded records, and remove the CHR and close the listener in
  `finally`. Results record the RouterOS version and architecture the CHR
  reported. Per tikoci-testing: a `stable` smoke of `/tool/sniffer` and
  mangle on code PRs (a CI job behind lint and unit), and a sweep of the
  active channels nightly and before a release. quickchr is a
  devDependency only.

  What it checks (`test/integration/capture.test.ts`, one CHR for the
  file): `/tool/sniffer` streaming ICMP read through `openCapture()`, 3
  echo requests and 3 replies as `ethernet`, `ipv4`, `icmp` packets under a
  TZSP v1 `received` Ethernet layer; a mangle `sniff-tzsp` rule on the
  output chain, 2 requests and the rule's counter at 2; and the sniffer
  again through the CLI (`--proto icmp --format jsonl`), exit 0 and the
  same 6 packets. Each capture stops on `count`, so its summary is
  `complete`. Passed on RouterOS 7.25.1 (`stable`) and 7.24.6
  (`long-term`), x86_64 under KVM, quickchr 0.5.6 and 0.6.0, Linux,
  2026-11-19, in about 33 s with a 24 s boot; each check was also seen failing once with
  its expectation swapped.

  `TZSP_SNIFF_ROUTEROS` (a channel or a version, default `stable`) picks
  the router, and `TZSP_SNIFF_INTEGRATION_RESULTS` names a JSON file for
  the results, beside which the machine's QEMU log is copied before
  removal; both are test knobs, which shipped code never reads. Setup
  asserts that the CHR reported a version and an architecture, and that
  the version is the exact one `prefetch` resolved the target to, on every
  run (a channel too). The guest architecture is always
  the host's own, given to quickchr explicitly, so its `default-arch`
  setting cannot turn the boot into cross-architecture emulation; the setup
  and cleanup hooks' timeouts are derived from what quickchr itself may wait
  for, and `afterAll` waits for the setup to settle before it removes the machine. In CI,
  `.github/workflows/integration.yml` owns the QEMU setup: CI's `smoke` job
  calls it with `stable` for any diff that is not docs-only, after lint and
  unit pass, and `sweep.yml` calls it nightly, once per version the active
  channels resolve to (`scripts/sweep-plan.ts`, quickchr's
  `selectActiveChannels`), every leg must-pass. `nightly.yml` calls
  `sweep.yml` on a schedule and files a red run as an issue; the release
  workflow #17 adds is to call `sweep.yml` and publish only if it passes;
  until #17 wires that, the `workflow_call` entry point gates nothing. The issue-writing
  job stays out of `sweep.yml` because a caller must grant every
  permission a reusable workflow's jobs ask for, even a skipped job's.

  **Decided: quickchr through its library** (slice 3, 2026-11-19),
  pinned exact as a devDependency. quickchr 0.5.6 ships TypeScript source
  that this repo's `exactOptionalPropertyTypes` rejected once a test
  imported it, so the first cut drove its CLI (tikoci/quickchr#285).
  quickchr 0.6.0 checks its source under the house tsconfig (its
  `lint:consumer`) and exports its boot budget (`defaultBootTimeout`), so
  `test/chr/quickchr.ts` calls the library. The lab and the integration
  tier share that module, and `scripts/sweep-plan.ts` imports quickchr's
  version helpers directly. The module's rules, which later tests inherit
  (cross-review of ec42e8c, each seen failing against it; quickchr's
  review of 3841326 for the single `start` and the prefetch):

  - **Fetch, then create and boot in one call.** `prefetch` resolves a
    channel to an exact version and caches the image (`cacheAdd`) in a hook
    of its own, and `create` boots that version with one `QuickCHR.start`,
    as quickchr recommends (tikoci/quickchr#296). Creating with `add` and
    booting with `start` had three costs in 0.6.0: `add` printed its image
    lines to stdout (tikoci/quickchr#290), the boot ignored `timeoutExtra`
    (tikoci/quickchr#291), and a second `start` by name could reach a
    machine other than the one `add` made.
  - **Ownership is the name and `createdAt`.** A random `tzsp-it-` or
    `tzsp-lab-` name is checked absent (`QuickCHR.get`, `listOrphans`),
    since `start` would boot a machine that has it, and the `createdAt` of
    the machine `start` returns is recorded. `teardown` and the log copy
    act only on a machine of that name with that `createdAt`, so one made
    by another process under the same name is never removed.
  - **A failed `create` owns nothing.** On a boot timeout quickchr 0.6.0
    removes the machine `start` made (`remove-new`, its full `qemu.log`
    kept under `<data dir>/failures/`), before state is saved it removes
    the directory it made, and a failure before the claim
    (`MACHINE_EXISTS`, `MACHINE_LOCKED`) made nothing of this process's. A
    leftover is reported, never removed. One gap is quickchr's: a failure
    after QEMU is spawned and before the state is first saved deletes the
    directory and leaves QEMU running (tikoci/quickchr#298). `create` then
    looks for a QEMU whose command line names `/machines/<name>/`
    (`pgrep`), and reports it with its pid in the error and in
    `cleanupAll`'s leftovers, so the run fails rather than hiding it
    (final cross-review of 90c4d98, seen with the state write forced to
    fail).
  - **Unreadable state is reported, not removed**: its QEMU may still run,
    and only `quickchr remove <name>` should decide. A failed removal is
    not remembered, so a later `cleanupAll` tries again.
  - **After a signal, nothing new starts.** `prefetch` and `create` check
    `stopping`; a quickchr call already running cannot be interrupted, so
    `cleanupAll` waits for every `create` in flight first.
  - **Stated, not inherited, options**: the factory admin login
    (`secureLogin: false`, whatever the user's quickchr settings say) and a
    qcow2 boot disk, as the quickchr CLI makes and the lab's evidence was
    taken on (the library's default is raw).
  - **Budgets.** `prefetchBudget`: three channel lookups, then three
    download attempts of up to 15 min each. `createBudget`: the allocator
    lock (60 s), the boot budget, and the boot-failure report
    (`BOOT_FORENSICS_BUDGET_MS`, 180 s, deep diagnostics included) with
    the stop after it. The boot budget is quickchr's exported `defaultBootTimeout`,
    the larger of one TCG attempt and two accelerated ones (under KVM or
    HVF a missed boot starts QEMU once more). `teardownBudget`: the boot
    budget for the machine lock, then stopping QEMU. Only the boot budget
    is exported; the rest are quoted from quickchr's source by file, until
    quickchr owns the sum (tikoci/quickchr#292). No `timeoutExtra`:
    quickchr's own budget is the one relied on.

  **A local run uses the developer's quickchr data directory.** quickchr
  keeps its image cache inside it and has no separate cache setting, so an
  isolated `QUICKCHR_DATA_DIR` would download the image on every run. The
  tier only touches machines it created, under the `tzsp-it-` prefix, and
  removes them in `afterAll`. The name goes to stderr before `start`
  (`machine: tzsp-it-…`), so a run killed later says what it left;
  `quickchr list <name>` reports it, and `quickchr remove <name>` clears
  it. A kill before quickchr saved its state leaves a directory with no
  readable state, and its QEMU may run: stop that QEMU first
  (`pgrep -af "qemu-system.*/machines/<name>/"`), since `remove` deletes
  such a directory without stopping it (tikoci/quickchr#294). CI sets
  `QUICKCHR_DATA_DIR` under the runner's temp directory.
- **TShark** (`test/tshark`, `bun run test:tshark`, which sets
  `TZSP_SNIFF_TSHARK=1`): TShark reads a pcapng that `pcapngWriter` and
  `fileSink` made, as a non-root user, and the test checks the link type,
  an inner field, the interface name, the peer comment and the time. It
  fails rather than skips when `tshark` is missing, and fails on any
  version but `TZSP_SNIFF_TSHARK_VERSION` when that is set. CI's `tshark`
  job runs it on `ubuntu-24.04` with the archive's TShark, pinned to
  4.2.2; locally, any TShark on `PATH` (a Docker image of Ubuntu 24.04
  gives CI's).
- **Fixtures** are small and sanitized, as hex in tests or capture files
  under `test/fixtures/` with a README saying where each came from.

## Open questions

- Which `setup` filters translate to each sender (#8): #5 grounded the
  senders' framing, not the filters. Each flag needs its own CHR test of
  both senders before it translates; #5 saw `filter-operator-between-entries`
  default to `or`, and `and` with `filter-ip-protocol=icmp,udp` stream
  nothing.
