<!-- cspell:ignore Tvb epan usr recvfrom libuv EPB IDB LINKTYPE WTAP ENCAP winbox ipc -- Wireshark, pcapng and system names -->

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
createFilter(spec): (capture: Capture) => boolean
pcapngWriter(sink): CaptureWriter                        // streaming, with backpressure
snifferCommands(options): string[]                       // RouterOS lines for /tool/sniffer or mangle
dissectors(): DissectorInfo[]                            // what can be decoded
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
| `dissectors` | list protocols, how each is matched (EtherType, IP protocol, port) and its fields |

**Decided: `listen` is the default command**, so `tzsp-sniff --count 10`
works, which is what an agent guesses; `--help` lists `listen` and says it is
the default.

**Requirement, flags:**

- One registry declares each flag's arity, the commands it applies to, and
  the flags it conflicts with. A flag given to a command it does not apply to
  is refused with a code that names where it does apply (tikoci-cli-mcp,
  "Refuse, never drop"): `decode --follow`; `--fields` or `--stats` with
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
capture (`unread`), and packets reported; all but the first add up to it.
The summary also says what stopped the capture (`stoppedBy`: `count`,
`duration`, `idle`, `interrupt` or `error`): whichever
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
| only control, unsupported or malformed records | `capture/no-frames` | `--detail full` to see them |
| frames arrived, filters removed all | `capture/all-filtered` | the filter flags in effect |

**Decided:** `--expect N` turns fewer than N packets reported into exit 1
with error `capture/expect-unmet`, also when the capture ended by SIGINT;
the error carries the same case as the table. Without `--expect`, SIGINT
ends a capture normally (summary written, exit 0).

### Stream termination

**Requirement.** Every JSONL stream starts with a `header` record
(`schemaVersion`, ports, bind address, filters, limits) and, once started,
ends with exactly one `summary` record whose `status` is `complete`,
`interrupted`, `incomplete` (records dropped) or `error`, with the error
code when there is one. Between them: `packet`, `record` (control,
unsupported or malformed), `warning` and `tip`, as they happen. A stream
with no `summary` was cut off (the process was killed or the pipe broke)
and a reader treats it as failed. In text and pcapng formats, warnings, tips, errors and
the summary go to stderr. Tests read each stream to EOF and check the last
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
**Unverified**: that Wireshark and TShark open it this way
(`WTAP_ENCAP_TZSP` is registered in `packet-tzsp.c`) and show the peer
option; checked by a test before the format ships.

**Requirement, file lifecycle:** the file is created exclusively (an
existing file is an error naming `--overwrite`), with owner-only
permissions where the OS supports them, because captures can hold
credentials and private traffic. Blocks are flushed as they are written,
so a SIGINT leaves a valid file up to the last whole block. A write or
close failure (disk full) ends the capture with a coded error and a
non-zero exit, even if packets were already printed. The examples use a
path in the working directory, not a shared `/tmp`.

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
- **Fixtures** are small and sanitized, as hex in tests or capture files
  under `test/fixtures/` with a README saying where each came from.

## Open questions

- Which `setup` filters translate to each sender (#8): #5 grounded the
  senders' framing, not the filters. Each flag needs its own CHR test of
  both senders before it translates; #5 saw `filter-operator-between-entries`
  default to `or`, and `and` with `filter-ip-protocol=icmp,udp` stream
  nothing.
