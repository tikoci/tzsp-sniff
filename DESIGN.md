<!-- cspell:ignore Tvb epan usr recvfrom -- Wireshark and system names used once -->

# Design

Why tzsp-sniff is built the way it is. Status: **proposal**, 2026-11-18,
for review in the first PR; maintainer answers folded in the same day. Decisions that hold are marked **Decided**;
the rest are proposals until that PR merges, and open questions are listed
at the end.

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

Boundaries with other tikoci repos (tikoci-crossref):

| Concern | Owner | Here |
| --- | --- | --- |
| Arming the router (running `/tool/sniffer` commands) | centrs (device access), quickchr (CHRs) | prints the commands and exports a builder for them; never logs in to a router |
| RouterOS binary protocol knowledge | m2ir (YAML schemas) | consumes it: dissector tables generated from m2ir at a pinned commit |
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
           │ UDP to <host>:<port>, TZSP v1, Ethernet encapsulation
host     receiver (node:dgram, one socket per port, unconnected)
           │ { bytes, from: ip:port, port label, arrival time }
         parseTzsp ─→ dissect (Ethernet → IP → TCP/UDP → app) ─→ filter ─→ format
                                                                            │
                                         text · jsonl · json · pcapng ─→ stdout
```

- **Time is host arrival time.** RouterOS sends no timestamp tag (quickchr
  CMR lab, 7.26beta5), so times are accurate to host jitter. A `time-stamp`
  tag, if a sender includes one, is decoded but not trusted over arrival.
- **Which router sent it** comes from the UDP source address, or from the
  port when that is all there is. Under QEMU user-mode networking every guest
  appears as 127.0.0.1, so quickchr's lab uses one port per router (quickchr
  `examples/cmr/README.md`, "Wire capture"). The CLI takes several ports, each
  with an optional label: `--port 37008 --port 37009=router-b`.
- **No interface tag.** RouterOS's TZSP carries no interface name; a frame's
  source MAC is the best capture-point hint, as quickchr's `dedupe()` found.
- **The socket stays unconnected** (`recvfrom`): a connected socket drops the
  datagrams QEMU's SLIRP relays (quickchr `docs/networking-recipes.md`).
- **`reusePort` is off by default, an option to measure.** For MNDP it matters,
  because broadcasts reach every socket bound with it, and centrs sets it
  everywhere but Windows (`defaultMndpReusePort()`). TZSP arrives as unicast,
  and on Linux unicast to a port shared through `SO_REUSEPORT` is expected
  to be spread across the sockets rather than copied, so a second listener
  would take some of the packets without saying so. That needs a test on
  Linux and macOS before it is offered. Node has the `reusePort` option in
  `node:dgram` (it is in `@types/node` 22); which Node versions and
  platforms honor it is to be checked too.
- **quickchr may give TZSP a default port.** quickchr already maps common
  services for a CHR; a pre-assigned TZSP port there (and as the default in our
  `snifferCommands()`) would let `tzsp-sniff --port` and quickchr agree
  without a lookup. That is a quickchr change; until then `setup --quickchr`
  prints what to run.
- **Always closed.** An open dgram socket keeps the process alive; every
  capture ends by count, duration, idle time, a signal or the caller's
  `AbortSignal`, and closes its sockets in `finally`.

## Library

The library never prints or exits (tikoci-cli-mcp, "Layers"). Proposed
exports, all usable from Node and Bun:

```typescript
parseTzsp(datagram: Uint8Array): TzspDatagram          // exists
dissect(frame: Uint8Array, options?): Dissection         // layers, never throws
listen(options): AsyncIterable<Capture>                  // ports, count, duration, idle, signal
createFilter(spec): (capture: Capture) => boolean
summarize(captures): Stats                               // counts per protocol, conversation, sender
toPcapng(captures): Uint8Array                           // or a streaming writer
snifferCommands(options): string[]                       // RouterOS lines for /tool/sniffer or mangle
dissectors(): DissectorInfo[]                            // what can be decoded
```

A TUI, an MCP server or a centrs command is an adapter over these, not a
second implementation.

## CLI

One binary, `tzsp-sniff`, following tikoci-cli-mcp: stdout is the result,
everything else goes to stderr, errors carry a code from one registry.

| Command | Does |
| --- | --- |
| `listen` (the default) | receive and print, until `--count`, `--duration` or `--idle` is met, or forever with `--follow` |
| `decode <file\|->` | the same pipeline over a pcap or pcapng file (ours from `--write`, or one RouterOS saved: pcapng since 7.20) or hex datagrams on stdin; no network |
| `setup` | print the RouterOS commands for this host's addresses and port; `--quickchr` uses the SLIRP gateway 10.0.2.2; `--mangle` for `sniff-tzsp` |
| `dissectors` | list protocols, how each is matched (EtherType, IP protocol, port) and its detail fields |

**Decided: `listen` is the default command**, so `tzsp-sniff --count 10`
works, which is what an agent guesses; `--help` lists `listen` and says it is
the default. Flags come from one registry with declared arity; `--help` is
answered before dispatch. Every flag has a `TZSP_SNIFF_<KEY>` environment variable
(`TZSP_SNIFF_PORT`); a flag wins.

### Output for agents

Three knobs keep answers small, from cheapest to richest:

- `--stats`: no packets, only the summary (counts per protocol, sender and
  conversation, first and last time).
- `--detail line|summary|layers|full`: `line` is one string per packet like
  tcpdump's; `summary` adds the fields an agent filters on (addresses, ports,
  protocol chain, flags, length); `layers` adds every dissector's fields;
  `full` adds the raw bytes as hex.
- `--fields a,b,c`: only the named fields, in that order.

`--format text|jsonl|json|pcapng`. Text is the default, one line per packet,
plain when stdout is not a terminal or `NO_COLOR` is set. `jsonl` is one
record per line and is the streaming form; `json` is one document at the end;
`pcapng` hands the capture to Wireshark or `tshark -r -`.

**Capture now, look later.** `--write <file.pcapng>` saves every datagram as
received, whatever `--format`, `--detail` or the filters print. With
`--stats`, the first look costs a few lines:

```sh
tzsp-sniff --duration 30s --write /tmp/cmr.pcapng --stats
tzsp-sniff decode /tmp/cmr.pcapng --proto tcp --port-match 54321 --detail layers
```

The summary says whether the file is worth reading and which filter to
start with, and `decode` drills in without capturing again, with no `tee`,
`jq` or a script in between. The file keeps the raw bytes, so it can be
decoded again after a dissector improves, or opened in Wireshark.

**Decided: the output shape is this tool's own.** It is not centrs's envelope
(`ok`, `data`, `warnings`, `tips`, `error`), which fits centrs's
explain-retrieve-execute flow. A centrs adapter maps our records to whatever
its `tools` commands return; `tools btest` has the same question there.

Streaming rules (not covered by tikoci-cli-mcp yet; see the road test):

- **JSONL records carry a `type`**: one `header` first (with `schemaVersion`,
  ports and filters in effect), then `packet`, `warning` and `tip` records as
  they happen, and one `summary` last. A reader can stop at any line.
- **A capture that ends with no packets is a read with an empty result**:
  exit 0, a `capture/no-packets` warning, and a tip naming `tzsp-sniff setup`
  (the most common cause is an unarmed router). **Decided:** `--expect N`
  turns fewer than N packets into exit 1, for scripts and tests that need
  traffic; the error then names the router-side checks (is the sniffer
  running, is `streaming-server` this host and port).
- **SIGINT ends a capture normally**: the summary is written, then exit 0.
- **Malformed datagrams are counted and kept**, not dropped: a `problem`
  record at `--detail full`, a count in the summary.

### Filters

Simple and flag-shaped rather than BPF: `--proto`, `--host`, `--net`,
`--port-match`, `--mac`, `--ether-type`, `--sender`. Repeating a flag ORs its
values; different flags AND. `--not-<flag>` negates. The router can already
filter what it sends (`filter-*` properties, mangle matchers), and `setup`
prints those when given the same flags, so filtering at the source is the
first suggestion for heavy traffic.

## Dissectors

A dissector is a pure function from bytes to one layer: named fields, the
next protocol to try, the payload span, and a `problem` when the bytes are
short or malformed. It never throws and always keeps the raw bytes, so an
unknown field can still be read and a record can be decoded again after the
dissector improves. A registry dispatches on EtherType, IP protocol and
UDP or TCP port, with a heuristic hook for protocols on unusual ports.

**Proposed order**, by what RouterOS work needs first:

1. TZSP itself, Ethernet and 802.1Q, ARP, IPv4, IPv6 (extension headers
   followed), ICMP and ICMPv6, UDP, TCP (flags, sequence numbers), LLDP.
2. DNS, DHCP, OSPF, VRRP, BGP headers, GRE and EoIP.
3. RouterOS protocols, routed through routeros-proprietary-protocols: the
   MAC-Telnet and MAC-WinBox header (UDP 20561), RoMON (EtherType 0x88bf),
   bandwidth test (TCP 2000), CMR (TCP 54321, framing only), WinBox M2
   framing and `nv::message` (TCP 8291) from m2ir's `physical/nv-message.yaml`,
   plaintext sessions only.
4. MNDP (UDP 5678). Later than its size suggests: centrs already listens for
   MNDP, and quickchr's CMR lab keeps its own decoder until the next CMR beta.
   When it lands it follows m2ir's grounded wire map and keeps each TLV with its raw
   bytes.

**Tables from m2ir, not by hand.** Where m2ir has a schema, field names and
enums are generated from its YAML at one pinned commit, with a `--check` mode
in the gate, as centrs pins restraml trees (tikoci-data-contracts). m2ir's
dissector proposal asks for exactly this: "Generate semantic tables from YAML
and keep Wireshark stream handling in the consumer." A finding made here goes
back to m2ir as evidence, not into a second catalog.

## Decided: no embedded Lua or Wireshark

The question was whether to run Wireshark's Lua dissectors (through Lua over
FFI) for full coverage instead of writing TypeScript ones. No:

- **A Wireshark Lua dissector is not portable Lua.** It is written against
  Wireshark's own API (`Proto`, `ProtoField`, `Tvb`, `TreeItem`, dissector
  tables, reassembly, preferences), which is C in `epan`. A Lua VM alone runs
  none of it; we would be rewriting that API.
- **Wireshark's coverage is mostly C**, not Lua, so even a perfect Lua host
  would not bring "full coverage".
- **FFI breaks Node.** `bun:ffi` is Bun-only, and the Node equivalent is a
  native addon per platform.
- **Licensing.** Wireshark and most of its dissectors are GPL-2.0-or-later;
  this package is MIT. Protocol numbers are facts and are cited; code is not
  copied.

Full coverage is still one pipe away, with no root and no FFI:
`tzsp-sniff listen --format pcapng | tshark -r - -T json`. Only live capture
needs privileges, not reading a file or pipe. That path also runs Lua
plugins, such as the Cisco-Talos WinBox dissector or a future m2ir one.

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
- The bin will start `#!/usr/bin/env node`. Node does not load `.env`, so
  tikoci-toolchain's `--no-env-file` concern does not arise. Whether `bunx`
  then runs it under Node or Bun is to be measured, not assumed.

The cost is a build step and a `dist/` that must match `src/`; the release
workflow's packed-tarball smoke test (tikoci-release) is what proves it.

## Testing

- **Unit** (`test/unit`, every PR, three OSes): parsers and dissectors on
  captured RouterOS bytes with their provenance (version, architecture, date,
  capture), the filter and formatter, the CLI's flag registry and help.
- **Node smoke** (`test/smoke`): the built package under Node.
- **Integration** (`test/integration`, `TZSP_SNIFF_INTEGRATION=1`): boot a
  CHR with quickchr, arm `/tool/sniffer` toward the SLIRP gateway, generate
  traffic (a ping, an MNDP announcement), and assert the decoded records,
  on `stable` and `long-term`. quickchr is a devDependency only.
- **Fixtures** are small and sanitized, as hex in tests or pcapng files under
  `test/fixtures/` with a README saying where each came from.

## To ground on a CHR

Before code relies on them (tikoci-grounding):

- Does mangle `sniff-id` add a TZSP tag, and which one? quickchr notes the
  sensor tag was not sent on 7.26beta5 `/tool/sniffer`.
- Does any RouterOS sender use tags or encapsulations other than Ethernet
  (wireless interfaces, `filter-direction`)?
- Do `/tool/sniffer` and mangle streams differ in framing, and does
  `only-headers` truncate the frame inside TZSP?
- Behavior across `stable`, `long-term` and an arm64 CHR.

## Open questions

- `reusePort`: whether to offer it at all, after measuring unicast delivery
  with two listeners on Linux and macOS, under Node and Bun.
- The exact JSONL record fields, settled with the first `listen` slice and
  pinned by tests, with `schemaVersion` in the header record.
