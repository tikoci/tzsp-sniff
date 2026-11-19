<img src="assets/icon.svg" width="64" height="64" alt="">

# tzsp-sniff

Receive and decode TZSP packet streams from MikroTik RouterOS without root.

RouterOS can mirror packets to a remote host as TZSP: `/tool/sniffer` with
streaming enabled, or a firewall mangle rule with `action=sniff-tzsp`.
`tzsp-sniff` listens on a plain UDP port (37008 by default), so it needs no
capture privileges, and decodes what arrives into output an agent can read in
few tokens, or a person can read on a terminal. It is built for RouterOS
work, including CHRs under [quickchr](https://github.com/tikoci/quickchr),
rather than as a general sniffer.

> **Status: early.** Not yet published to npm. `tzsp-sniff` (the `listen`
> command) receives, filters and decodes Ethernet, VLAN, ARP, IPv4, IPv6,
> ICMP, UDP and TCP. `--write`, `decode` and `setup` are designed
> ([DESIGN.md](DESIGN.md)) and not built yet.

## Use

On the router (RouterOS 7), point the sniffer at this host:

```routeros
/tool/sniffer/set streaming-enabled=yes streaming-server=192.0.2.10:37008
/tool/sniffer/start
```

A CHR under quickchr reaches the host at `10.0.2.2`. Then, on the host
(until the package is on npm, run `bun install && bun run build` in a
checkout and use `node dist/cli/bin.js` for `tzsp-sniff`):

```sh
tzsp-sniff --count 10                     # ten packets, one line each
tzsp-sniff --duration 30s --stats         # only the summary
tzsp-sniff --format jsonl --follow        # a JSON record per line until Ctrl-C
tzsp-sniff --port 37008=router-a --port 37009=router-b --duration 1m
tzsp-sniff --proto tcp --not-port-match 22 --count 20   # filters
tzsp-sniff --format jsonl --host 10.0.2.15 --fields seq,src,dst,protocols
```

```text
11:13:43.607 10.0.2.15 > 10.0.2.3 icmp echo-request id=45568 seq=0 len=36
11:13:43.609 10.0.2.3 > 10.0.2.15 icmp echo-reply id=45568 seq=0 len=36
```

With no limit, it stops after 10 seconds and says so, so a guessed command
never hangs. stdout is the result; in text format the start line, warnings,
tips and the summary go to stderr, except that with `--stats` the summary
is the result, on stdout. `--detail line|summary|layers|full` sets
how much each packet carries, cheapest first. A JSONL stream starts with a
`header` record and ends with one `summary` (`complete`, `interrupted`,
`incomplete` when datagrams were dropped, or `error`); a stream without a
summary was cut off. `jq` reads the stream as it is, and `jq -s .` turns it
into one array; there is no `--format json`, since a capture is a stream.
An empty capture exits 0 with a warning saying which
case it was (`capture/no-datagrams`, `capture/no-frames`,
`capture/all-filtered`); `--expect <n>` makes too few packets exit 1.

Filters keep packets: `--proto`, `--host`, `--net`, `--port-match` (not
`--port`, which is the port to listen on), `--mac`, `--ether-type` and
`--sender` (the listener label or the UDP peer, never a field in the
packet). Host, net, mac and port-match have `--src-` and `--dst-` forms,
and every filter has a `--not-` form. Repeating a flag, or a comma list,
ORs its values; different flags AND. A packet without the field (no ports
on ARP, a later IP fragment) matches no filter and is not removed by a
`--not-` one. Filters apply to frames, not to TZSP control records; the
summary counts what they removed as `filtered`, and `--count` counts what
they kept. `--fields a,b,c` prints only those fields of each packet, and of the
summary in JSONL or with `--stats`, raising `--detail` as far as they need. To take the first few packets, use
`--count <n>` rather than `| head`: a closed pipe is noticed only at the next
write, so a quiet `--follow | head` waits for the next datagram.
`tzsp-sniff --help` has every flag.

### Library

The package will be `@tikoci/tzsp-sniff`, and runs on Node 22 or later or on
Bun. The CLI is an adapter over these exports:

```typescript
import { openCapture } from "@tikoci/tzsp-sniff";

const capture = await openCapture({ ports: [{ port: 37008 }], count: 10 });
for await (const record of capture) {
  // header, then packet / record / warning, then summary
  if (record.type === "packet") console.log(record.line, record.src, record.dst);
}
```

`openCapture({ filter })` takes the filters as a spec whose keys mirror
the flags (`srcPortMatch` is `--src-port-match`), and `createFilter(spec)`
makes the same filter for your own loop:

```typescript
import { createFilter } from "@tikoci/tzsp-sniff";

const keep = createFilter({ proto: ["tcp"], not: { portMatch: [22] } });
keep.flags; // ["--proto tcp", "--not-port-match 22"]
// for await (const capture of listener) if (keep(capture)) { … }
```

`listen()` is the layer below: the sockets and a bounded queue, yielding
each datagram with its arrival time, UDP peer and listener label.
`dissect(frame)` decodes one Ethernet frame into layers, each with its span
and fields. `parseTzsp(datagram)` reads the TZSP header:

```typescript
import { dissect, parseTzsp } from "@tikoci/tzsp-sniff";

const record = parseTzsp(udpPayload);
// { kind: "packet", datagram: udpPayload, version: 1, typeName: "received",
//   encapsulationName: "ethernet", tags: [], payload: Uint8Array }
if (record.kind === "packet") dissect(record.payload).protocols; // ["ethernet", "ipv4", "icmp"]
```

`kind` says what the record is: `packet` (received Ethernet, the only kind
whose `payload` is a frame to dissect), `control` (a keepalive or
port-opener), `unsupported` (another type or encapsulation, or too many tags)
or `invalid` (truncated or malformed). Neither parser throws: a record or
layer that cannot be read carries a `problem` (`truncated`, `malformed` or
`unsupported`) and a finer `reason`, and keeps its bytes. An `unsupported`
record can still carry a `payload` view (a transmit record, or a radiotap
frame), so dispatch on `kind`, not on `payload`. `datagram` is always the
input itself, a view of your buffer rather than a copy.

## Development

Needs [Bun](https://bun.sh) (the version in `package.json` `packageManager`)
and Node 22 or later for the smoke check.

```sh
bun install
bun run check
```

`bun run lint` also runs two tools `bun install` does not provide; a local run
skips a missing one with a message, and CI installs both:

<!-- cspell:ignore winget koalaman -->

| Tool | macOS | Linux | Windows |
| --- | --- | --- | --- |
| [shellcheck](https://www.shellcheck.net) | `brew install shellcheck` | `apt install shellcheck` | `winget install koalaman.shellcheck` |
| [actionlint](https://github.com/rhysd/actionlint) | `brew install actionlint` | release binary | release binary |

`bun run test:integration` boots a RouterOS CHR with
[quickchr](https://github.com/tikoci/quickchr) (a devDependency), has it
stream TZSP to the tests, and removes it; it needs QEMU with `qemu-img`, and KVM or HVF to
take under a minute. `TZSP_SNIFF_ROUTEROS` picks a channel or a version
(default `stable`). CI runs it on `stable` for every code change and on
every active channel nightly.

Agent instructions are in [AGENTS.md](AGENTS.md).

## License

MIT
