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
> ICMP, UDP and TCP, and saves captures as pcapng (`--write`, `--format
> pcapng`); `decode` reads them again, and the files RouterOS saves.
> `setup` is designed ([DESIGN.md](DESIGN.md)) and not built yet.

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
tzsp-sniff --duration 30s --write cmr.pcapng --stats   # save everything, print the summary
tzsp-sniff --proto icmp --format pcapng --follow | tshark -r -   # filtered, to a pipe
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

`--write <file>` saves every datagram the capture reads, as it arrived,
before filters and whatever the output prints (the summary's `dropped` and
`unread` count the ones it never read), as a pcapng file with link type TZSP (128):
each packet block holds the whole TZSP datagram (tags, control and
malformed records included), one interface per listener carries its label
and port, and each packet's comment names its UDP peer
(`peer=10.0.2.15:37008`). Wireshark and TShark open it as it is (checked in
CI on TShark 4.2.2). The file must not exist (`--overwrite` replaces a
regular file with a new one, so a reader of the old file never sees the
capture), is owner-only where the OS has permissions, and is written block
by block, so Ctrl-C leaves a valid file. It cannot be the file stdout or
stderr is redirected to. The header names the file, the summary counts
what was written, and a failed write ends the capture with
`write/failed` and exit 1, the file ending at its last whole block (the
datagram it was saving counts as `unsaved`). `--format pcapng` writes the same format to
stdout with the filters applied, for a pipe or a redirect (it is refused on
a terminal, and with `--fields`, `--stats` or `--detail`); the start line,
warnings and the summary go to stderr.

### `decode`: look again, with no network

`tzsp-sniff decode <file>` (or `-` for stdin) runs the same pipeline over a
capture file: the same records, filters, `--fields`, `--detail`, `--stats`,
`--count` and `--expect`, and text or JSONL.

```sh
tzsp-sniff --duration 30s --write cmr.pcapng --stats        # capture once
tzsp-sniff decode cmr.pcapng --proto tcp --port-match 54321 --detail layers
tzsp-sniff decode sniffer-file.pcapng --format jsonl        # a file /tool/sniffer saved
tzsp-sniff decode - --input hex < datagrams.hex             # one TZSP datagram per line
```

The format is told from the first bytes (pcapng, or pcap in either byte
order and resolution); `--input pcapng|pcap|hex` sets it, and hex (one
TZSP datagram per line; blank lines and `#` comments skipped) is never
guessed. What a packet is depends on the file's link type:

- **TZSP** (128, what `--write` saves): each packet is a datagram, with its
  listener label and UDP peer restored, so a file decodes to the records
  the capture printed.
- **Ethernet**: a frame that is UDP to the TZSP port is unwrapped, with the
  IP source as its peer and the port as its listener (a host capture of the
  stream); any other frame is decoded as it is, with no listener or peer (a
  file RouterOS saved). Such records carry the file's `interface` (`ether1
  rx`), its `comment` (`cpu:0 fp:0`) at `--detail layers`, and the router's
  time.
- **Raw IP and Linux cooked** (`tshark -i any`): UDP to the TZSP port is
  unwrapped; anything else is an `unsupported` record (`link/not-tzsp`).

`--tzsp-port <port>` (repeatable) names the TZSP ports to unwrap; the
default is 37008. IP fragments are not reassembled. Any other link type
ends the stream with `decode/link-type`. Every length is checked before it
is read (1 MiB per block, 128 KiB per hex line): a corrupt file prints the
records before the damage, then ends with `decode/malformed` and exit 1; a
file cut inside a block (still being written, or copied short) prints what
is whole, warns `decode/truncated`, and its summary is `incomplete`.
`listen`'s flags (`--port`, `--follow`, `--write` …) and `--format pcapng`
are refused with `cli/wrong-command`, which names `listen`. The summary's
`durationMs` is the span of the file's timestamps, and `stoppedBy` is `end`
once the input is read.

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

`pcapngWriter(sink)` and `fileSink(path, { overwrite })` are `--write`:
pass the writer as `openCapture({ write })` to save every datagram, or as
`writeReported` to save only what the stream reports. A sink is any
`{ write(chunk) }` that returns a promise; the writer waits for each block
and ends the capture with `write/stalled` when a sink takes nothing for 30
seconds.

`openDecode(input, options)` is `decode`: `input` is the bytes, or any
iterable of chunks (a file or stdin stream), and the stream has the same
records, with a `decode` header:

```typescript
import { readFile } from "node:fs/promises";
import { openDecode } from "@tikoci/tzsp-sniff";

for await (const record of await openDecode(await readFile("cmr.pcapng"), {
  filter: { proto: ["tcp"] },
})) {
  if (record.type === "packet") console.log(record.listener, record.line);
}
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
[quickchr](https://github.com/tikoci/quickchr) (a devDependency) for this
machine's CPU, has it stream TZSP to the tests, and removes it.
`TZSP_SNIFF_ROUTEROS` picks a channel or a version (default `stable`). CI
runs it on `stable` for every code change and on every active channel
nightly. It needs QEMU with `qemu-img`, and an arm64 host also needs UEFI
firmware; `node_modules/.bin/quickchr doctor` says what is missing:

<!-- cspell:ignore edk efi dnf -->

| Host | Install | Boot |
| --- | --- | --- |
| Linux x86_64 | `apt install qemu-system-x86 qemu-utils` | under a minute with KVM |
| Linux arm64 | `apt install qemu-system-arm qemu-efi-aarch64 qemu-utils` (`edk2-aarch64` on dnf) | under a minute with KVM |
| macOS | `brew install qemu` (firmware included) | HVF on Intel; Apple Silicon boots the arm64 CHR under TCG, so several minutes |
| Windows | `winget install SoftwareFreedomConservancy.QEMU` | TCG, several minutes |

quickchr's [MANUAL](https://github.com/tikoci/quickchr/blob/main/MANUAL.md)
has the full list.

`bun run test:tshark` has TShark read a file the writer made, and checks an
inner field, the interface and the peer comment. It needs `tshark` on
`PATH` (`apt install tshark`, `brew install wireshark`); CI runs it on
Ubuntu 24.04's TShark and sets `TZSP_SNIFF_TSHARK_VERSION` to pin it.

Agent instructions are in [AGENTS.md](AGENTS.md).

## License

MIT
