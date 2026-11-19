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

> **Status: early.** Not yet published to npm. The library parses TZSP
> datagrams today; the listener, dissectors and CLI are being designed.

## Use

The package will be `@tikoci/tzsp-sniff`, and runs on Node 22 or later or on
Bun:

```typescript
import { parseTzsp } from "@tikoci/tzsp-sniff";

const record = parseTzsp(udpPayload);
// { kind: "packet", datagram: udpPayload, version: 1, typeName: "received",
//   encapsulationName: "ethernet", tags: [], payload: Uint8Array }
```

`kind` says what the record is: `packet` (received Ethernet, the only kind
whose `payload` is a frame to dissect), `control` (a keepalive or
port-opener), `unsupported` (another type or encapsulation) or `invalid`.
`parseTzsp` never throws: a record it cannot read has a `problem`
(`truncated`, `malformed` or `unsupported`) and a finer `reason`.
`datagram` is always the input itself, a view of your buffer rather than a
copy, so the bytes are kept whatever happened.

On the router:

```routeros
/tool/sniffer set streaming-enabled=yes streaming-server=192.0.2.10:37008 filter-interface=ether2
/tool/sniffer start
```

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

Agent instructions are in [AGENTS.md](AGENTS.md).

## License

MIT
