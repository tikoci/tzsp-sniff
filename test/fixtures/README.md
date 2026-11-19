# Test fixtures

## `routeros/`: what RouterOS sends

Real bytes from RouterOS CHRs, captured by the lab in
[`test/lab/tzsp-senders/`](../lab/tzsp-senders/) for issue #5. What each
one shows, and why, is in that lab's [REPORT.md](../lab/tzsp-senders/REPORT.md).
[`test/unit/routeros-fixtures.test.ts`](../unit/routeros-fixtures.test.ts)
pins them.

Provenance for every file is in [`routeros/index.json`](routeros/index.json):
the experiment, RouterOS version and architecture as the router reported
them (`/system/resource`), the channel quickchr resolved, the QEMU
accelerator, the date, the host UDP port the router sent to, and the exact
router commands. The full evidence, including each command's output, is the
`evidence` file it names.

All captures: quickchr 0.5.2 CHRs on a Linux x86_64 host, one `user`
(SLIRP) NIC, the router sending to the gateway `10.0.2.2:<port>`, which
QEMU delivers to a plain UDP socket on the host's `127.0.0.1:<port>`.

| File pattern | What it is |
| --- | --- |
| `<version>-<arch>-<experiment>.hex` | One TZSP datagram (the UDP payload) per line, in arrival order, as hex |
| `<version>-<arch>-sniffer-file.pcapng` | The file `/tool/sniffer` saved with `file-name=`, copied off the router over SCP, unchanged |

Experiments (the commands are in `index.json`):

| Experiment | Sender and settings |
| --- | --- |
| `sniffer-stream` | `/tool/sniffer` streaming, ICMP to and from 10.0.2.3 |
| `sniffer-only-headers` | the same with `only-headers=yes`, a 1000-byte ping |
| `sniffer-filter-stream-yes`, `-no` | streaming ICMP and UDP with `filter-stream=yes` or `no`; the `no` file keeps the first 8 datagrams of a self-capture loop |
| `mangle-prerouting`, `-input`, `-output`, `-postrouting` | one `action=sniff-tzsp` rule in that chain, ICMP with 10.0.2.3 |
| `mangle-sniff-id` | an `output` rule with `sniff-id=4660` |
| `mangle-sniff-pc` | `action=sniff-pc` with `sniff-id=4660`: not TZSP, kept so a receiver can recognize it |
| `mangle-self-output`, `-postrouting` | an ICMP rule plus a UDP rule that matches the first rule's TZSP datagrams |
| `mangle-mirrors-sniffer` | a `postrouting` rule that matches `/tool/sniffer`'s stream, while the sniffer streams |

Sanitized: the frames hold only SLIRP addresses (10.0.2.0/24), QEMU MAC
addresses and ping payloads. MNDP announcements (UDP 5678, which carry the
CHR's software id) are dropped by `fixtures.ts`. No host paths, user names
or real-network addresses.

Regenerate, after a lab run:

```sh
bun test/lab/tzsp-senders/lab.ts
bun test/lab/tzsp-senders/fixtures.ts
```

A new run changes ICMP ids, timestamps, MACs and ports, so the unit test
asserts the shape (header bytes, tags, MACs, lengths, nesting), not those
values.
