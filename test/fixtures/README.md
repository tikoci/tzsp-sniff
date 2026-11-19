# Test fixtures

## `routeros/`: what RouterOS sends

Real bytes from RouterOS CHRs, captured by the lab in
[`test/lab/tzsp-senders/`](../lab/tzsp-senders/) for issue #5. What each
one shows is in that lab's [REPORT.md](../lab/tzsp-senders/REPORT.md).
[`test/unit/routeros-fixtures.test.ts`](../unit/routeros-fixtures.test.ts)
pins them, and checks each against the run it came from.

Provenance for every file is in [`routeros/index.json`](routeros/index.json):
the experiment, RouterOS version and architecture as the router reported
them (`/system/resource`), the channel quickchr resolved, the QEMU
accelerator, the UTC date, the host UDP port the router sent to, and the
run's evidence file. That file has the exact router commands, their
output, the router state read during each experiment, and a tally of every
datagram received.

All captures: quickchr 0.5.2 CHRs on a Linux x86_64 host, one `user`
(SLIRP) NIC, the router sending to the gateway `10.0.2.2:<port>`, which
QEMU delivers to a plain UDP socket on the host's `127.0.0.1:<port>`.

| File pattern | What it is |
| --- | --- |
| `<version>-<arch>-<experiment>.hex` | One datagram (the UDP payload) per line, in arrival order, as hex |
| `<version>-<arch>-sniffer-file.pcapng` | The file `/tool/sniffer` saved with `file-name=`, copied off the router over SCP, unchanged (SHA-256 in the run's evidence) |

Experiments (the commands are in the evidence):

| Experiment | Sender and settings |
| --- | --- |
| `sniffer-stream` | `/tool/sniffer` streaming, ICMP with 10.0.2.3 |
| `sniffer-only-headers` | the same with `only-headers=yes`, a 1000-byte ping |
| `sniffer-or-two-protocols` | `filter-ip-protocol=icmp,udp` with `filter-operator-between-entries=or` (the `and` run sent nothing, so it has no fixture) |
| `sniffer-filter-stream-yes`, `-no` | streaming ICMP and UDP with `filter-stream=yes` or `no`; the `no` file keeps the first 8 datagrams of the self-capture loop and its deepest |
| `mangle-prerouting`, `-input`, `-output`, `-postrouting` | one `action=sniff-tzsp` rule in that chain, ICMP with 10.0.2.3 |
| `mangle-sniff-id` | an `output` rule with `sniff-id=4660` |
| `mangle-sniff-pc` | `action=sniff-pc` with `sniff-id=4660`: not TZSP, kept so a receiver can recognize it |
| `mangle-self-output`, `-postrouting` | an ICMP rule plus a UDP rule that matches the first rule's TZSP datagrams |
| `mangle-mirrors-sniffer` | a `postrouting` rule that matches `/tool/sniffer`'s stream, while the sniffer streams |

Sanitized at capture: the lab stores only datagrams whose innermost frame
is its own ping between 10.0.2.15 and 10.0.2.3, and only a saved file
whose interfaces and packets are of that kind. Anything else (MNDP, which
carries the CHR's software id, for one) is counted by kind, never stored.
No host names, paths, user names or real-network addresses.

Regenerate:

```sh
bun test/lab/tzsp-senders/lab.ts       # new evidence, on CHRs
bun test/lab/tzsp-senders/fixtures.ts  # fixtures from evidence/, on any checkout
```

A new lab run changes ICMP ids, timestamps, MACs and ports, so the unit
test asserts the shape (header bytes, tags, MACs, lengths, nesting,
counters), and checks each fixture against its own run's evidence.
