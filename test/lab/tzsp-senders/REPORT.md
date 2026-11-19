# Lab: RouterOS's two TZSP senders

Issue #5. What `/tool/sniffer` streaming and mangle `action=sniff-tzsp`
put on the wire, captured raw on CHRs, so tzsp-sniff's design rests on seen
bytes rather than one capture and the docs. Every statement below cites
the retained evidence; what was not retained is not claimed.

## Run it

```sh
bun test/lab/tzsp-senders/lab.ts       # three routers, about 3.5 minutes with KVM
bun test/lab/tzsp-senders/fixtures.ts  # rebuild test/fixtures/routeros/ from evidence/
bun test test/unit/routeros-fixtures.test.ts
```

`--only x86:stable,x86:long-term,arm64:stable` picks routers. It runs the
quickchr devDependency (`bun install`; the results below were taken with
quickchr 0.5.2 on `PATH`, before the lab moved to it; it now uses
quickchr's library), and needs `scp` on `PATH`.
It is not a test tier and never gates CI. Its machine handling and REST
calls are in `test/chr/`, shared with the integration tier.

The script creates its own machines (a random name, checked absent,
created with quickchr's `add`, which refuses an existing name) and removes
them at the end, on failure, and on SIGINT or SIGTERM, then checks they are
gone. Every router command must succeed and every experiment's control
traffic must arrive (`expect` in `lab.ts`), or nothing is written to
`evidence/`. Only datagrams that are the lab's own pings are stored; any
other datagram is counted by kind and dropped.

## Setup

| | |
| --- | --- |
| Date | 2026-11-19 UTC (02:49 to 02:53) |
| Host | Linux x86_64, Bun 1.4.4, quickchr 0.5.2 |
| Routers | 7.25.1 (`stable`) x86_64 and 7.24.6 (`long-term`; the router reports `7.24.6 (long-term)`) x86_64, QEMU `-accel kvm`; 7.25.1 arm64, QEMU `-accel tcg,tb-size=256` |
| Boot | x86 25 s each; arm64 under TCG 40 s (`bootMs` in each run) |
| Network | one `user` (SLIRP) NIC; the router sends to the gateway `10.0.2.2:<port>`, which QEMU delivers to the host's `127.0.0.1:<port>` |
| Listener | `node:dgram`, unconnected, bound to `127.0.0.1` port 0 (a free port the kernel picks), one per router |
| Traffic | `/ping 10.0.2.3` (SLIRP's DNS address) from the router at 10.0.2.15 |

Version and architecture are what the router reported (`/system/resource`
`version` and `architecture-name`); the accelerator is the `-accel`
argument of the running QEMU process.

[`evidence/`](evidence/) holds one JSON per router: every command and its
output, the router state read by REST, each experiment's datagram tally,
and its first 8 lab datagrams (plus the deepest one), in hex. The two saved
capture files are there too; each run records its file's SHA-256. The
fixtures and their provenance (`index.json`) are in
[`test/fixtures/routeros/`](../../fixtures/routeros/).

## Results, per checklist item

Everything below was seen on both 7.25.1 and 7.24.6 x86_64, unless it
says otherwise. Byte offsets count from the start of the UDP payload.

### Both senders: version, type, encapsulation and tags

**Seen.** Every datagram that arrived from `/tool/sniffer` streaming and
from mangle `sniff-tzsp` started `01 00 00 01 01`: version 1, type 0
(received), encapsulation 1 (Ethernet), then the end tag, with no tag
before it. That is a tally of every datagram in every TZSP experiment
(`summary.tzspHeaderNoTags` equals `summary.datagrams`), not only the
stored ones. The Ethernet frame follows at byte 5. The earlier 7.26beta5
capture (quickchr `examples/cmr/FINDINGS.md`, "Wire") agrees.

What was inside, for the ICMP echo tested:

| Sender | Frame inside TZSP |
| --- | --- |
| `/tool/sniffer` streaming | requests and replies, with the MACs of the link |
| mangle `prerouting`, `input` | the echo replies, with the MACs of the link |
| mangle `output`, `postrouting` | the router's own echo requests behind a 14-byte Ethernet header whose destination and source MACs are all zero, EtherType `0800` |

Only the router's own echo requests went through `output` and
`postrouting`; forwarded traffic and other protocols were not tested
there, and `forward` was not tested at all.

Fixtures: `*-sniffer-stream.hex`, `*-mangle-{prerouting,input,output,postrouting}.hex`.

### Mangle `sniff-id`

**Seen: no tag.** On a `sniff-tzsp` rule, `sniff-id=4660` is accepted by
`add` but not kept: the rule's REST record (`state.restRecord`),
`print detail` and `export` have no `sniff-id`, and its datagrams have the
same header and no tag (`*-mangle-sniff-id.hex`).

`sniff-id` is kept by the other sniff action, `sniff-pc` (its REST record
has `"sniff-id": "4660"`). `sniff-pc` does not send TZSP. Each 82-byte
datagram for a ping starts with the id as 4 big-endian bytes
(`00 00 12 34`), then 8 bytes that differ per packet, then the 56-byte IPv4
packet at byte 12 with no Ethernet header, then 14 bytes
(`*-mangle-sniff-pc.hex`). Only the id and the IPv4 packet are
interpreted here. A TZSP parser reads version 0.

### Timestamp (tag 82) or sensor tags

**Seen: none**, from either sender in these experiments (the tally above).
Only the sniffer ran on arm64. A capture this size cannot show that a tag
never appears.

The file `/tool/sniffer` saves does carry time: see below.

### `only-headers`

**Seen.** With `only-headers=yes`, each 1000-byte ping (IPv4 total length
1000) arrived as its first 60 bytes of Ethernet frame, in a 65-byte
datagram, with no tag giving the original length
(`*-sniffer-only-headers.hex`). Only that size was tested.

### `filter-stream`, and a mangle rule that matches its own output

**`filter-stream` reads `false`** on a fresh CHR of both versions
(`snifferDefaults`).

**With `filter-stream=no` and a filter that matches UDP, the sniffer
captured its own stream.** Settings: `filter-ip-protocol=icmp,udp`,
`filter-operator-between-entries=or`, one ping, and a background job on
the router that stopped the sniffer 4 s after it was armed. Seen:

- 801 (7.25.1) and 850 (7.24.6) datagrams, every one starting
  `01 00 00 01 01`.
- Each copy wraps the previous datagram in TZSP, Ethernet, IPv4 and UDP to
  the listener, adding 47 bytes; unwrapping a stored copy once gives an
  earlier stored datagram, byte for byte.
- Whole copies reached 30 layers (1485-byte datagrams, in the length
  tally). A 31st layer would be 1532 bytes, more than one Ethernet frame,
  and goes out as IPv4 fragments. The deepest datagram stored (1519 bytes)
  is the sniffer's capture of such a first fragment (more-fragments set):
  31 TZSP layers, with the ping inside cut short.
- The fragments and their copies were counted, not stored: 701 and 734
  datagrams whose innermost layer is a UDP IPv4 fragment, and 36 and 54
  whose innermost layer is under 14 bytes.
- The fixture keeps the first 8 and the deepest
  (`*-sniffer-filter-stream-no.hex`).

The same settings with `filter-stream=yes` sent the ping's request and
reply and nothing else (`*-sniffer-filter-stream-yes.hex`).

**No copy of TZSP came back from mangle**, in these runs:

| Rules (the first is the trigger in every row) | Counters (packets) | Datagrams that arrived |
| --- | --- | --- |
| `output` ICMP to 10.0.2.3; `output` UDP to `10.0.2.2:<port>` | 2, 0 | the 2 echo requests, no TZSP inside |
| `output` ICMP to 10.0.2.3; `postrouting` UDP to `10.0.2.2:<port>` | 2, 2 (206 bytes: two 103-byte packets, IPv4 20 + UDP 8 + TZSP 75) | the 2 echo requests, no TZSP inside |
| `postrouting` UDP to `10.0.2.2:<port>`, while `/tool/sniffer` streams there | 4 (412 bytes) | the sniffer's 2 requests and 2 replies, no TZSP inside |

So with this matcher, the `output` rule counted nothing. The `postrouting`
rule counted the TZSP datagrams, both the mangle rule's and the sniffer's,
and no further copy arrived within the experiment's drain time. Why is not
known. Only rules whose target is the same address and port were tested.

Fixtures: `*-mangle-self-{output,postrouting}.hex`,
`*-mangle-mirrors-sniffer.hex`; the counters are in the evidence.

### A file saved by `/tool/sniffer`

**Seen.** `file-name=tzsp-lab-capture` saved a file of exactly that name,
836 bytes for three pings on the one NIC (x86 only). It is pcapng:

- a little-endian section header block, no options;
- two interface description blocks, both link type 1 (Ethernet), snap
  length 65536, `if_tsresol` 9 (nanoseconds), named `ether1 rx`
  (interface 0) and `ether1 tx` (interface 1);
- six enhanced packet blocks, alternating request on `tx` and reply on
  `rx`, captured length equal to original length (70), each with the one
  comment `cpu:0 fp:0`, timestamps increasing and on the run's date.

So a saved file carries what TZSP does not: an interface, a direction and
the router's time. Copied off over SCP unchanged:
`*-sniffer-file.pcapng`. Other names, NICs and traffic were not tested.

### arm64

**Seen.** 7.25.1 arm64 under TCG: `/tool/sniffer` streaming sent
`01 00 00 01 01` with no tags, 3 requests and 3 replies with the MACs of
the link (`7.25.1-arm64-sniffer-stream.hex`). Only this basic stream ran
on arm64.

## Also seen

- **`filter-operator-between-entries` reads `or`** on a fresh CHR. With
  `and`, `filter-ip-protocol=icmp,udp` and no other filter, the sniffer was
  running (`state.snifferRunningAfterStart`) and streamed nothing for two
  pings; the same with `or` streamed all four packets
  (`sniffer-and-two-protocols`, `sniffer-or-two-protocols`). What `and`
  does with other combinations was not tested.

## Applied to `src/tzsp.ts`

The header comment's RouterOS paragraph now states these results (PR #7).

## Open questions

- Why mangle counts TZSP addressed to its own target in `postrouting` but
  no copy arrives (#9). A rule with a different target was not tested.
- `setup` and `filter-stream`: decided, `setup` does not force
  `filter-stream=yes`; `--help` explains it (DESIGN.md, "`setup`").
- `setup`'s filter translation: each flag needs its own CHR test; the
  `and` result above shows a name match is not enough (#8).
- Not covered: physical routers, wireless (802.11 encapsulations), VLAN
  tags, IPv6, traffic other than ICMP echo, mangle `forward`, the `testing`
  and `development` channels, and mangle and the other sniffer settings on
  arm64.
