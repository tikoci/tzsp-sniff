# Lab: RouterOS's two TZSP senders

Issue #5. What `/tool/sniffer` streaming and mangle `action=sniff-tzsp`
put on the wire, captured raw on a CHR, so tzsp-sniff's design rests on
seen bytes rather than one capture and the docs.

## Run it

```sh
bun test/lab/tzsp-senders/lab.ts       # all three routers, about 3 minutes on KVM
bun test/lab/tzsp-senders/fixtures.ts  # rebuild test/fixtures/routeros/ from the evidence
bun test test/unit/routeros-fixtures.test.ts
```

`--only x86:stable,x86:long-term,arm64:stable` picks routers. The lab
needs `quickchr` (0.5.2 here) and `scp` on `PATH`, and Linux for the
accelerator check (it reads QEMU's `/proc/<pid>/cmdline`). It is not a
test tier and never gates CI.

## Setup

| | |
| --- | --- |
| Date | 2026-11-18 |
| Host | Linux x86_64 (orca), Bun 1.4.4, quickchr 0.5.2 |
| Routers | 7.25.1 (`stable`) x86_64 and 7.24.6 (`long-term`, reported as `7.24.6 (long-term)`) x86_64, QEMU `-accel kvm`; 7.25.1 arm64, QEMU `-accel tcg,tb-size=256` |
| Boot | x86 about 25 s; arm64 under TCG 42 s and 49 s on two runs, well inside quickchr's own budget |
| Network | one `user` (SLIRP) NIC; the router sends to the gateway `10.0.2.2:<port>`, which QEMU delivers to the host's `127.0.0.1:<port>` |
| Listener | `node:dgram`, unconnected, bound to `127.0.0.1` port 0, so the kernel chose a free port; one port per router |
| Traffic | `/ping 10.0.2.3` (SLIRP's DNS address) |

Each router gets a machine named `tzsp-lab-<channel>-<arch>-<run id>`,
stopped and removed in `finally`. Experiments run one after another on the
router's one port; each datagram is labelled with the experiment running
when it arrived, with a 1.5 s drain before the next one.

Version and architecture are what the router reported
(`/system/resource` `version` and `architecture-name`); the accelerator is
the `-accel` argument of the running QEMU process.

The evidence is in [`evidence/`](evidence/): one JSON per router with
every command, its output and the raw datagrams in hex, and the saved
capture files. The fixtures and their provenance (`index.json`) are in
[`test/fixtures/routeros/`](../../fixtures/routeros/).

## Results, per checklist item

All results below hold for both 7.25.1 and 7.24.6 x86_64, unless a row
says otherwise. Byte offsets count from the start of the UDP payload.

### Both senders: version, type, encapsulation and tags

**Seen.** Every datagram from `/tool/sniffer` streaming and from mangle
`sniff-tzsp`, in every chain and experiment, starts `01 00 00 01 01`:
version 1, type 0 (received), encapsulation 1 (Ethernet), then the end tag
with no tag before it. The Ethernet frame follows at byte 5. The
earlier 7.26beta5 capture (quickchr `examples/cmr/FINDINGS.md`, "Wire")
agrees.

The senders differ in the frame they put there:

| Sender | Frame inside TZSP |
| --- | --- |
| `/tool/sniffer` streaming | the frame as on the wire, real MACs, both directions |
| mangle `prerouting`, `input` | the received frame, real MACs |
| mangle `output`, `postrouting` | the IP packet behind a 14-byte Ethernet header whose destination and source MACs are all zero, EtherType `0800` |
| mangle `forward` | not tested: the CHR forwarded nothing |

So an all-zero MAC from mangle means "sent by the router, no link header
yet", not an endpoint.

Fixtures: `*-sniffer-stream.hex`, `*-mangle-{prerouting,input,output,postrouting}.hex`.

### Mangle `sniff-id`

**Seen.** It adds no tag. On a `sniff-tzsp` rule, `sniff-id=4660` is
accepted by `add` but not kept: `print detail` and `export` show no
`sniff-id` (nor did the rule's REST record, in the exploratory session
below), and the datagrams are byte for byte the
shape of a rule without it (`*-mangle-sniff-id.hex`).

`sniff-id` belongs to the other sniff action, `sniff-pc`, which keeps it
(the rule shows `sniff-id=4660`). `sniff-pc` does not send TZSP: its
82-byte datagram for a 56-byte ping starts with the id as 4 big-endian
bytes (`00 00 12 34`), then 8 bytes that change per packet, then the IP
packet with no Ethernet header, then 14 more bytes. Only the id and the IP
packet's position are interpreted here (`*-mangle-sniff-pc.hex`). A TZSP
parser sees version 0.

### Timestamp (tag 82) or sensor tags

**Seen: none.** No datagram from either sender, in any experiment, on
either version or architecture, carried any tag. There was nothing to
learn about tag 82's format.

The file `/tool/sniffer` saves does carry time: see below.

### `only-headers`

**Seen.** With `only-headers=yes`, a 1000-byte ping (IPv4 total length
1000) arrives as its first 60 bytes of Ethernet frame: the datagram is 65
bytes. No tag gives the original length (`*-sniffer-only-headers.hex`);
the IPv4 total length is the only sign the frame was cut.

### `filter-stream`, and a mangle rule that matches its own output

**`filter-stream` defaults to `no`** on both versions (REST shows
`"filter-stream": "false"` on a fresh CHR).

**`filter-stream=no` with a filter that matches UDP captures the sniffer's
own stream**, each copy wrapped once more: TZSP, Ethernet, IPv4, UDP to
the listener, then the previous datagram. Each layer adds 47 bytes.
Started by one ping, the stream reached 32 layers and 1519-byte datagrams
(5 bytes of TZSP and a 1514-byte frame), with 892 (7.25.1) and 903 (7.24.6)
datagrams in the 4 s before a background job on the router stopped the
sniffer. The fixture keeps the first 8 (`*-sniffer-filter-stream-no.hex`).
The same settings with `filter-stream=yes` sent only the ping and its
reply (`*-sniffer-filter-stream-yes.hex`).

**Mangle does not mirror TZSP back to its target**, in these runs:

| Rule (plus an `output` ICMP rule as the trigger) | Its counter | Datagrams with a TZSP datagram inside |
| --- | --- | --- |
| `chain=output protocol=udp dst-address=10.0.2.2 dst-port=<port>` | 0 packets | none |
| the same in `chain=postrouting` | 2 packets, 206 bytes (the two 103-byte TZSP datagrams) | none |
| the same `postrouting` rule while `/tool/sniffer` streams to that port | 4 packets, 412 bytes (the sniffer's datagrams) | none |

So TZSP that a `sniff-tzsp` rule sends does not pass the `output` chain,
and it and the sniffer's stream do pass `postrouting`, where a matching
`sniff-tzsp` rule counts them but no copy reached the listener. Why is not
known: RouterOS may skip packets addressed to the sniff target, or skip
packets it generated for sniffing. Only a rule whose target is the same
address and port was tested.

Fixtures: `*-mangle-self-{output,postrouting}.hex`,
`*-mangle-mirrors-sniffer.hex` (the trigger's datagrams only; the test
asserts none nests).

### A file saved by `/tool/sniffer`

**Seen.** `file-name=tzsp-lab-capture` saved a file of exactly that name,
no extension added, 836 bytes for three pings. It is pcapng:

- a little-endian section header block;
- two interface description blocks, both link type 1 (Ethernet), snap
  length 65536, `if_tsresol` 9 (nanoseconds), named `ether1 rx` (interface
  0) and `ether1 tx` (interface 1): one interface per direction;
- six enhanced packet blocks (each ping's request on `tx`, reply on `rx`),
  captured length equal to original length (70), each with the comment
  `cpu:0 fp:0`.

So a saved file carries what TZSP does not: the interface, the direction,
and a timestamp from the router. Copied off over SCP unchanged:
`*-sniffer-file.pcapng`.

### arm64

**Seen.** 7.25.1 arm64 under TCG: `/tool/sniffer` streaming sends the same
`01 00 00 01 01` header, no tags, whole frames with real MACs
(`7.25.1-arm64-sniffer-stream.hex`). Only the basic stream was run on
arm64.

## Also seen

- **`filter-operator-between-entries` defaults to `or`.** With `and`,
  `filter-ip-protocol=icmp,udp` and no other filter, the sniffer streamed
  nothing for a ping (both versions; experiment `sniffer-and-two-protocols`
  in the evidence). The first two lab runs used that setting for the
  `filter-stream` experiments and got nothing; it was first blamed on
  starting the sniffer inside one script, which a third run disproved.
  This matters to `setup`'s filter translation (DESIGN.md).
- **A mangle rule added over REST was not in effect at once** in the
  exploratory session: a ping sent right after `add` left the rule's
  counters at 0. The lab waits 2 s (`:delay 2s`) after each `add`, and
  every rule then counted its packets.

Exploratory session, by hand, 7.25.1 x86_64 under KVM, the same day,
before the script existed. Seen once, not re-run, so not relied on:

- `/ping 10.0.2.2` (the SLIRP gateway) got replies, but the sniffer
  recorded none of those packets; pings to 10.0.2.3 were recorded. The lab
  pings 10.0.2.3.
- With `filter-stream=no` and `filter-ip-protocol=udp`, the self-capture
  loop ran until the machine was powered off, and REST calls timed out
  during it. The lab therefore schedules the stop in a background job
  (`:execute`) before starting the sniffer; with that, REST answered
  within 2 ms after the stop.

## Suggested wording for `src/tzsp.ts`

The header comment's RouterOS paragraph, for whoever next edits that file
(#4 owns it now):

```typescript
 * RouterOS: `/tool/sniffer` streaming and mangle `action=sniff-tzsp` send
 * `01 00 00 01 01`, version 1, received, Ethernet, the end tag alone, on
 * 7.25.1 and 7.24.6 x86_64 (KVM) and 7.25.1 arm64 (TCG, sniffer only),
 * 2026-11-18 (test/lab/tzsp-senders/REPORT.md, fixtures in
 * test/fixtures/routeros/). Mangle `sniff-id` adds no tag: it is not kept on
 * a sniff-tzsp rule, and `sniff-pc`, which keeps it, does not send TZSP.
```

## Open questions

- Why mangle counts but does not mirror TZSP addressed to its own target
  (above). A rule mirroring to a different port or host was not tested.
- `setup` and `filter-stream`: the default is `no`, and `no` with a UDP
  filter loops. Whether `setup` should always print `filter-stream=yes` is
  a design decision, not made here.
- `setup`'s filter translation: `filter-operator-between-entries=and` with
  a two-value list matched nothing, so "one sniffer setting each" needs a
  CHR test per flag before any flag is said to translate.
- Not covered: physical routers, wireless (802.11 encapsulations), VLAN
  tags, IPv6, mangle `forward`, the `testing` and `development` channels,
  and mangle and the other sniffer settings on arm64.
