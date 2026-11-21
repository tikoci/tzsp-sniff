# Lab: the MNDP RouterOS sends

Issue #31 (slice 6d of #18). What a RouterOS CHR announces over MNDP, seen
through `/tool/sniffer` streaming, so the MNDP dissector, which reads a
table generated from m2ir, is checked against the router and not only
against m2ir. Each finding is set against m2ir's
`profiles/mndp/profile.yaml` at 677ece8 (the vendored snapshot,
`vendor/m2ir/`).

Run by hand, never a gate:

```sh
bun test/lab/mndp/lab.ts                 # stable and long-term, x86 and arm64
bun test/lab/mndp/lab.ts --only x86:stable
bun test/lab/mndp/fixtures.ts            # test/fixtures/mndp/ from evidence/
```

It needs what the integration tier needs (README, "Development"), and
`qemu-system-aarch64` with UEFI firmware for the arm64 routers.

## Setup

| | |
| --- | --- |
| Date | 2026-11-21 (UTC), all four targets in one run |
| Host | Linux x86_64, quickchr 0.6.0 |
| Routers | 7.25.1 (`stable`) and 7.24.6 (`long-term`), x86_64 under QEMU `kvm` and arm64 under `tcg`; one machine per target |
| Boot | x86 24 s; arm64 39 s (`bootMs` in each run) |
| Network | ether1 on SLIRP: 10.0.2.15/24 from QEMU's DHCP server, and an IPv6 link-local address; discovery settings as booted |
| Capture | `/tool/sniffer` streaming everything to `10.0.2.2:<port>` with `filter-stream=yes`; only frames that are UDP to or from port 5678, IPv4 or IPv6, kept, the rest counted (`other`: 67 to 85 per run) |

**The software id is redacted.** TLV 11 carries the license software id,
which m2ir says to treat as device-identifying, and which the other labs
keep out of the repo. The lab overwrites its value with as many `X` bytes
before a datagram is kept, so every length and offset is as sent.

The evidence for each target is in [evidence/](evidence/): every command,
the router's identity, ether1's MAC, its addresses, the discovery settings,
the `/ip/packing` entry, and every MNDP datagram with its arrival time.

## Experiments

| Experiment | Setup | Waits for |
| --- | --- | --- |
| `default` | none, as booted | two announcements (two header values) |
| `discover-interval` | `/ip/neighbor/discovery-settings/set discover-interval=10s` | one with TTL 41 |
| `identity-utf8` | `/system/identity/set name="lab-café"` | one with that identity |
| `packing` | `/ip/packing/add interface=ether1 packing=none unpacking=compress-all aggregated-size=1500` | one with TLV 4 |
| `ipv6-disabled` | `/ipv6/settings/set disable-ipv6=yes` | the next two, whatever they carry |

Each experiment keeps what arrives in the 2 s after its last header value
too, for the IPv6 copy.

## What it showed

The same on all four routers, but for TLV 7, which names the channel on
7.24.6 only (below). The 48 datagrams are in test/fixtures/mndp/, and the
unit tier replays them.

- **Every datagram decodes with no problem** through `dissect()`, and no
  TLV lands in `otherTlvs`: every type sent is one the m2ir table names.
  Live, through `openCapture()`, the integration tier (`the router's own
  MNDP decodes with no problem`) checks the router's identity, ether1's MAC,
  the board and the version on `stable`.
- **Layout.** TLVs 1, 5, 7, 8, 10, 11, 12, 14, 16, 18, 19, 17, 15, in that
  order; with packing, 2, 3, 4 and 9 come right after TLV 1. This is
  m2ir's `layouts` entry for 7.24.5 and later, packing group included.
- **Header.** A counter, little-endian on x86_64 **and arm64**: 03 00 00
  00, then 04 00 00 00 and so on, one more per announcement, periodic or
  triggered; the IPv6 copy carries the same value. m2ir's arm64 reading
  rests on its FINDINGS.md, with no committed arm64 sample
  (`architectures-in-committed-samples`); these are arm64 samples.
- **Two copies.** Each announcement went out to `255.255.255.255:5678` from
  10.0.2.15 and to `[ff02::1]:5678` from ether1's link-local address, the
  IPv6 copy first by 0 to 4 ms, from and to port 5678.
- **Interval and TTL.** As booted, an announcement every 30 s with TLV 19 =
  121 (0x79); after `discover-interval=10s`, a triggered one at once with
  41 (0x29). Both are m2ir's formula, min(interval × 4 + 1, 255).
- **Triggered at once** (within 0.35 s, and 2.1 to 2.2 s for
  `discover-interval`): identity, `/ip/packing` and `disable-ipv6`, as
  m2ir's `lifecycle.triggered` lists from 7.26beta5.
- **TLV 5** sends `lab-café` as its UTF-8 bytes (9 bytes), as m2ir's
  "UTF-8 bytes as configured".
- **TLV 7**: `7.24.6 (long-term) 2026-10-30 08:24:29` and `7.25.1
  2026-11-02 12:39:53`, m2ir's 7.14–7.24 and 7.25-and-later formats.
- **TLV 12** is `CHR`; `/system/resource` reports the board as `CHR QEMU
  Standard PC (i440FX + PIIX, 1996)` (x86_64) or `CHR QEMU QEMU Virtual
  Machine` (arm64), so a check compares with `CHR`, not the board name.
- **TLV 18** is 00 (no CAPsMAN, no CMR) and **TLV 16** `ether1`; TLV 17 is
  10.0.2.15 and TLV 15 the link-local address, the only IPv6 address.
- **Packing on 7.24.6 and 7.25.1.** `unpacking=compress-all` adds TLVs 2,
  3, 4 and 9, with 9 = dc 05 00 00 (1500 little-endian) **on arm64 as on
  x86_64**. m2ir saw these TLVs on 7.26beta5 only, and leaves TLV 9's byte
  order "unverified on every other architecture" than x86_64.
- **`disable-ipv6=yes` on 7.24.6 and 7.25.1**: the next announcement, at
  once, has TLV 14 = 00 and no TLV 15, and from then on there is no IPv6
  copy. m2ir's `meaning-by-version` marks 7.21 to 7.25.1 `guessed`, with
  `on-disable: untested`; on these two versions TLV 14 follows
  `disable-ipv6` at once, as m2ir saw on 7.26beta5.

## Back to m2ir

Nothing here contradicts the profile; it adds versions and an
architecture. Filed as [tikoci/m2ir#13](https://github.com/tikoci/m2ir/issues/13) with this evidence: arm64 header and
TLV 9 samples, the packing TLVs on 7.24.6 and 7.25.1, TLV 14 following
`disable-ipv6` at once on 7.24.6 and 7.25.1, and the triggered list on
7.24.6 and 7.25.1. The generated table here stays as m2ir's until m2ir
changes (DESIGN.md, "Tables from m2ir, not by hand").

## What it does not show

- A boot announcement (header 0), a request, a reply to one, or a dying
  gasp: the lab starts listening after boot and sends nothing to the
  router. Their vectors in the unit tier are built from m2ir's forms.
- TLV 18 bits (CAPsMAN and CMR need packages a CHR does not have here), a
  global IPv6 address (SLIRP gave none), a bridge port's `bridge/ether1`.
- 6.x, or 7.x before 7.24.6, and mipsbe: only these two versions on CHRs,
  arm64 under `tcg`.
