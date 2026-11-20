# Lab: the LLDP RouterOS sends

Issue #26 (slice 6b of #18). What a RouterOS CHR sends as LLDP on its own,
seen through `/tool/sniffer` streaming, so the LLDP dissector and its
integration check rest on captures rather than on documentation.

Run by hand, never a gate:

```sh
bun test/lab/lldp/lab.ts                 # stable and long-term, x86 and arm64
bun test/lab/lldp/lab.ts --only x86:stable
bun test/lab/lldp/fixtures.ts            # test/fixtures/lldp/ from evidence/
```

It needs what the integration tier needs (README, "Development"), and
`qemu-system-aarch64` with UEFI firmware for the arm64 router.

## Setup

| | |
| --- | --- |
| Date | 2026-11-20 (UTC); 7.24.6 arm64 in a later run the same day |
| Host | Linux x86_64, quickchr 0.6.0 |
| Routers | 7.25.1 (`stable`) and 7.24.6 (`long-term`), x86_64 under QEMU `kvm` and arm64 under `tcg` |
| Boot | x86 24 s and 26 s; arm64 39 s each (`bootMs` in each run) |
| Network | one SLIRP NIC, ether1, 10.0.2.15/24 and an EUI-64 link-local IPv6 address |
| Capture | `/tool/sniffer` streaming everything to `10.0.2.2:<port>` with `filter-stream=yes`; only frames with EtherType 0x88cc kept, the rest counted (`other`: CDP, MNDP and the like) |

The evidence for each router is in [evidence/](evidence/): every command,
the discovery settings as booted, ether1's MAC, the identity, the addresses,
and every LLDP datagram with its arrival time.

## Experiments

| Experiment | Setup | Waits for |
| --- | --- | --- |
| `default` | none: discovery as booted | two LLDPDUs |
| `optional-tlvs` | `/ip/neighbor/discovery-settings/set lldp-vlan-info=yes lldp-mac-phy-config=yes lldp-max-frame-size=yes` | one LLDPDU |
| `identity-utf8` | `/system/identity/set name="lab-café"` | one LLDPDU |

Each experiment keeps only LLDPDUs that show its setup: the identity as
booted and none of the optional TLVs, then the optional TLVs, then the UTF-8
identity (`SHOWS` in lab.ts, checked again by fixtures.ts). One sent before
the setup took effect would be counted as `stale`; the committed runs
predate that count, and every LLDPDU in them passes the check. The 7.24.6
arm64 run had it: 0 stale. In that run the lab starts accepting before the
setup command (an LLDPDU can arrive before the REST call returns), so its
`at` counts from the setup's start; the three earlier runs count from its
end.

Discovery as booted, the same on all three:
`protocol=cdp,lldp,mndp discover-interval=30s discover-interface-list=static
lldp-med=yes lldp-vlan-info=no lldp-mac-phy-config=no lldp-max-frame-size=no
lldp-med-net-policy-vlan=disabled mode=tx-and-rx`.

## What it showed

The same on all four routers, apart from the system description and the
addresses; 7.24.6 arm64 sends byte for byte the layout 7.24.6 x86_64 does:

- **Every LLDPDU decodes with no problem**, through `dissect()` and
  `openCapture()` (the integration tier, `the router's own LLDP decodes with
  no problem`).
- **Interval.** As booted, one LLDPDU on ether1 every 30.0 s (`default`,
  two LLDPDUs 30,000 to 30,007 ms apart). The first came 12 to 15 s after
  the sniffer started.
- **A settings change sends at once.** After each `set`, an LLDPDU arrived
  within 0.2 to 0.8 s, before the interval was due.
- **Destination** 01:80:c2:00:00:0e (the nearest-bridge address), from
  ether1's MAC, untagged. Nothing follows End: every frame is Ethernet and
  LLDP only, with no padding (as booted, 156 bytes on 7.25.1 and 168 on
  7.24.6; with the optional TLVs, 184 and 196; with the UTF-8 identity, 190
  and 202).
- **TLVs, in order** (type and length):
  chassis id (7: subtype 4, MAC address, ether1's MAC), port id (7:
  subtype 5, interface name, `ether1`), TTL (2: **121**), system name
  (identity), system description (`MikroTik RouterOS 7.25.1 2026-11-02
  12:39:53 CHR`; 7.24.6 adds `(long-term)`), system capabilities (4:
  bridge and router, router enabled), **port description after the
  capabilities** (`ether1`), an LLDP-MED capabilities TLV (127, OUI
  00-12-BB, subtype 1, `000104`), two management addresses (12 and 24
  bytes: IPv4 10.0.2.15 and the IPv6 link-local address, both ifIndex 2, no
  OID), End. Eleven TLVs with End.
- **Optional TLVs.** `lldp-mac-phy-config` adds IEEE 802.3 subtype 1
  (MAC/PHY configuration, `0115000000`), `lldp-max-frame-size` IEEE 802.3
  subtype 4 (`05ee`, 1518), and `lldp-vlan-info` IEEE 802.1 **subtype 2**
  (port and protocol VLAN ID, `000000`), not subtype 1 (port VLAN ID), on
  an interface with no VLAN. They come after the LLDP-MED TLV and before
  the management addresses. Fourteen TLVs with End.
- **Identity as UTF-8.** `lab-café` goes out as the 9 bytes of its UTF-8
  form (`6c61622d636166c3a9`).

## What it does not show

- An interface in a bridge or with VLANs, LLDP received from a neighbor,
  `lldp-med-net-policy-vlan` set, or `dying-gasp` (a TTL of 0 on
  shutdown).
- Hardware: only CHRs, each with one virtual NIC.
- arm64 under `tcg`, not hardware acceleration; the bytes match x86's for
  each version.
