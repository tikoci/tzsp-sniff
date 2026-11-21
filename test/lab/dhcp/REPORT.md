# Lab: the DHCPv4 RouterOS sends

Issue #29 (slice 6c of #18). What a RouterOS CHR sends as a DHCP client and
as a DHCP server, seen through `/tool/sniffer` streaming, so the DHCP
dissector and its integration check rest on captures rather than on the
RFCs alone.

Run by hand, never a gate:

```sh
bun test/lab/dhcp/lab.ts                 # stable and long-term, x86 and arm64
bun test/lab/dhcp/lab.ts --only x86:stable
bun test/lab/dhcp/fixtures.ts            # test/fixtures/dhcp/ from evidence/
```

It needs what the integration tier needs (README, "Development"), and
`qemu-system-aarch64` with UEFI firmware for the arm64 routers.

## Setup

| | |
| --- | --- |
| Date | 2026-11-21 (UTC), all four targets in one run |
| Host | Linux x86_64, quickchr 0.6.0 |
| Routers | 7.25.1 (`stable`) and 7.24.6 (`long-term`), x86_64 under QEMU `kvm` and arm64 under `tcg`; two machines per target |
| Boot | x86 24 s; arm64 37 to 41 s (`bootMs` in each run) |
| Network | each machine: ether1 on SLIRP (10.0.2.15/24, from QEMU's DHCP server), ether2 on a quickchr named socket shared by the two (an L2 link, unix datagram) |
| Capture | `server` only: `/tool/sniffer` streaming everything to `10.0.2.2:<port>` with `filter-stream=yes`; only frames that are UDP between ports 67 and 68 kept, the rest counted (`other`: 61 to 83 per run) |

Each datagram is labelled by its Ethernet source: `server`'s ether1 and
`client`'s ether2 are `routeros-client`, `server`'s ether2 is
`routeros-server`, and 52:55:0a:00:02:02 is `qemu-slirp`. **QEMU's replies
are QEMU's, not RouterOS's**: they are kept as the other side of the
client's exchange, and no test treats them as RouterOS behavior.

The evidence for each target is in [evidence/](evidence/): every command,
each router's identity and MACs, the ether1 dhcp-client before and after,
the server's lease, and every DHCP datagram with its arrival time.

## Experiments

| Experiment | Setup | Waits for |
| --- | --- | --- |
| `client-renew` | `server`: `/ip/dhcp-client/renew [find interface=ether1]` | RouterOS's REQUEST, QEMU's ACK |
| `server-exchange` | `server`: 192.168.88.1/24 on ether2, pool .10 to .20, `/ip/dhcp-server` with `lease-time=10m`, a network with gateway, DNS server and `domain=lab.test`; `client`: identity `lab-café`, a dhcp-client on ether2 | DISCOVER, OFFER, REQUEST, ACK |
| `server-release` | `client`: `/ip/dhcp-client/release [find interface=ether2]` | RELEASE |
| `client-release` | `server`: `/ip/dhcp-client/release [find interface=ether1]`, then wait for `bound` | RELEASE |

Each experiment keeps what arrives in the 2 s after its last wanted message
too, so a message that follows is seen.

## What it showed

The same on all four routers but for one IP TTL (below): with the xid,
MACs and leased address put aside, the DHCP messages decode identically.

- **Every message decodes with no problem**, through `dissect()` and
  `openCapture()` (the integration tier, `the router's own DHCP REQUEST
  decodes with no problem`). No option lands in `otherOptions`.
- **Sizes.** Every RouterOS message, client or server, is a 300-byte BOOTP
  message: End, then zero padding to the RFC 951 minimum. QEMU's ACK is 548
  bytes.
- **IP TTL, the one difference between versions.** Broadcast messages
  (DISCOVER, OFFER, the REQUEST in SELECTING, ACK) go out with TTL 16 on
  both versions; the unicast ones (the renewing REQUEST, RELEASE) with TTL
  64 on 7.24.6 and 16 on 7.25.1, on both architectures. QEMU's ACK has 64.
- **Client, renewing** (ether1, bound to QEMU): one REQUEST, unicast to
  10.0.2.2 (Ethernet to QEMU's MAC), ciaddr 10.0.2.15, broadcast flag clear,
  no requested-address option (RFC 2131 4.3.2, RENEWING). QEMU's ACK
  followed within 1 ms on x86 (to 255.255.255.255).
- **Client options**, in this order on the wire: message type, host name
  (the identity: `CHR` as booted; `lab-café` as the 9 bytes of its UTF-8
  form), parameter request list, client id (`01` and the interface's MAC),
  End (codes 53, 12, 55, 61), for DISCOVER and the renewing REQUEST. The
  REQUEST in SELECTING adds requested address and server id after the host
  name (53, 12, 50, 54, 55, 61). RELEASE carries 53, 54 and 61 only. The
  parameter request list is the same everywhere: 1, 121, 3, 33, 6, 42, 138,
  43, 15 (subnet mask, classless static route, router, static route, DNS
  servers, NTP servers, CAPWAP AC, vendor specific, domain name). No max
  message size, vendor class id or lease time is asked for. This is the
  dhcp-client as booted: `dhcp-options=hostname,clientid`,
  `use-broadcast=both`.
- **Broadcast flag.** Set on DISCOVER and on the REQUEST that answers an
  OFFER (ciaddr 0.0.0.0), clear once the client has an address (renewing
  REQUEST, RELEASE): `use-broadcast=both` as booted.
- **Server.** OFFER and ACK broadcast to 255.255.255.255 (Ethernet
  broadcast), from 192.168.88.1, with the broadcast flag echoed; options:
  message type, subnet mask, router, DNS server, domain name, lease time
  (600), server id, End (53, 1, 3, 6, 15, 51, 54). **No renewal (58) or rebinding (59) time.** The
  pool's top address, 192.168.88.20, was offered first. The OFFER came 0.51
  s after the DISCOVER on x86, 0.65 to 0.67 s on arm64; the REQUEST and ACK
  within 25 ms after it.
- **Release.** A RELEASE (unicast to the server, ciaddr set, the lease's
  xid), and then **at once a new DISCOVER**: the client releases and starts
  over (0.3 to 1.0 s later on the L2 link). On ether1 the stream then went
  quiet: with no address, `/tool/sniffer` streaming has no source, so the
  new exchange with QEMU was not seen, and the REST call that released
  returned only once the client was bound again. The lab therefore releases
  ether1 last and waits for `bound`.

## What it does not show

- A relay (giaddr, option 82), a NAK, DECLINE, INFORM, a static lease,
  option 43 or vendor options set on the server, `dhcp-options` changed on
  the client, or option overload: none was set up, and the dissector's
  vectors for them are host-made.
- DHCP on a VLAN or a bridge port, or more than one client.
- Hardware: only CHRs. arm64 under `tcg`, not hardware acceleration.
