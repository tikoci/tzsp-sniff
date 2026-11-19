# Changelog

User-visible changes to `@tikoci/tzsp-sniff`, one section per stable version
(tikoci-release). Work in progress goes under `## X.Y.Z — next`, matching
package.json's `X.Y.Z-next`; the stable release replaces `next` with the date.

## 0.1.0 — next

### Added

- `tzsp-sniff` CLI, `listen` command (the default): receives TZSP on one or
  more UDP ports (`--port <port>[=<label>]`, `--bind`), stops at `--count`,
  `--duration` or `--idle`, or runs to Ctrl-C with `--follow`, and stops
  after 10 seconds with a `tip/default-duration` when no limit is given
  (`--format json` needs an explicit `--count` or `--duration`, and stops at
  10,000 entries or 64 MiB of them).
  `--format text|jsonl|json`, `--detail line|summary|layers|full`, `--stats`
  and `--expect`. Exit 0 done (an empty capture carries a
  `capture/no-datagrams` or `capture/no-frames` warning), 1 the capture
  failed or `--expect` was not met, 2 a usage error. Runs on Node 22 or
  later and on Bun.
- `openCapture()`: the capture as a stream of records, a `header` first and
  one `summary` last (status, counters, protocol, problem, sender and
  conversation tables), with `packet`, `record`, `warning` and `tip` between.
- `listen()`: one UDP socket per port, a bounded queue (`DEFAULT_QUEUE`,
  10,000 datagrams or 16 MiB) that drops and counts when full, and a
  lifecycle that closes every socket on abort, `close()`, `break`, an error
  in the consumer or a failed bind (`listen/bind-failed` names the port).
- `dissect()`: Ethernet, 802.1Q and 802.1ad, ARP, IPv4, IPv6 (extension
  headers capped at 8), ICMP, ICMPv6, UDP and TCP, each layer with its span,
  fields and any `problem`; never throws.
- `CODES` and `TzspSniffError`: every error, warning and tip code in one
  registry.
- `parseTzsp()`: parses a TZSP datagram into its version, type,
  encapsulation, tags and payload, and reports a malformed one as a `problem`
  instead of throwing.
- `parseTzsp()` results carry a `kind` (`packet`, `control`, `unsupported`
  or `invalid`) and the complete `datagram` (a view of the input, not a
  copy). Keepalive and port-opener records parse as `control`; only a
  received Ethernet record is a `packet` to dissect. `problem` is now
  `truncated`, `malformed` or `unsupported`, with the failed check in
  `reason`; the exported type ties each `problem` and `reason` to its
  `kind`. Every type but keepalive and port-opener has its tag list
  checked, as Wireshark does, and a datagram with more than `TZSP_MAX_TAGS`
  (64) tags stops as `unsupported`.
