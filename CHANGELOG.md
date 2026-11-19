# Changelog

User-visible changes to `@tikoci/tzsp-sniff`, one section per stable version
(tikoci-release). Work in progress goes under `## X.Y.Z — next`, matching
package.json's `X.Y.Z-next`; the stable release replaces `next` with the date.

## 0.1.0 — next

### Added

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
