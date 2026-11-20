# Changelog

User-visible changes to `@tikoci/tzsp-sniff`, one section per stable version
(tikoci-release). Work in progress goes under `## X.Y.Z — next`, matching
package.json's `X.Y.Z-next`; the stable release replaces `next` with the date.

## 0.1.0 — next

### Added

- `dissectors` and `dissectors()`: each protocol decoded, how it is reached
  (link type, EtherType, IP protocol) and its layer's fields, with type and
  whether each can be absent; text, or one `dissector` record per protocol
  with `--format jsonl`. The list is read from the registry that dispatch
  goes through, as is `--proto`'s.

- `decode <file|->`: the capture pipeline over a pcapng or pcap file
  (detected from its first bytes, either byte order), hex lines (`--input
  hex`) or stdin, with no network: the same records, filters, `--fields`,
  `--detail`, `--stats`, `--count` and `--expect`. A `--write` file decodes
  to the records the capture printed (listener label and peer restored, an IPv6 zone too); a
  file RouterOS saved decodes as Ethernet frames with their `interface` and
  `comment`; UDP to the TZSP port in an Ethernet, raw IP or Linux cooked
  capture is unwrapped (`--tzsp-port` to change the port). Other link types
  end with `decode/link-type`; a corrupt file with `decode/malformed` and
  exit 1, after the records before the damage; a file cut inside a block
  warns `decode/truncated` and is `incomplete`. Lengths are capped before
  anything is allocated (1 MiB per block or pcap record with its header,
  128 KiB per hex line, 4,096 interfaces and 1 MiB of names per pcapng
  section), and the structure is checked: pcap magic, version and snap
  length, simple packet block sizes, a section's declared length (a multiple of
  4), and
  timestamps a Date can hold. Ctrl-C ends `decode -` even while the
  producer keeps stdin open or is slow to clean up, and an aborted
  `openDecode()` releases its input whether or not a record was read, and
  closing one settles while a read waits on a quiet input; a path that is not a regular file (a named
  pipe, a device) is refused with `decode/read-failed`, whose fix says to
  pipe it to `decode -`. A flag of
  `listen` under `decode`, and the reverse, is refused with
  `cli/wrong-command`, which names the command it belongs to.
- `openDecode(input, options)` in the library, with `DecodeOptions`,
  `DecodeStream`, `MAX_BLOCK_BYTES`, `MAX_HEX_LINE`, `MAX_INTERFACES` and
  `MAX_INTERFACE_NAME_BYTES`. Decoded records may lack `time`, `listener`
  and `peer` (files that do not say them); `openCapture()` yields
  `CaptureRecord`, which keeps them required. Records gain `interface` and
  `comment`; headers carry `command` (`listen` or
  `decode`); `stoppedBy` gains `end`; a decode's sender rows may lack
  `listener` or `peer`. `packetRecord()`, `datagramRecord()`, filters and `summarize()`
  take an `Entry`, which a listener's `Capture` is.
- `--write` refuses listeners whose labels pass what one pcapng section
  holds and `decode` reads back (4,096 interfaces, 1 MiB of names), with
  `write/invalid-option` before the file is touched.
- `--write <file>`: save every datagram the capture reads, as received,
  before filters and whatever `--format`, `--detail` or `--stats` print
  (the summary's `dropped` and `unread` count what it never read), as pcapng with link
  type TZSP (128): one interface per listener (its label and port), the
  arrival time on each block, and the UDP peer as the block's comment
  (`peer=<address>:<port>`). Wireshark and TShark open it. The file is
  created new and owner-only (an existing one is `write/exists`;
  `--overwrite` replaces a regular file with a new owner-only one), written
  block by block so Ctrl-C leaves a valid file, and named in the header;
  the summary gains `written` (datagrams and bytes). A write or close
  failure ends the capture with `write/failed` (or `write/stalled`) and
  exit 1, the file still ending at its last whole block, and the datagram
  being saved counts in the new `unsaved` counter.
  The file stdout or stderr is redirected to is refused
  (`cli/write-to-output`).
- `--format pcapng`: the same format on stdout, with filters applied
  (control and invalid records included). Refused on a terminal
  (`cli/binary-to-terminal`) and with `--fields`, `--stats` or `--detail`.
- `pcapngWriter(sink)` (sink calls run one at a time, in order, even when
  writes are not awaited), `fileSink(path, { overwrite })` and
  `LINKTYPE_TZSP` in the library; `openCapture()` takes `write` and
  `writeReported` writers.
- Filters: `--proto`, `--host`, `--net`, `--port-match`, `--mac`,
  `--ether-type` and `--sender`, with `--src-` and `--dst-` forms for host,
  net, mac and port-match, and a `--not-` form of each. Repeating a flag or
  giving a comma list ORs its values; different flags AND. A packet without
  the field matches no filter and is not removed by a `--not-` one. Removed
  frames are counted as `filtered`; when filters remove every frame, the
  `capture/all-filtered` warning names them. The header lists the filters
  in effect, and `--count` and `--expect` count after them. A value that
  does not parse is `filter/invalid-value` (exit 2).
- `--fields a,b,c`: only the named fields of each packet and record, in
  that order, and of the summary in JSONL or, in text, with `--stats` (a
  text summary field without `--stats` is refused); `type`, and a
  summary's `status`, always stay. Without `--detail`, the detail is
  raised to carry the fields.
- `createFilter(spec)`: the filters as a library function, with
  `filterFlags()` and `FILTER_KEYS`; `selectFields()`, `ENTRY_FIELDS` and
  `SUMMARY_FIELDS` for `--fields`. `openCapture()` takes `filter`.
- `tzsp-sniff` CLI, `listen` command (the default): receives TZSP on one or
  more UDP ports (`--port <port>[=<label>]`, `--bind`), stops at `--count`,
  `--duration` or `--idle`, or runs to Ctrl-C with `--follow`, and stops
  after 10 seconds with a `tip/default-duration` when no limit is given.
  `--format text|jsonl`, `--detail line|summary|layers|full`, `--stats`
  and `--expect`. Exit 0 done (an empty capture carries a
  `capture/no-datagrams` or `capture/no-frames` warning), 1 the capture
  failed or `--expect` was not met, 2 a usage error, 130 interrupted before
  the capture started or by a second Ctrl-C (no summary). Runs on Node 22 or
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
