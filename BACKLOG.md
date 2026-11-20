# Backlog

Small items, one or two sentences each, deleted when done or declined
(tikoci-docs). Anything bigger is an issue.

- Add the repo to tikoci.github.io
  `data/repo-config.ts` so tikoci-crossref lists it.
- quickchr: if a lab wants it, advertise a TZSP receiver endpoint per VM
  (address and port the guest should send to), not a `hostfwd` entry:
  tzsp-sniff must own the host socket (DESIGN.md, "Not quickchr's port map").
- m2ir: add a LICENSE file matching the README's CC0-1.0 for schema
  content; nothing here is generated from m2ir until it has one (DESIGN.md).
- Dissect TZSP inside UDP to the listener's port, capped, so the
  `filter-stream=no` self-capture (#5 fixtures) reads as nested layers
  rather than UDP data.
- Test binding `::` and an IPv6 peer in the unit tier, once CI's runners are
  known to have IPv6 loopback on all three OSes.
- Windows: Node makes stdout and stderr pipes synchronous there
  (`net.Socket` calls `setBlocking(true)` and `makeSyncWrite` for fd 1 and 2
  when they are a Pipe), so a pipe reader that stops reading can block the
  event loop as a POSIX terminal did. Measure on windows-latest under Node
  and Bun before changing `terminalStream`: `fs.write` made Node's
  `process.exit()` wait for the stuck pool thread on Linux.
- Idea, not a requirement: a periodic summary while `--follow` runs (every
  so often, gently, with a flag to turn it off), as a watch view. It would
  also make a quiet `--follow | head` notice the closed pipe.
- Consider a larger socket receive buffer (`recvBufferSize`) once a busy
  capture shows kernel drops; check Bun supports the option first.
- Filters select frames only (DESIGN.md, "Decided, filters"): consider
  letting `--sender` also select control, unsupported and invalid records,
  which would need its own counter so the counters still add up.
- quickchr upstream, each to follow up here once fixed:
  - tikoci/quickchr#292: one deadline for consumers, so `test/chr/` stops
    quoting download, lock and boot-failure budgets from quickchr's source.
  - tikoci/quickchr#293: the default arch under Rosetta, in `start` and
    `cacheAdd`; once fixed, `hostArch()`'s `sysctl` check can go.
  - tikoci/quickchr#294: `remove` that will not delete a running machine's
    directory; once fixed, `test/chr/`'s unreadable-state advice can say
    `quickchr remove <name>` alone.
  - tikoci/quickchr#298: a failed first state save after QEMU is spawned
    leaves QEMU running; once fixed, `test/chr/`'s `qemuFor` check can go.
  - tikoci/quickchr#295: a cache directory apart from the data directory;
    once there, a local run can use a private `QUICKCHR_DATA_DIR` and drop
    the `createdAt` ownership checks.
  - tikoci/quickchr#290 and #291 (`add`'s stdout, `timeoutExtra` on an
    `add`-made machine) are avoided by creating with one `start`, not
    waited on.
- Sweep: skip a night when neither `main` nor any resolved channel version
  changed since the last green sweep (centrs fingerprints both), once the
  nightly boots cost more than they tell.
- Integration: reap `tzsp-it-` machines a killed run left behind, once it
  can tell them from a run still in progress (quickchr has no owner field).
- CI smoke waits for the whole unit matrix; split the Linux unit leg out
  (centrs `unit-linux`) if macOS or Windows make it wait noticeably.
- zizmor `self-repository` (a note) asks for `$/.github/workflows/…` in
  place of `./.github/workflows/…`; actionlint 1.7.12 rejects that form,
  so switch once actionlint accepts it.
- `--port-match` ranges (`8000-8100`), if a lab asks for one.
- pcapng: an interface statistics block at close (`isb_ifrecv`,
  `isb_ifdrop` per listener), once the listener counts drops per port.
- pcapng: microsecond arrival times (`performance.timeOrigin +
  performance.now()`, `if_tsresol` 6), if a lab needs finer ordering than
  the sequence number gives.
- `decode --format pcapng` (refused in slice 5): filter a TZSP file down to
  a smaller one; inputs with no TZSP datagram (a file RouterOS saved) would
  still be refused.
- `decode <named pipe>` (refused in slice 5, since a `FileHandle` read on
  it cannot be cancelled and Ctrl-C would wait on the producer): read a
  FIFO through a cancellable stream, if `<(...)` is asked for.
- `openDecode()` on a Node `Readable` that has gone quiet: closing the
  decode wakes it, but Node's stream iterator queues `return()` behind the
  pending read, so the stream stays open until data comes. Calling
  `destroy()` when the input has one, as the CLI does for stdin, would
  release it (final review of 888b9b5).
- `openDecode()` hears the caller's abort through an `abort` listener; one
  added earlier that calls `stopImmediatePropagation()` keeps it from
  running, and a pull waiting on the input stays pending. A subscription
  that survives that, if a caller shares its signal that way (final review
  of 888b9b5).
- A filter on a decoded file's `interface` (`ether1 rx`), if a lab asks for
  the direction.
- `decode`: reassemble IP fragments of UDP to the TZSP port, so a TZSP
  datagram over the path MTU (the `filter-stream=no` loop, #5) decodes
  whole.
- Dissector registry: matches on a UDP or TCP port, and the heuristic hook,
  with the first dissector reached that way (DNS or DHCP, after 0.1.0), and
  a way for a dissector to decline; the plan and its open questions are in
  DESIGN.md, "Decided: a dissector registry", "How port matches fit".
- Recovery hints that print placeholders (`tzsp-sniff decode <file>` for
  pcapng on listen; `run tzsp-sniff decode --input` for a flag of the wrong
  command) do not run as printed (tikoci-cli-mcp); point to a command that
  runs, as `dissectors` now does with `--help` (Codex re-review of PR #27).
- LLDP, **Unverified**: whether 802.1AB makes two more cases malformed. One
  is an enabled capability that the system capabilities lack (`00000010`).
  The other is a management address with `unknown` interface numbering and
  a non-zero number. Codex's review of PR #28 cited clauses 8.5.8.3 and
  8.5.9.6 from a copy we could not read. Neither Wireshark (packet-lldp.c
  at ffc784d8541a) nor RouterOS's own LLDP shows them. Decide once the
  standard's text is checked.
