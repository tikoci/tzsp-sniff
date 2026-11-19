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
- Under Bun, a terminal that stops reading (Ctrl-S, an unread PTY) still
  blocks the event loop, so neither `output/stalled` nor SIGINT can end the
  capture; Node is fixed by `unblockTerminal` (PR #20 review). Find a Bun
  way to make TTY writes non-blocking, or move them off the main thread.
- Consider a larger socket receive buffer (`recvBufferSize`) once a busy
  capture shows kernel drops; check Bun supports the option first.
