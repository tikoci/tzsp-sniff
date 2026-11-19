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
  - tikoci/quickchr#290: `add` prints image lines to stdout despite
    `onProgress`.
  - tikoci/quickchr#291: `start` of an `add`-made machine ignores
    `timeoutExtra`; once fixed, `test/chr/` can honor
    `QUICKCHR_TIMEOUT_EXTRA`.
  - tikoci/quickchr#292: one deadline for consumers, so `test/chr/` stops
    quoting download and lock budgets from quickchr's source.
  - tikoci/quickchr#293: the default arch under Rosetta; once fixed,
    `hostArch()`'s `sysctl` check can go.
  - tikoci/quickchr#294: a `start` bound to the machine `add` made, and
    `remove` that will not delete a running machine's directory.
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
