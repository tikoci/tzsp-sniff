# tzsp-sniff agent entry point

tikoci rules are in the house skills: read
<https://tikoci.dev/house/skills/tikoci-house/SKILL.md> first. Which repo owns
what: <https://tikoci.dev/house/skills/tikoci-crossref/SKILL.md>.

`@tikoci/tzsp-sniff` receives TZSP streams from RouterOS (`/tool/sniffer`
streaming, mangle `action=sniff-tzsp`) on a plain UDP socket, with no root,
and decodes them for agents and people: a CLI and a TypeScript library.
README.md is the user overview.

## Commands

- `bun install`
- `bun run check`: the gate (lint, unit tests, build, Node smoke). CI runs
  the same scripts.
- `bun run lint:fix`: Biome format and safe fixes.
- `bun run test`: unit tier only.
- `bun run test:integration`: the integration tier on a CHR booted by
  quickchr (QEMU with `qemu-img`, UEFI firmware on arm64: README,
  "Development"; `node_modules/.bin/quickchr doctor` checks);
  `TZSP_SNIFF_ROUTEROS=<channel or version>` picks the router, default
  `stable`. Not part of `check`; CI runs it.
- `bun run test:tshark`: TShark reads a pcapng the writer made (needs
  `tshark` on `PATH`; `TZSP_SNIFF_TSHARK_VERSION` pins it). Not part of
  `check`; CI's `tshark` job runs it.
- `git config core.hooksPath .githooks` enables the pre-commit (Biome) and
  pre-push (lint) hooks.

## Layout

- `src/`: shipped library code. `src/index.ts` is the package entry.
- `test/unit/`: `bun:test`, loopback sockets only: no external network and
  no VM. `test/tshark/`: TShark reading our pcapng, behind
  `TZSP_SNIFF_TSHARK`. `test/smoke/`: the Node check
  against `dist/`. `test/node/`: `bun:test` cases that run the built CLI
  under Node (after `bun run build`). `test/integration/`: a real CHR,
  behind `TZSP_SNIFF_INTEGRATION`. `test/lab/`: experiments run by hand,
  with a `REPORT.md`. `test/chr/`: the quickchr machine handling and
  router REST calls those two share.
- `scripts/`: repo tooling run by Bun.
- `.scratch/`: gitignored temporary work.

## Rules for this repo

- **Shipped code runs on Node and Bun.** `src/` uses no `Bun.*` and no
  `bun:*` imports; `tsconfig.src.json` checks it with Node's types only, and
  `test/smoke/node-smoke.mjs` loads the built `dist/` under Node. Tests and
  scripts may use Bun freely (tikoci-toolchain, "Node only where shipped code
  runs on Node"). Reason: users run it with `npx` or `bunx`, and other tikoci
  tools import it.
- **Parsers never throw.** A malformed datagram or frame yields a record with
  a `problem` and its raw bytes, so one bad packet cannot stop a capture.
- **RouterOS wire facts are grounded.** A comment that states how RouterOS
  sends something names the RouterOS version, architecture and the capture or
  test that showed it (tikoci-grounding). Protocol numbers from Wireshark are
  cited by file and commit; no Wireshark code is copied (it is GPL).
- **Small items** go in [BACKLOG.md](BACKLOG.md); work with an end point is
  an issue.
- **Design and its reasons** are in [DESIGN.md](DESIGN.md). Do not bring
  back, without a new decision there: an embedded Lua VM or FFI to run
  Wireshark dissectors ("Decided: no embedded Lua or Wireshark"), or `Bun.*`
  in shipped code ("Decided: Node and `npx`").

## Workflow

Work toward 0.1.0 is planned in #18: ordered slices, one sub-issue each,
with its scope, a "Done when" checklist and what it leaves out.

- **The next slice is the first open sub-issue of #18.** Asked to continue,
  work it; do not re-derive the plan from DESIGN.md.
- **A slice runs without asking for permission**, through tikoci-pr-flow:
  branch from `main`, build to the issue's "Done when", run `bun run
  check`, commit, push, open a draft PR with `Closes #N`, get the
  cross-review, and hand back with the PR link. The maintainer merges. A
  slice too big for one PR is split into issues first, each with its own
  "Done when", and each PR says `Part of #N`.
- **Done, for every slice:**
  - every "Done when" item is met, or moved to a follow-up issue linked
    from the PR; none is dropped silently;
  - every behavior change has a test that was seen failing once;
  - `bun run check` passes, and the PR names any check that could not run
    locally and the CI job that runs it;
  - CHANGELOG has a bullet for each user-visible change, README matches,
    and DESIGN.md records each decision made and each **Unverified** claim
    settled;
  - small leftovers are in BACKLOG.md;
  - #18's **Next** line names the following slice.
- **Stop and ask** only to change something DESIGN.md marks **Decided**, to
  narrow or reorder a slice, or when a slice waits on an open grounding
  issue (#8, #9).
- When a plan is done, the next one is a new planning issue of the same
  shape, and this section points to it.

## House skills

- tikoci-toolchain (copied)
- tikoci-cli-mcp (copied)
- tikoci-testing (copied)
- tikoci-grounding (copied)
- tikoci-linting (copied)
- tikoci-pr-flow (copied): every slice goes through it.
- tikoci-house, tikoci-crossref, tikoci-docs, tikoci-ci, tikoci-dependencies,
  tikoci-release, tikoci-github, tikoci-data-contracts (referenced): read `https://tikoci.dev/house/skills/<name>/SKILL.md` when
  the task matches its "Use when".
- tikoci-home (referenced, not adopted): the tool keeps no files outside the
  checkout. Its environment variables follow the `<TOOL>_<KEY>` naming
  (`TZSP_SNIFF_*`).

## House exceptions

- **No `--json` document mode**: `--format jsonl` is the machine output,
  and `jq -s .` makes one document from it (tikoci-cli-mcp, "Output";
  DESIGN.md, "Decided: JSONL, no `--format json`").

- **Biome formatter on** (tabs, double quotes; Markdown excluded), from the
  first commit: in a repo with no prior code it costs no noisy diffs, and
  every agent then writes one shape (tikoci-linting, "Lint: Biome").
