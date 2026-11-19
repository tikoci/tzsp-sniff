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
- `git config core.hooksPath .githooks` enables the pre-commit (Biome) and
  pre-push (lint) hooks.

## Layout

- `src/`: shipped library code. `src/index.ts` is the package entry.
- `test/unit/`: `bun:test`, no network or VM. `test/smoke/`: the Node check
  against `dist/`.
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

## House skills

- tikoci-toolchain (copied)
- tikoci-cli-mcp (copied)
- tikoci-testing (copied)
- tikoci-grounding (copied)
- tikoci-linting (copied)
- tikoci-house, tikoci-crossref, tikoci-docs, tikoci-ci, tikoci-dependencies,
  tikoci-release, tikoci-github, tikoci-pr-flow, tikoci-data-contracts
  (referenced): read `https://tikoci.dev/house/skills/<name>/SKILL.md` when
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
