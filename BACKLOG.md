# Backlog

Small items, one or two sentences each, deleted when done or declined
(tikoci-docs). Anything bigger becomes an issue once the GitHub repo exists.

- Before the first push: create `tikoci/tzsp-sniff` per tikoci-github
  (settings, `skip-review` label, CodeQL default setup) and fill in
  SECURITY.md's State column from the read-back.
- After the first push: add the repo to tikoci.github.io
  `data/repo-config.ts` so tikoci-crossref lists it.
- quickchr: if a lab wants it, advertise a TZSP receiver endpoint per VM
  (address and port the guest should send to), not a `hostfwd` entry:
  tzsp-sniff must own the host socket (DESIGN.md, "Not quickchr's port map").
- m2ir: add a LICENSE file matching the README's CC0-1.0 for schema
  content; nothing here is generated from m2ir until it has one (DESIGN.md).
