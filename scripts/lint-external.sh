#!/bin/sh
# Linters bun install does not provide (tikoci-linting): shellcheck and
# actionlint. A local run skips a missing tool and says so; with CI set, a
# missing tool fails, so a broken install step cannot remove the gate.
set -eu

missing=0
run() {
	tool=$1
	shift
	if command -v "$tool" > /dev/null 2>&1; then
		"$tool" "$@"
	elif [ -n "${CI:-}" ]; then
		echo "lint-external: $tool is not installed (required in CI)" >&2
		missing=1
	else
		echo "lint-external: skipped $tool (not installed; see README, Development)" >&2
	fi
}

run shellcheck -s sh --severity=warning .githooks/pre-commit .githooks/pre-push scripts/lint-external.sh
run actionlint
exit "$missing"
