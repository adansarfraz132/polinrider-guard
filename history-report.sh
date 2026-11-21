#!/usr/bin/env bash
# history-report.sh - read-only git forensics: when did PolinRider code enter each repo's
# history, which commits and branches carry it, is HEAD still infected, and (optionally,
# with --github owner/repo) do that repo's public forks carry the same code.
#
# Usage: history-report.sh [--json FILE] [--max-commits N] [--github OWNER/REPO [--max-forks N]]
#                          [--fingerprint STR]... [--no-code-search] [PATH...]
# Exit codes: 0 = clean, 1 = infected only in history, 2 = infected now, 3 = error.
# Requires bash, perl and git; --github also needs curl. Never changes a repository.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
command -v perl >/dev/null 2>&1 || { echo "perl is required." >&2; exit 3; }
command -v git >/dev/null 2>&1 || { echo "git is required." >&2; exit 3; }
exec perl "${HERE}/lib/history-core.pl" "$@"
