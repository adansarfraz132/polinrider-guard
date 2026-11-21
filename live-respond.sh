#!/usr/bin/env bash
# live-respond.sh - find PolinRider activity that is running NOW and the places it can start
# again from, optionally stop it (--kill) and move it aside (--quarantine), then say whether
# it is safe to rotate credentials. Default is report only. See README "If you're already infected".
#
# Usage: live-respond.sh [--kill] [--quarantine] [--watch [--interval N]] [--scan-dir DIR]...
#        live-respond.sh --restore QUARANTINE_DIR --yes
#        live-respond.sh history [history-report.sh options]
# Exit codes: 0 = SAFE TO ROTATE CREDENTIALS, 2 = NOT SAFE YET, 3 = error.
# Requires bash and perl (macOS, Linux, Git for Windows). On Windows use live-respond.ps1.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
command -v perl >/dev/null 2>&1 || { echo "perl is required (it ships with macOS, Linux and Git for Windows)." >&2; exit 3; }
if [[ "${1:-}" == "history" ]]; then shift; exec "${HERE}/history-report.sh" "$@"; fi
exec perl "${HERE}/lib/live-core.pl" "$@"
