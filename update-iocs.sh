#!/usr/bin/env bash
# update-iocs.sh - refresh the public SafeDep IOC snapshot used as an extra data source.
# The CSV is treated as DATA ONLY (string/hash lookups); nothing in it is executed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
out="${HERE}/iocs/feeds/safedep-ioc.csv"; tmp="${out}.tmp"
curl -fsSL --proto '=https' --max-time 60 -o "${tmp}" https://safedep.io/ti/ioc.csv
head -n 1 "${tmp}" | grep -q '^"kind","value"' || { echo "Unexpected feed format; keeping the old snapshot." >&2; rm -f "${tmp}"; exit 1; }
mv "${tmp}" "${out}"
echo "Updated ${out}: $(($(wc -l < "${out}") - 1)) IOCs, $(date '+%Y-%m-%d %H:%M %Z')"
