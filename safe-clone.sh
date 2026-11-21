#!/usr/bin/env bash
# safe-clone.sh URL [DIR] - clone with every repo-supplied hook disabled, scan, and
# quarantine the folder if HIGH findings appear. Use instead of a plain `git clone`
# for anything from outside your organization (job tests, "take-home" repos, client code, PRs).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
url="${1:?usage: safe-clone.sh URL [DIR]}"
dir="${2:-$(basename "${url%.git}")}"
# Clone without our post-checkout hook (we scan explicitly) and without submodules/LFS smudge.
GIT_LFS_SKIP_SMUDGE=1 git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
  clone --no-recurse-submodules "${url}" "${dir}" || exit 3
"${HERE}/scan-repo.sh" "${dir}"
rc=$?
if [[ ${rc} -eq 2 ]]; then
  q="${dir}.QUARANTINED-DO-NOT-OPEN"
  mv "${dir}" "${q}"
  echo "Moved to ${q}. Do not open it in an editor or install anything. Tell your security team." >&2
fi
exit "${rc}"
