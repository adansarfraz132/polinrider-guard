#!/usr/bin/env bash
# safe-pull.sh [REMOTE] [BRANCH] - fetch, scan the INCOMING tree in a temp folder, and only
# fast-forward if it is clean. Nothing from the remote touches your working tree first.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
G=(git -c core.hooksPath=/dev/null -c core.fsmonitor=false)
"${G[@]}" rev-parse --git-dir >/dev/null 2>&1 || { echo "Not a git repo." >&2; exit 3; }
upstream="$("${G[@]}" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
remote="${1:-${upstream%%/*}}"; branch="${2:-${upstream#*/}}"
[[ -n "${remote}" && -n "${branch}" ]] || { echo "No upstream set; pass REMOTE BRANCH." >&2; exit 3; }
"${G[@]}" fetch --no-recurse-submodules "${remote}" "${branch}" || exit 3
incoming="$("${G[@]}" rev-parse FETCH_HEAD)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/safe-pull.XXXXXX")"; trap 'rm -rf "${tmp}"' EXIT
"${G[@]}" archive "${incoming}" | tar -x -C "${tmp}"
echo "Files changed by this pull:"; "${G[@]}" diff --stat HEAD "${incoming}" | tail -n 25
"${HERE}/scan-repo.sh" --no-git "${tmp}"
rc=$?
if [[ ${rc} -eq 2 ]]; then echo "Pull refused: the incoming code has HIGH findings. Nothing was merged. Tell your security team." >&2; exit 2; fi
if [[ ${rc} -eq 1 && -z "${YES:-}" ]]; then
  read -r -p "MEDIUM findings above. Merge anyway? [y/N] " a; [[ "${a}" == [yY] ]] || exit 1
fi
"${G[@]}" merge --ff-only "${incoming}"
