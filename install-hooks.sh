#!/usr/bin/env bash
# install-hooks.sh [--uninstall] - point git's global core.hooksPath at this kit's hooks so
# every clone, checkout and pull is scanned, and commits with malware markers are blocked.
# Repos that set their own local core.hooksPath (husky, lefthook) override this; use
# safe-pull.sh in those, or run scan-repo.sh manually.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DEST="${HOME:?}/.polinrider-guard"
if [[ "${1:-}" == "--uninstall" ]]; then
  git config --global --unset core.hooksPath || true; echo "Removed global core.hooksPath."; exit 0
fi
cur="$(git config --global core.hooksPath || true)"
if [[ -n "${cur}" && "${cur}" != "${DEST}/hooks" ]]; then
  echo "core.hooksPath is already set to ${cur}. Not overwriting; merge by hand." >&2; exit 1
fi
mkdir -p "${DEST}"
rm -rf "${DEST:?}/hooks" "${DEST:?}/lib" "${DEST:?}/iocs.new"
cp -R "${HERE}/hooks" "${HERE}/lib" "${DEST}/"
cp -R "${HERE}/iocs" "${DEST}/iocs.new" && rm -rf "${DEST}/iocs" && mv "${DEST}/iocs.new" "${DEST}/iocs"
cp "${HERE}/scan-repo.sh" "${HERE}/safe-clone.sh" "${HERE}/safe-pull.sh" "${HERE}/safe-install.sh" "${HERE}/host-check.sh" "${DEST}/"
chmod +x "${DEST}"/*.sh "${DEST}/hooks/"*
git config --global core.hooksPath "${DEST}/hooks"
# Extra git safety that costs nothing: verify objects on fetch.
git config --global transfer.fsckObjects true
git config --global fetch.fsckObjects true
echo "Installed to ${DEST}. Global hooks: $(git config --global core.hooksPath)"
echo "Tip: add  alias sclone='${DEST}/safe-clone.sh' spull='${DEST}/safe-pull.sh' sinstall='${DEST}/safe-install.sh'  to your shell rc."
