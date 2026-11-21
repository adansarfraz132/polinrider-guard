#!/usr/bin/env bash
# apply-dev-defaults.sh [--apply] - apply the safe defaults from safe-defaults/ for the
# CURRENT user. Dry run by default: prints what it would change. Backs up files it edits.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
APPLY=0; [[ "${1:-}" == "--apply" ]] && APPLY=1
do_() { if [[ ${APPLY} -eq 1 ]]; then echo "+ $*"; "$@"; else echo "(dry run) $*"; fi; }

# npm
if command -v npm >/dev/null 2>&1; then
  [[ "$(npm config get ignore-scripts)" == "true" ]] || do_ npm config set ignore-scripts true --location=user
  if npm config ls -l 2>/dev/null | grep -q '^min-release-age'; then
    [[ "$(npm config get min-release-age)" == "1" ]] || do_ npm config set min-release-age 1 --location=user
  else echo "npm $(npm --version) has no min-release-age; upgrade npm to get it."; fi
fi
# yarn berry
if command -v yarn >/dev/null 2>&1 && ! yarn --version 2>/dev/null | grep -q '^1\.'; then
  do_ yarn config set enableScripts false --home
fi
# VS Code-family user settings: insert keys only if missing; never rewrite existing JSONC.
case "$(uname -s)" in
  Darwin) base="${HOME}/Library/Application Support" ;;
  *) base="${XDG_CONFIG_HOME:-${HOME}/.config}" ;;
esac
for app in Code "Code - Insiders" Cursor VSCodium Windsurf; do
  f="${base}/${app}/User/settings.json"
  [[ -d "$(dirname "${f}")" ]] || continue
  [[ -f "${f}" ]] || { do_ sh -c "printf '{\n}\n' > \"${f}\""; }
  add=""
  for kv in '"task.allowAutomaticTasks": "off"' '"security.workspace.trust.enabled": true' \
            '"security.workspace.trust.untrustedFiles": "open"' '"security.workspace.trust.emptyWindow": false' \
            '"security.workspace.trust.startupPrompt": "always"' \
            '"extensions.autoUpdate": false' '"extensions.autoCheckUpdates": false'; do
    key="${kv%%:*}"
    if [[ -f "${f}" ]] && grep -qF "${key}" "${f}"; then
      grep -F "${key}" "${f}" | grep -qF "${kv}" || echo "NOTE ${app}: ${key} is set to a different value; change it by hand to ${kv#*: }"
    else add="${add}  ${kv},"$'\n'; fi
  done
  if [[ -n "${add}" ]]; then
    if [[ ${APPLY} -eq 1 ]]; then
      cp "${f}" "${f}.bak.$(date +%Y%m%d%H%M%S)"
      perl -0pi -e 'BEGIN { $a = shift @ARGV } s/\{/"{\n" . $a/e' "${add}" "${f}"
      echo "+ updated ${f} (backup next to it)"
    else printf '(dry run) add to %s:\n%s' "${f}" "${add}"; fi
  fi
done
# git hooks + fsck
cur="$(git config --global core.hooksPath || true)"
[[ "${cur}" == "${HOME}/.polinrider-guard/hooks" ]] || do_ "${HERE}/install-hooks.sh"
[[ ${APPLY} -eq 1 ]] || echo "Dry run only. Re-run with --apply to make these changes."
