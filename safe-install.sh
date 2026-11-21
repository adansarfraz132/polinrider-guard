#!/usr/bin/env bash
# safe-install.sh [DIR] - scan, install dependencies with lifecycle scripts OFF, then re-scan
# node_modules. Build scripts you actually need can be run afterwards, one trusted package
# at a time (npm rebuild <pkg>, or list them in pnpm allowBuilds).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
dir="${1:-.}"; cd "${dir}" || exit 3
"${HERE}/scan-repo.sh" --with-tools .
rc=$?
[[ ${rc} -eq 2 ]] && { echo "Install refused (HIGH findings)." >&2; exit 2; }
if [[ ${rc} -eq 1 && -z "${YES:-}" ]]; then read -r -p "MEDIUM findings above. Install anyway with scripts disabled? [y/N] " a; [[ "${a}" == [yY] ]] || exit 1; fi
if   [[ -f pnpm-lock.yaml ]]; then pnpm install --frozen-lockfile --ignore-scripts
elif [[ -f yarn.lock ]]; then
  if yarn --version 2>/dev/null | grep -q '^1\.'; then yarn install --frozen-lockfile --ignore-scripts; else YARN_ENABLE_SCRIPTS=false yarn install --immutable; fi
elif [[ -f bun.lock || -f bun.lockb ]]; then bun install --frozen-lockfile --ignore-scripts
elif [[ -f package-lock.json || -f npm-shrinkwrap.json ]]; then npm ci --ignore-scripts --no-audit --no-fund
elif [[ -f package.json ]]; then echo "No lockfile: refusing a floating install. Ask the repo owner for a lockfile, or run: npm install --ignore-scripts --package-lock-only, review it, then rerun." >&2; exit 1
else echo "No JavaScript project here. For Python, use a venv and: pip install --only-binary=:all: -r requirements.txt" >&2; exit 0
fi
echo "Re-scanning installed packages (node_modules)..."
"${HERE}/scan-repo.sh" --deep --no-git .
