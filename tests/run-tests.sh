#!/usr/bin/env bash
# Self-test for scan-repo.sh using HARMLESS synthetic samples created in a temp dir.
# Nothing here is real malware: the "payloads" are inert strings that only carry the
# published marker text, so the scanner has something to find. Nothing is executed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SCAN="${HERE}/../scan-repo.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/scan-selftest.XXXXXX")"
trap '[[ -n "${KEEP:-}" ]] || rm -rf "${T}"' EXIT
pass=0 fail=0
ok()  { pass=$((pass+1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail+1)); printf 'FAIL %s\n' "$1"; }
gitc() { git -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false "$@"; }

# ---------------------------------------------------------------- clean sample
C="${T}/clean"; mkdir -p "${C}/public/fonts" "${C}/src" "${C}/.vscode"
cat > "${C}/package.json" <<'EOF'
{ "name": "clean-sample", "version": "1.0.0", "private": true,
  "scripts": { "build": "vite build", "dev": "vite" },
  "dependencies": { "react": "^18.3.1" } }
EOF
cat > "${C}/package-lock.json" <<'EOF'
{
  "name": "clean-sample",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "clean-sample"
    },
    "node_modules/react": {
      "version": "18.3.1",
      "resolved": "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
      "integrity": "sha512-AAAA"
    }
  }
}
EOF
printf 'export default {\n  plugins: { tailwindcss: {}, autoprefixer: {} },\n};\n' > "${C}/postcss.config.mjs"
printf 'export const add = (a, b) => a + b;\n' > "${C}/src/math.js"
printf 'wOF2\0\1\0\0fakebutvalidheader' > "${C}/public/fonts/fa-solid-400.woff2"
printf '{ "version": "2.0.0", "tasks": [ { "label": "build", "type": "shell", "command": "npm run build" } ] }\n' > "${C}/.vscode/tasks.json"

set +e; "${SCAN}" --no-git "${C}" > "${T}/clean.out" 2>&1; rc=$?; set -e
if [[ ${rc} -eq 0 ]]; then ok "clean sample exits 0"; else bad "clean sample exit ${rc}"; cat "${T}/clean.out"; fi

# ---------------------------------------------------------------- dirty sample
D="${T}/dirty"; mkdir -p "${D}/public/fonts" "${D}/src" "${D}/.vscode" "${D}/.devcontainer" "${D}/bin"
cat > "${D}/package.json" <<'EOF'
{ "name": "dirty-sample", "version": "1.0.0",
  "scripts": { "postinstall": "node -e \"console.log('inert test')\"", "start": "node src/app.js" },
  "dependencies": { "tailwindcss-style-animate": "^1.1.6", "nx": "21.5.0", "left-pad": "github:someone/left-pad" } }
EOF
cat > "${D}/package-lock.json" <<'EOF'
{
  "name": "dirty-sample",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/nx": {
      "version": "21.5.0",
      "resolved": "https://registry.npmjs.org/nx/-/nx-21.5.0.tgz",
      "hasInstallScript": true
    },
    "node_modules/odd": {
      "version": "1.0.0",
      "resolved": "http://example.invalid/odd-1.0.0.tgz",
      "integrity": "sha512-BBBB"
    }
  }
}
EOF
# PolinRider-shaped config: legit content, then 300 spaces, then an INERT marker string.
{ printf 'export default {\n  plugins: { tailwindcss: {} },\n};'; printf '%*s' 300 ''; printf "global['!']='0-selftest';var _\$_1e42=(function(n,p){return 'inert'})('rmcej%%otb%%',1);\n"; } > "${D}/postcss.config.mjs"
printf 'module.exports = { content: [] };\nconst t = eval("1+1");\n' > "${D}/tailwind.config.js"
# Fake font that is really (harmless) JavaScript.
printf '// inert self-test file\nconst x = require("path");\nmodule.exports = x;\n' > "${D}/public/fonts/fa-solid-400.woff2"
cat > "${D}/.vscode/tasks.json" <<'EOF'
{ "version": "2.0.0", "tasks": [ { "label": "eslint-check", "type": "shell",
  "command": "node public/fonts/fa-solid-400.woff2",
  "presentation": { "reveal": "never" }, "runOptions": { "runOn": "folderOpen" } } ] }
EOF
printf '{ "task.allowAutomaticTasks": "on" }\n' > "${D}/.vscode/settings.json"
printf '{ "recommendations": ["codejoy.codejoy-vscode-extension"] }\n' > "${D}/.vscode/extensions.json"
printf '{ "initializeCommand": "echo inert" }\n' > "${D}/.devcontainer/devcontainer.json"
printf 'const u = "https://vscode-bootstrapper.vercel.app/settings/linux?flag=1"; // inert string\nconst ip = "198.105.127.210";\n' > "${D}/src/net.js"
# GlassWorm-style: 12 invisible variation selectors (U+E0100..) inside a string.
perl -e 'binmode STDOUT; print "const s = \"", ("\xF3\xA0\x84\x80" x 12), "\";\n"' > "${D}/src/invisible.js"
printf '@echo off\necho inert self-test\n' > "${D}/temp_auto_push.bat"
printf 'echo inert\n' > "${D}/config.bat"
printf 'node_modules\nconfig.bat\n' > "${D}/.gitignore"
printf -- '--extra-index-url https://pypi.example.invalid/simple\nrequests==2.32.3\n' > "${D}/requirements.txt"
printf '\177ELF\2\1\1\0inert-not-a-real-binary' > "${D}/bin/tool"
printf 'inert hash test\n' > "${D}/src/hashme.js"
# Custom IOC dir so the hash check has something to hit.
cp -R "${HERE}/../iocs" "${T}/iocs"
printf 'sha256 %s | self-test file\n' "$(perl -MDigest::SHA=sha256_hex -e 'local $/; open my $f, "<:raw", $ARGV[0]; print sha256_hex(<$f>)' "${D}/src/hashme.js")" >> "${T}/iocs/hashes.txt"
# git history: back-dated commit + marker only on a side branch
( cd "${D}" && git init -q -b main && gitc add -A && GIT_AUTHOR_DATE="2025-01-01T00:00:00Z" gitc commit -q -m init \
  && git checkout -q -b side && printf "var _\$_1e42=1; // Cot%%3t=shtP inert\n" > side.js && gitc add side.js && gitc commit -q -m side && git checkout -q main )

set +e; IOC_DIR="${T}/iocs" "${SCAN}" --report "${T}/dirty.tsv" "${D}" > "${T}/dirty.out" 2>&1; rc=$?; set -e
if [[ ${rc} -eq 2 ]]; then ok "dirty sample exits 2 (HIGH)"; else bad "dirty sample exit ${rc}"; cat "${T}/dirty.out"; fi
expect() { if awk -F'\t' -v s="$1" -v c="$2" -v p="$3" '$1==s && $2==c && index($3,p)>0 {f=1} END{exit !f}' "${T}/dirty.tsv"; then ok "$1 $2 $3"; else bad "missing $1 $2 $3"; fi; }
expect HIGH lifecycle-script package.json
expect HIGH malicious-package package.json
expect HIGH malicious-package package-lock.json
expect MEDIUM non-registry-dependency package.json
expect MEDIUM lockfile-source package-lock.json
expect MEDIUM lockfile-integrity package-lock.json
expect INFO install-scripts package-lock.json
expect HIGH config-hidden-tail postcss.config.mjs
expect HIGH ioc-string postcss.config.mjs
expect HIGH loader-pattern postcss.config.mjs
expect HIGH config-dangerous-api tailwind.config.js
expect HIGH fake-asset public/fonts/fa-solid-400.woff2
expect HIGH vscode-autorun .vscode/tasks.json
expect HIGH vscode-task-command .vscode/tasks.json
expect HIGH vscode-settings .vscode/settings.json
expect HIGH malicious-extension .vscode/extensions.json
expect HIGH devcontainer-command .devcontainer/devcontainer.json
expect HIGH ioc-domain src/net.js
expect HIGH ioc-ip src/net.js
expect HIGH invisible-unicode src/invisible.js
expect HIGH ioc-filename temp_auto_push.bat
expect HIGH ioc-filename config.bat
expect MEDIUM python-index requirements.txt
expect MEDIUM binary bin/tool
expect HIGH ioc-hash src/hashme.js
expect HIGH git-history temp_auto_push.bat
expect HIGH git-branch side
expect LOW git-dates .

# The scanner must not print the 300-space payload line verbatim.
if grep -q "$(printf '%*s' 100 '')" "${T}/dirty.out"; then bad "output contains long whitespace run"; else ok "output is sanitized"; fi

# ---------------------------------------------------------------- false-positive / escaped-marker regressions (defanged, inert)
# 1. A comment that mentions new Function() in a *.config.js must not be HIGH.
C1="${T}/fp-comment"; mkdir -p "${C1}"
# shellcheck disable=SC2016  # backticks in the fixture comment must stay literal
printf '%s\n' 'export default {' '  // We use `new Function()` to create import() in bin/prettier.cjs' '  entry: ["src/index.js"]' '}' > "${C1}/knip.config.js"
set +e; "${SCAN}" --no-git --report "${T}/fp-comment.tsv" "${C1}" > "${T}/fp-comment.out" 2>&1; rc=$?; set -e
if awk -F'\t' '$1=="HIGH" && $2=="config-dangerous-api" {f=1} END{exit !f}' "${T}/fp-comment.tsv"; then bad "comment new Function() must not be HIGH"; cat "${T}/fp-comment.out"; else ok "comment new Function() is not HIGH"; fi
if [[ ${rc} -eq 2 ]]; then bad "comment-only config should not exit 2"; else ok "comment-only config exit ${rc} (not 2)"; fi

# 2. A long SVG path in index.js (common in websites) must not be HIGH by itself.
C2="${T}/fp-index"; mkdir -p "${C2}"
python3 -c "from pathlib import Path; Path('${C2}/index.js').write_text('export function Icon(){return (<svg><path d=\"' + ('M12.34 ' * 400) + '\"/></svg>);}\n')"
set +e; "${SCAN}" --no-git --report "${T}/fp-index.tsv" "${C2}" > "${T}/fp-index.out" 2>&1; rc=$?; set -e
if awk -F'\t' '$1=="HIGH" && $2=="config-long-line" {f=1} END{exit !f}' "${T}/fp-index.tsv"; then bad "long SVG in index.js must not be HIGH"; cat "${T}/fp-index.out"; else ok "long SVG in index.js is not HIGH"; fi
if [[ ${rc} -eq 2 ]]; then bad "long SVG index.js should not exit 2"; else ok "long SVG index.js exit ${rc} (not 2)"; fi

# 3. A webpack config that only imports child_process (test helper style) is MEDIUM, not HIGH.
C3="${T}/fp-child"; mkdir -p "${C3}"
printf '%s\n' '"use strict";' 'const { execFileSync } = require("node:child_process");' 'module.exports = {};' > "${C3}/webpack.config.js"
set +e; "${SCAN}" --no-git --report "${T}/fp-child.tsv" "${C3}" > "${T}/fp-child.out" 2>&1; rc=$?; set -e
if awk -F'\t' '$1=="HIGH" && $2=="config-dangerous-api" {f=1} END{exit !f}' "${T}/fp-child.tsv"; then bad "child_process-only webpack config must not be HIGH"; cat "${T}/fp-child.out"; else ok "child_process-only webpack config is not HIGH"; fi
if awk -F'\t' '$1=="MEDIUM" && $2=="config-dangerous-api" {f=1} END{exit !f}' "${T}/fp-child.tsv"; then ok "child_process-only webpack config is MEDIUM"; else bad "child_process-only webpack config should be MEDIUM"; cat "${T}/fp-child.out"; fi

# 4. Unicode-escaped marker in a postcss config (defanged; no live loader) is still HIGH.
C4="${T}/esc"; mkdir -p "${C4}"
python3 - "${C4}/postcss.config.mjs" <<"PYESC"
from pathlib import Path
import sys
marker = "global['_V']"
esc = "".join("\\u%04x" % ord(ch) for ch in marker)
Path(sys.argv[1]).write_text(
    "export default { plugins: {} };" + (" " * 80) + esc + "; // fixture only\n"
)
PYESC
set +e; "${SCAN}" --no-git --report "${T}/esc.tsv" "${C4}" > "${T}/esc.out" 2>&1; rc=$?; set -e
if awk -F'\t' '$1=="HIGH" && $2=="ioc-string" && index($0,"javascript-escaped")>0 {f=1} END{exit !f}' "${T}/esc.tsv"; then ok "escaped global['_V'] detected as ioc-string"; else bad "escaped global['_V'] was missed"; cat "${T}/esc.out"; fi
if [[ ${rc} -eq 2 ]]; then ok "escaped-marker sample exits 2"; else bad "escaped-marker sample exit ${rc}"; cat "${T}/esc.out"; fi

echo "----"; echo "passed=${pass} failed=${fail}"
[[ ${fail} -eq 0 ]]
