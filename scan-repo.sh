#!/usr/bin/env bash
# scan-repo.sh - static "is this repo safe to install/open?" check.
#
# Run it BEFORE npm/pnpm/yarn/bun install, pip install, or opening a folder
# in VS Code / Cursor. It only reads files. It never runs package scripts,
# never imports project code, and never contacts the network unless you pass
# --with-tools (osv-scanner / gitleaks, which read lockfiles and git history).
#
# Usage: scan-repo.sh [--deep] [--with-tools] [--no-git] [--report FILE] [--skip RELFILE]... [PATH]
#   --deep        also scan node_modules/, .venv/ (use after an install)
#   --with-tools  also run osv-scanner (known-malicious + vulnerable deps) and
#                 gitleaks (committed secrets) if they are installed
#   --no-git      skip git history / all-branches checks
#   --report FILE write the raw TAB-separated findings to FILE
#   --skip RELFILE  skip one file (path relative to PATH). Command-line only on
#                 purpose: a repo cannot ship its own ignore list.
#
# Exit codes: 0 = nothing worrying, 1 = review MEDIUM findings, 2 = HIGH: stop,
#             3 = scanner error. Requires bash and perl (macOS, Linux, Git for Windows).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
IOC_DIR="${IOC_DIR:-${SCRIPT_DIR}/iocs}"
CORE="${SCRIPT_DIR}/lib/scan-core.pl"
DEEP=0 WITH_TOOLS=0 NO_GIT=0 REPORT="" TARGET="."
SKIP=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep) DEEP=1 ;;
    --with-tools) WITH_TOOLS=1 ;;
    --no-git) NO_GIT=1 ;;
    --report) REPORT="${2:-}"; shift ;;
    --skip) SKIP+=(--skip "${2:-}"); shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    -*) echo "Unknown option: $1" >&2; exit 3 ;;
    *) TARGET="$1" ;;
  esac
  shift
done

command -v perl >/dev/null 2>&1 || { echo "perl is required (it ships with macOS, Linux and Git for Windows)." >&2; exit 3; }
[[ -d "${TARGET}" ]] || { echo "Not a directory: ${TARGET}" >&2; exit 3; }
ROOT="$(cd "${TARGET}" && pwd -P)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/scan-repo.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT
OUT="${TMP}/findings.tsv"

add() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "${OUT}"; }

deep_flag="--no-deep"; [[ ${DEEP} -eq 1 ]] && deep_flag="--deep"
self_flag=() self_spec=()
case "${SCRIPT_DIR}/" in
  "${ROOT}/"*)
    # The scanner's own IOC lists contain the markers; skip only this folder.
    self_flag=(--self "${SCRIPT_DIR}")
    self_spec=(":(exclude)${SCRIPT_DIR#"${ROOT}/"}/**") ;;
esac

if ! perl "${CORE}" --root "${ROOT}" --ioc-dir "${IOC_DIR}" ${self_flag[@]+"${self_flag[@]}"} ${SKIP[@]+"${SKIP[@]}"} "${deep_flag}" > "${OUT}" 2> "${TMP}/core.err"; then
  echo "Scanner error:" >&2; cat "${TMP}/core.err" >&2; exit 3
fi
NFILES="$(awk -F'\t' '$1=="#files"{print $2}' "${OUT}")"
grep -v '^#files' "${OUT}" > "${OUT}.tmp" || true; mv "${OUT}.tmp" "${OUT}"

# ---------------------------------------------------------------- git checks
if [[ ${NO_GIT} -eq 0 ]] && command -v git >/dev/null 2>&1 && git -C "${ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
  # Never let repo config run anything: no fsmonitor, no hooks, no pager.
  G=(git -C "${ROOT}" -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.pager=cat --no-pager)
  # 1. PolinRider propagation script anywhere in history.
  if "${G[@]}" log --all --format= --name-only 2>/dev/null | grep -qE '(^|/)temp_auto_push\.bat$'; then
    add HIGH git-history temp_auto_push.bat "temp_auto_push.bat exists in git history: past PolinRider infection, rotate secrets"
  fi
  # 2. Markers on OTHER branches (OSM: many victims are infected only off the default branch).
  pat="${TMP}/strings.txt"; grep -vE '^[[:space:]]*(#|$)' "${IOC_DIR}/strings-high.txt" > "${pat}"
  refs="$("${G[@]}" for-each-ref --format='%(refname)' refs/heads refs/remotes 2>/dev/null | grep -v '/HEAD$' | head -n 200)"
  if [[ -n "${refs}" ]]; then
    # shellcheck disable=SC2086
    "${G[@]}" grep -I -i -l -F -f "${pat}" ${refs} -- . ${self_spec[@]+"${self_spec[@]}"} 2>/dev/null | head -n 20 |
      while IFS= read -r hit; do add HIGH git-branch "${hit}" "malware marker present on a branch (not necessarily checked out)"; done
  fi
  # 3. Back-dated commits (PolinRider amends + force-pushes with the original author date).
  "${G[@]}" log --all -n 300 --format='%h %at %ct %an' 2>/dev/null |
    awk '{ d=$3-$2; if (d > 30*86400) { n++; if (n<=3) ex=ex" "$1"("int(d/86400)"d)" } } END { if (n>0) printf "LOW\tgit-dates\t.\t%d commits have a committer date 30+ days after the author date (rebases do this too; PolinRider back-dates):%s\n", n, ex }' >> "${OUT}"
  # 4. Submodules from odd places.
  if [[ -f "${ROOT}/.gitmodules" ]] && grep -qE 'url[[:space:]]*=[[:space:]]*(-|[^h[:space:]]|http:)' "${ROOT}/.gitmodules"; then
    add MEDIUM gitmodules .gitmodules "submodule URL is not https:// - review before 'git submodule update'"
  fi
fi

# ---------------------------------------------------------------- optional free tools
if [[ ${WITH_TOOLS} -eq 1 ]]; then
  if command -v osv-scanner >/dev/null 2>&1; then
    osv-scanner scan source -r --format json "${ROOT}" > "${TMP}/osv.json" 2>/dev/null
    if [[ -s "${TMP}/osv.json" ]]; then
      perl -MJSON::PP -e '
        local $/; my $j = eval { decode_json(<STDIN>) } or exit 0; my ($mal, $vuln) = (0, 0);
        for my $r (@{ $j->{results} || [] }) { for my $p (@{ $r->{packages} || [] }) {
          for my $v (@{ $p->{vulnerabilities} || [] }) {
            if (($v->{id} // "") =~ /^MAL-/) { $mal++; printf "HIGH\tosv-malicious\t%s\t%s %s\@%s\n", $r->{source}{path}, $v->{id}, $p->{package}{name}, $p->{package}{version} }
            else { $vuln++ } } } }
        printf "INFO\tosv-vulns\t.\t%d known vulnerabilities in locked dependencies (run osv-scanner for details)\n", $vuln if $vuln;
      ' < "${TMP}/osv.json" >> "${OUT}"
    fi
  else
    add INFO tools . "osv-scanner not installed (free: https://github.com/google/osv-scanner)"
  fi
  if command -v gitleaks >/dev/null 2>&1; then
    if ! gitleaks detect --source "${ROOT}" --no-banner --redact --report-format json --report-path "${TMP}/gl.json" >/dev/null 2>&1; then
      n="$(perl -MJSON::PP -e 'local $/; my $j = eval { decode_json(<STDIN>) } || []; print scalar @$j' < "${TMP}/gl.json" 2>/dev/null || echo 0)"
      [[ "${n}" != "0" ]] && add MEDIUM gitleaks . "${n} possible committed secrets (values redacted; run gitleaks detect --redact -v)"
    fi
  else
    add INFO tools . "gitleaks not installed (free: https://github.com/gitleaks/gitleaks)"
  fi
fi

[[ -n "${REPORT}" ]] && cp "${OUT}" "${REPORT}"

# ---------------------------------------------------------------- summary
high="$(grep -c '^HIGH' "${OUT}" || true)"; med="$(grep -c '^MEDIUM' "${OUT}" || true)"
low="$(grep -c '^LOW' "${OUT}" || true)"; info="$(grep -c '^INFO' "${OUT}" || true)"
if [[ -t 1 ]]; then R=$'\e[31m' Y=$'\e[33m' GRN=$'\e[32m' N=$'\e[0m'; else R="" Y="" GRN="" N=""; fi
echo "Repo scan: ${ROOT}"
echo "Files checked: ${NFILES:-0}   HIGH: ${high}   MEDIUM: ${med}   LOW: ${low}   INFO: ${info}"
for sev in HIGH MEDIUM LOW INFO; do
  awk -F'\t' -v s="${sev}" '$1==s' "${OUT}" | sort -u | while IFS=$'\t' read -r s c l d; do
    case "${s}" in HIGH) col="${R}" ;; MEDIUM) col="${Y}" ;; *) col="" ;; esac
    printf '%s%-6s%s %-24s %s\n       %s\n' "${col}" "${s}" "${N}" "${c}" "${l}" "${d}"
  done
done
if [[ "${high}" -gt 0 ]]; then
  cat <<EOF
${R}STOP.${N} Do not run npm/pnpm/yarn/pip install, do not open this folder in VS Code/Cursor
in trusted mode, and do not run any of its scripts. Send this output to your security team.
If anything from this repo already ran on this machine, disconnect it, then rotate
GitHub/npm/cloud tokens and SSH keys from a different, clean device.
EOF
  exit 2
elif [[ "${med}" -gt 0 ]]; then
  echo "${Y}Review the MEDIUM items before installing.${N} Install with scripts off: npm ci --ignore-scripts"
  exit 1
fi
echo "${GRN}No known-bad patterns found.${N} This is a first pass, not a guarantee: still install with --ignore-scripts."
exit 0
