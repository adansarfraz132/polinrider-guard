#!/usr/bin/env bash
# host-check.sh - read-only check of THIS Mac/Linux machine for artifacts left by the
# researched developer-targeted malware (see THREATS.md). Changes nothing.
# Exit 2 if anything HIGH is found.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
IOC="${HERE}/iocs"
found=0
hit() { printf '\033[31mHIGH\033[0m  %s\n      %s\n' "$1" "$2"; found=1; }
note() { printf 'INFO  %s\n' "$1"; }

# 1. Files and folders in home directories (BeaverTail/InvisibleFerret, s1ngularity, PolinRider stage 3)
homes=("${HOME}")
if [[ ${EUID} -eq 0 ]]; then for h in /Users/* /home/*; do [[ -d "${h}" ]] && homes+=("${h}"); done; fi
while IFS='|' read -r path note_; do
  path="${path%"${path##*[![:space:]]}"}"; [[ -z "${path}" || "${path}" == \#* || "${path}" == AppData* ]] && continue
  if [[ "${path}" == /* ]]; then
    [[ -e "${path}" ]] && hit "${path}" "${note_}"
  else
    for h in "${homes[@]}"; do
      for p in "${h}"/${path}; do [[ -e "${p}" ]] && hit "${p}" "${note_}"; done
    done
  fi
done < "${IOC}/host-artifacts.txt"

# 2. s1ngularity sabotage line in shell startup files
for h in "${homes[@]}"; do
  for rc in .bashrc .zshrc .bash_profile .profile .zprofile; do
    [[ -f "${h}/${rc}" ]] && grep -q 'sudo shutdown -h 0' "${h}/${rc}" && hit "${h}/${rc}" "contains 'sudo shutdown -h 0' (s1ngularity / Nx)"
  done
done

# 3. Installed VS Code-family extensions vs. known-malicious list
for h in "${homes[@]}"; do
  for d in .vscode/extensions .vscode-insiders/extensions .cursor/extensions .vscode-oss/extensions .windsurf/extensions; do
    [[ -d "${h}/${d}" ]] || continue
    for e in "${h}/${d}"/*/; do
      e="$(basename "${e}")"; id="$(echo "${e}" | sed -E 's/-[0-9][0-9A-Za-z.+-]*$//' | tr '[:upper:]' '[:lower:]')"; ver="${e#"${id}"}"; ver="${ver#-}"
      while IFS= read -r bad; do
        [[ -z "${bad}" || "${bad}" == \#* ]] && continue
        b="$(echo "${bad}" | tr '[:upper:]' '[:lower:]')"
        if [[ "${b}" == *@* ]]; then [[ "${id}@${ver}" == "${b}" ]] && hit "${h}/${d}/${e}" "known-malicious extension version (GlassWorm)"
        else [[ "${id}" == "${b}" ]] && hit "${h}/${d}/${e}" "known-malicious extension (GlassWorm)"; fi
      done < "${IOC}/vscode-extensions.txt"
    done
  done
done

# 4. Global npm packages vs. known-malicious list (npm ls only reads metadata)
if command -v npm >/dev/null 2>&1; then
  out="$(npm ls -g --depth=0 --parseable --long 2>/dev/null | awk -F: 'NF>1{print $2}' | while IFS= read -r pv; do
    name="${pv%@*}"; [[ "${pv}" == @* && "${name}" == "" ]] && name="${pv}"
    while IFS= read -r bad; do
      [[ -z "${bad}" || "${bad}" == \#* ]] && continue
      if [[ "${bad}" == *@[0-9]* ]]; then [[ "${pv}" == "${bad}" ]] && echo "HIGH  global npm package ${pv} (hijacked version)"
      else [[ "${name}" == "${bad}" ]] && echo "HIGH  global npm package ${pv} (malicious)"; fi
    done < "${IOC}/npm-packages.txt"
  done)"
  [[ -n "${out}" ]] && { echo "${out}"; found=1; }
  [[ "$(npm config get ignore-scripts 2>/dev/null)" == "true" ]] || note "npm ignore-scripts is OFF for this user (see safe-defaults/README)."
fi

# shellcheck disable=SC2009
# 5. Running processes that match the loaders' command lines
out="$(ps -axo pid=,command= 2>/dev/null | grep -E '(node|bun|python3?)[^ ]* .*(\.woff2?|spellright\.dict|/\.n2/|/\.npl|/\.nlp|/\.pyp/|bun_environment\.js|/\.npm/scoped_dir)' | grep -v grep |
  while IFS= read -r line; do echo "HIGH  suspicious process: ${line:0:200}"; done)"
[[ -n "${out}" ]] && { echo "${out}"; found=1; }

# 6. Connections to known C2 IPs/ports (snapshot; rotates)
if command -v lsof >/dev/null 2>&1; then
  ips="$(grep -vE '^[[:space:]]*(#|$)' "${IOC}/ips-high.txt" | paste -sd'|' -)"
  out="$(lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | grep -E "(${ips})|:(1224|2242|5918|5978)( |$)" |
    while IFS= read -r line; do echo "HIGH  connection: ${line:0:200}"; done)"
  [[ -n "${out}" ]] && { echo "${out}"; found=1; }
fi

if [[ ${found} -eq 1 ]]; then
  cat <<'EOF'

Something matched. Do not keep working on this machine:
 1. Disconnect it from the network (Wi-Fi off / unplug).
 2. Run ./live-respond.sh --kill --quarantine and wait for the verdict SAFE TO ROTATE CREDENTIALS.
    Rotating a token before that lets a still-running loader steal the new one.
 3. From a DIFFERENT clean device: rotate GitHub, npm, cloud, and SSH credentials; move crypto funds.
 4. Tell your security team. A full OS reinstall is the safe fix (SEAL recommends it for Contagious Interview).
EOF
  exit 2
fi
echo "No known artifacts found on this machine (snapshot IOCs; not a guarantee)."
