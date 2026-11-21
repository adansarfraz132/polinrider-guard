# Safe defaults for every team laptop

All free. Apply with `../apply-dev-defaults.sh` (macOS/Linux; dry run unless `--apply`)
or `../apply-dev-defaults.ps1` on Windows (dry run unless `-Apply`).

| Where | Setting | Why |
|---|---|---|
| npm (user `~/.npmrc`) | `ignore-scripts=true` | Shai-Hulud, s1ngularity/Nx and PolinRider's npm vehicles all ran from install-time scripts. |
| npm | `min-release-age=1` | Skip versions younger than 1 day (npm v11 docs). Hijacked versions (qix/chalk, Nx) were removed within hours. |
| pnpm (repo) | `minimumReleaseAge`, `strictDepBuilds`, `allowBuilds`, `blockExoticSubdeps`, `trustPolicy: no-downgrade` | pnpm.io/supply-chain-security. |
| Yarn Berry | `enableScripts: false` | Same idea as ignore-scripts. |
| pip | install unknown projects in a venv with `pip install --only-binary=:all:` | Source builds run `setup.py`. |
| VS Code / Cursor (user settings) | `task.allowAutomaticTasks: off` + Workspace Trust on | Blocks `.vscode/tasks.json` `runOn: folderOpen`, the PolinRider and Contagious Interview autorun (SEAL Intel). |
| VS Code / Cursor (user settings) | `extensions.autoUpdate: false`, `extensions.autoCheckUpdates: false` | Stops GlassWorm-style worms that spread through silent extension auto-updates. Review and update extensions by hand. |
| VS Code / Cursor | Open unknown repos in **Restricted Mode**; never click "Trust" for job tests / outside repos | SEAL: every victim had trusted the workspace (sometimes so an AI tool could read it). |
| Extensions | Install only from known publishers; review new ones regularly (the optional Fleet queries in extras/ can list them) | GlassWorm spread through extension auto-updates. Auto-update is turned off above. |
| git | Global `core.hooksPath` -> this kit's hooks; `fetch/transfer.fsckObjects=true` | Scan on clone/checkout/pull; block commits containing markers. |
| AI coding agents | Do not let Claude Code / Gemini CLI / Copilot agent run with `--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools` in an unknown repo | s1ngularity drove those CLIs with exactly these flags. |
| Hiring / job tests | **Team rule:** open "take-home" and outside repos only inside a throwaway VM or GitHub Codespace, never on a work laptop; never click "Trust" on the laptop | Contagious Interview delivery path (Unit 42, SEAL). How-to is in `../README.md`. |

Free tools worth installing (all open source):
- osv-scanner (google/osv-scanner): checks lockfiles against OSV, which includes OpenSSF malicious-package (`MAL-`) records. `osv-scanner scan source -r .`
- gitleaks: committed secrets. `gitleaks detect --redact`
- GuardDog (DataDog/guarddog): heuristics for malicious npm/PyPI packages. `pip install guarddog; guarddog npm scan <pkg>`
- Semgrep CE: `semgrep scan --config auto` (rules download from the registry).
- Socket CLI (`npm i -g socket`) has a free tier for public packages; needs an account for some features.
