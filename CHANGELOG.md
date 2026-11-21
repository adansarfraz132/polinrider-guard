# Changelog

## 0.2.0 - 2026-11-21

- New **live response**: `live-respond.sh` (macOS, Linux) and `live-respond.ps1`
  (Windows; also runs under PowerShell 7 on Linux/macOS for CI).
  - Detects running PolinRider activity: detached `node -e` loaders (published
    markers, RPC dead-drop plus eval or `/boot`, `/boot` from a raw IP),
    Python stealer processes, `temp_auto_push.*` scripts and amend plus
    force-push loops, and interpreters connected to known C2 IPs or ports.
    Reports PID, truncated command line and parent. Report only by default.
  - `--kill` (opt-in) stops matched processes and their children.
  - Detects re-run points: `~/.node_modules` (axios + socket.io-client),
    host artifacts, `folderOpen` tasks that download or run inline code,
    `temp_auto_push.*` and `config.bat`, systemd user units, XDG autostart,
    LaunchAgents, cron, shell startup files, global `core.hooksPath` hooks,
    repo hooks and config, injected configs and fake fonts (reuses the repo
    scanner); on Windows also Startup, Run keys, scheduled tasks, PowerShell
    profiles.
  - `--quarantine` (opt-in) MOVES files to `~/.polinrider-quarantine/<time>/`
    with `manifest.json` (original path, sha256, mode); never deletes.
    `--restore DIR --yes` puts them back. Line-level edits for shell startup
    files, crontab and git config.
  - Verdict: `SAFE TO ROTATE CREDENTIALS` only when no process and no re-run
    point remain after the actions, otherwise `NOT SAFE YET` with what is
    left. Then the credential rotation checklist.
  - `--watch [--interval N]` keeps re-checking and alerts, kills or
    quarantines on reappearance (opt-in).
  - `--accept PATH` clears a REVIEW item you checked yourself.
- New **git history report**: `history-report.sh` (also printed at the end of a
  live response run). Finds the first commit that introduced infected code
  (author and committer dates, date-mismatch flags), all commits and refs
  that carry it, whether HEAD is infected, and a summary with "infected since"
  dates across repos. `--json FILE` for machine output.
- `history-report.sh --github owner/repo`: checks up to `--max-forks` public
  forks' default branches for the same code and runs GitHub code search for
  the loader fingerprint. Rate-limit aware; `GITHUB_TOKEN` optional and never
  printed. Counts files, never claims user counts.
- README section "If you're already infected" (live response first, confirm
  the verdict, then rotate from a clean device, clean repos and force-push,
  consider reinstalling), and HOW-IT-WORKS sections on re-run points and the
  history report. Honest about what cannot be undone.
- Tests: `tests/run-live-tests.sh` (76 checks) and
  `tests/run-live-ps1-tests.sh` (13 checks). The existing 39 checks are
  unchanged. Windows-only parts have not been run on real Windows.

## 0.1.1 - 2026-11-21

- Documented the public infection chain in `docs/HOW-IT-WORKS.md` and
  recorded a real-sample validation run in `docs/VALIDATION.md`.
- Validated `scan-repo.sh` against 36 available infected samples (34
  SafeDep evidence files, one local historical `postcss.config.mjs`,
  and the published `temp_auto_push.bat` fingerprint) with no misses,
  and against 20 popular clean repositories.
- Fixed three HIGH false positives: comments mentioning `new Function()`,
  long SVG paths in `index.js` / `App.js`, and isolated `child_process`
  imports in webpack test configs.
- Detect JavaScript-escaped (`\uXXXX` / `\xHH`) IOC strings.
- Added npm IOCs `tailwind-color-shades` and `safe-validate`, and the
  SafeDep Python-stealer lock file path.
- `scan-repo.ps1` runs its native subset on non-Windows hosts (no
  `Join-Path` on empty `ProgramFiles`).


## 0.1.0 - 2026-11-21

- Initial public release of the standalone kit: repo scanner, host check,
  safe clone/pull/install wrappers, git hooks, safe editor and package-manager
  defaults, and published IOC lists with sources.
- Optional Fleet osquery reports and policies live under `extras/`.
