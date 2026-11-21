# Changelog

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
