# PolinRider Guard

A free, offline-first kit that checks a project *before* you install it,
open it in VS Code or Cursor, or run its scripts. It is aimed at
"poisoned repo" malware used against developers: PolinRider, Contagious
Interview (BeaverTail / InvisibleFerret), Shai-Hulud, s1ngularity (Nx),
the chalk/debug npm hijack, GlassWorm, and lookalikes.

The tools only read files. They never execute the code being checked.
No accounts are required.

This is a first pass, not a guarantee. Keep installing with scripts off.

## What PolinRider is

Attackers, often North Korean groups, hide a small obfuscated script in
files developers rarely read closely: the end of a very long line in
`postcss.config.mjs` (the most common file in OpenSourceMalware's
dataset, about 62%), other build configs (`tailwind.config.*`,
`next.config.*`, `vite.config.*`, `eslint.config.*`), a fake font such
as `fa-solid-400.woff2`, a `spellright.dict` file, or a VS Code
`tasks.json` that runs when you open the folder.

The usual delivery path is a trojanised "take-home" or job-test repo, an
npm lookalike, or a malicious pull request. The moment you run
`npm install`, click "Trust" on the folder, or start the dev server, the
loader can steal browser passwords, crypto wallets, `.env` files, SSH
keys, and GitHub or npm tokens, then use those tokens to infect *your*
repos and packages.

Command-and-control has been looked up from blockchain "dead drops"
(TRON, Aptos, later Ethereum). Persistence in git has included
`temp_auto_push.bat` (amend and force-push of back-dated commits) and
`config.bat` added to `.gitignore`.

A longer, sourced walk-through of the infection chain, including how
`temp_auto_push.bat` rewrites a victim's own git history, is in
[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md). Host artifacts and IOC
citations are in [THREATS.md](THREATS.md). Real-sample validation is in
[docs/VALIDATION.md](docs/VALIDATION.md). Every indicator
in `iocs/` comes from those public sources. Nothing was invented.
Indicators rotate, so the behaviour checks matter more than any single
IP or domain.

## Quick start

You need bash and perl (both ship with macOS, Linux, and Git for Windows).

### macOS and Linux

```bash
git clone https://github.com/adansarfraz132/polinrider-guard polinrider-guard
cd polinrider-guard

# Is this machine already infected? (read-only)
./host-check.sh

# Scan a repo *before* you open or install it
./scan-repo.sh /path/to/the/repo

# Optional one-time hardening of your own laptop (dry run first)
./apply-dev-defaults.sh
./apply-dev-defaults.sh --apply
```

`apply-dev-defaults.sh --apply` turns on npm/yarn defaults that skip
install-time scripts and brand-new package versions, sets VS Code and
Cursor to require workspace trust and to disable automatic tasks and
extension auto-updates, and installs git hooks that scan after clone,
checkout, and pull.

### Windows (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File .\host-check.ps1
powershell -ExecutionPolicy Bypass -File .\scan-repo.ps1 C:\path\to\the\repo
powershell -ExecutionPolicy Bypass -File .\apply-dev-defaults.ps1
powershell -ExecutionPolicy Bypass -File .\apply-dev-defaults.ps1 -Apply
```

What the defaults change, and why, is in [safe-defaults/README.md](safe-defaults/README.md).

## Scan a repo before you open it

Treat any repo you did not write, especially a job test, a take-home
assignment, or a PR from someone you do not know, as untrusted until it
has been scanned.

```bash
./safe-clone.sh https://github.com/example/take-home.git
# or, if it is already on disk:
./scan-repo.sh /path/to/the/repo
```

`safe-clone.sh` clones, then scans, then moves the folder aside if it
finds HIGH issues. Do not open that folder in an editor and do not run
`npm install` there.

Exit codes from `scan-repo.sh` / `scan-repo.ps1`:

| Code | Meaning |
|------|---------|
| 0 | Nothing worrying |
| 1 | Review MEDIUM findings |
| 2 | HIGH: stop. Do not install or open as trusted |
| 3 | Scanner error |

`--with-tools` also runs osv-scanner and gitleaks if you have them
installed. `--skip RELFILE` ignores one file; it is command-line only,
so a repo cannot ship its own ignore list.

### Team rule for job tests and outside repos

Open take-home and other untrusted repos only in a GitHub Codespace or a
throwaway VM. Do not clone them onto a work or personal laptop you rely
on, do not click "Trust" on that folder in VS Code or Cursor on that
laptop, and do not run `npm install` or the dev server there.

1. **GitHub Codespace (preferred).** In the GitHub repo, click Code,
   Codespaces, Create codespace. Do the work only in that window. Delete
   the codespace when you are finished. Do not download the folder.
2. **Throwaway VM.** Clone and run the project only inside the VM. Do
   not share the folder with the host, and do not open it in an editor
   on the host. Snapshot first if you want; delete or revert the VM
   when done.

If a repo is already on the laptop, do not open or install it. Move the
work into a Codespace or VM, then delete the local copy.

## Check whether a machine is already infected

```bash
./host-check.sh          # macOS / Linux
# Windows:
powershell -ExecutionPolicy Bypass -File .\host-check.ps1
```

The check is read-only. It looks for published host artifacts (for
example `~/.npl`, `~/.nlp`, `~/.n2`, `~/.pyp`, `store.node`), known
malicious VS Code or Cursor extensions, suspicious processes, and
connections to snapshot C2 IPs or ports (1224, 2242, 5918, 5978). A
clean result is not a guarantee; indicators rotate.

You can also scan folders you already have:

```bash
./scan-repo.sh ~/src/some-project
```

Pay extra attention to `postcss.config.mjs` and other build configs
(look at the far end of long lines, not just the start),
`.vscode/tasks.json` (`runOn: folderOpen`), fake `woff2` or
`spellright.dict` files, and `temp_auto_push.bat` in the tree or in git
history.

## If you are already infected

1. Disconnect the machine from the network (Wi-Fi off, or unplug).
   Do not keep working on it.
2. From a *different, clean* device, rotate GitHub, npm, cloud, and SSH
   credentials, browser-saved passwords, and any other tokens that may
   have been on the laptop. Move crypto funds to a new wallet you create
   on the clean device.
3. Report it: tell your security team or a trusted colleague, and notify
   GitHub, npm, or other platforms if you believe their tokens were
   stolen. If work data may be involved, tell your employer through
   their incident process.
4. A full OS reinstall is the safe fix. SEAL recommends it for
   Contagious Interview infections, especially on Windows.

Do not "clean it up and carry on." These loaders steal credentials and
then use them.

## Daily use

| Situation | Command |
|-----------|---------|
| Clone an untrusted repo | `./safe-clone.sh URL [DIR]` |
| Pull changes | `./safe-pull.sh [remote] [branch]` (scans incoming code, then fast-forwards) |
| Install dependencies | `./safe-install.sh [DIR]` (scan, install with scripts off, rescan `node_modules`) |
| Just check a folder | `./scan-repo.sh [--with-tools] DIR` (Windows: `scan-repo.ps1 DIR`) |
| Check this machine | `./host-check.sh` / `host-check.ps1` |
| Refresh threat data (weekly) | `./update-iocs.sh` |
| Apply laptop defaults | `./apply-dev-defaults.sh --apply` |

After `./install-hooks.sh` (also run by `apply-dev-defaults.sh --apply`),
hooks live in `~/.polinrider-guard` and scan on clone, checkout, and
pull. They also block commits that contain known malware markers. Repos
that set their own local `core.hooksPath` (Husky, Lefthook) override
this; use `safe-pull.sh` or scan by hand in those repos.

## What is checked

Known strings, domains, IPs, hashes, and malicious package names; code
hidden after long runs of spaces or very long lines in config files;
dangerous APIs in configs; install scripts in `package.json`;
non-registry dependencies and lockfile tricks; `.npmrc` / `.yarnrc` /
pnpmfile / bunfig overrides; Python `setup.py` / `.pth`; VS Code tasks,
settings, extensions, devcontainers, and MCP configs; fake fonts or
images that are really scripts; invisible Unicode; committed binaries
and native addons; risky GitHub workflows; git history
(`temp_auto_push.bat`, markers on other branches, back-dated commits,
odd submodule URLs).

IOC lists and how to refresh them: [iocs/README.md](iocs/README.md).

## Optional: Fleet osquery queries

If you already run Fleet, `extras/build-fleet-queries.py` generates
free-tier reports and policies from the same IOC lists. This is
optional. See [extras/README.md](extras/README.md).

## Tests

```bash
bash tests/run-tests.sh
```

Builds harmless clean and "dirty" sample repos in a temp folder and
checks 31 expectations. No real malware is used.

## Sources and credits

Campaign descriptions and every indicator are drawn from public
research, cited in [THREATS.md](THREATS.md). In particular:

- [OpenSourceMalware / PolinRider](https://github.com/OpenSourceMalware/PolinRider) and its scanner
- [SafeDep on PolinRider](https://safedep.io/blog/polinrider-ethereum-c2-github-repositories) and the [SafeDep IOC feed](https://safedep.io/ti/ioc.csv)
- [Chollima Hunter](https://chollimahunter.github.io/hunts/polinrider-config-injection-and-history-rewrite/)
- [Unit 42 on Contagious Interview](https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/)
- [SEAL Radar on VS Code task abuse](https://radar.securityalliance.org/vs-code-tasks-abuse-by-contagious-interview-dprk/)
- Reporting on Shai-Hulud, s1ngularity, the qix/chalk npm hijack, and GlassWorm, all linked from THREATS.md

## License

[MIT](LICENSE). Copyright (c) 2026 Adan Sarfraz.
