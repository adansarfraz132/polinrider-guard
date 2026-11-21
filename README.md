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

# Already infected, or not sure? Stop the malware, then rotate (see below)
./live-respond.sh --kill --quarantine

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
powershell -ExecutionPolicy Bypass -File .\live-respond.ps1 -Kill -Quarantine
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

## If you're already infected

The order matters. If you rotate a GitHub token while the loader is still
running or can start again, the new token is stolen too. So first stop
the malware and its re-run points, confirm the machine says it is safe,
and only then rotate.

1. **Disconnect from the network if you can, then run live response**
   with `--kill --quarantine`:

   ```bash
   ./live-respond.sh --kill --quarantine          # macOS / Linux
   powershell -ExecutionPolicy Bypass -File .\live-respond.ps1 -Kill -Quarantine   # Windows
   ```

   It finds running PolinRider activity and the places it restarts from
   (see below), stops the processes, and **moves** (never deletes) the
   files to `~/.polinrider-quarantine/<time>/` with a `manifest.json` of
   original paths and SHA-256 hashes. `./live-respond.sh --restore DIR --yes`
   puts everything back. Without `--kill` and `--quarantine` it only
   reports and changes nothing.
2. **Confirm the verdict.** The run ends with either
   `SAFE TO ROTATE CREDENTIALS` (no active process and no re-run point
   left after the actions) or `NOT SAFE YET` with a list of what is left.
   Fix what is listed and run it again. Review items you have checked
   yourself can be cleared with `--accept PATH`. Optionally leave
   `./live-respond.sh --kill --watch` running while you rotate: it
   re-checks every 30 seconds and stops or alerts on anything that
   reappears.
3. **Then rotate credentials, from a clean device if possible.** Revoke
   first, then create new ones: GitHub tokens, OAuth apps, SSH and GPG
   keys; `~/.git-credentials`; npm tokens; cloud and CI keys and every
   `.env` secret; browser-saved passwords and sessions; email and chat
   sessions; and move any crypto funds to a wallet created on the clean
   device. The tool prints this checklist after the verdict.
4. **Clean your repositories and force-push the clean history.** Run
   `./history-report.sh` (it also prints at the end of a full live
   response run). It names the first commit that introduced the infected
   code in each repo, the commits and branches that carry it, and whether
   HEAD is still infected. Remove the injected code, check every branch,
   and force-push the clean history. Tell collaborators to re-clone.
   Check forks and other copies too (see below).
5. **Consider reinstalling the operating system.** SEAL recommends it
   for Contagious Interview infections, especially on Windows. If you
   cannot explain every item the tool reported, or you did not run the
   loader yourself and cannot say when it started, reinstall.

**Be clear about what this cannot do.** It cannot undo data that was
already stolen: browser passwords, cookies, wallet data, `.env` keys and
git credentials taken before you ran it are gone, which is why step 3
exists. A SAFE verdict is a snapshot against published indicators, not
proof. Indicators rotate, and a rootkit or a renamed process would not
match. Do not "clean it up and carry on."

### What live response looks for

Running now:

- `node -e` loaders (also `bun`) whose inline code carries the published
  markers (`global.i='A9-...'`, `global['!']`, the `_$_xxxx` shuffle
  table, known wallets and XOR keys), a blockchain RPC lookup combined
  with `eval` or a `/boot` fetch, a `/boot` fetch from a raw IP and port,
  or use of the private `~/.node_modules` prefix with axios and
  socket.io; `node` running a font, `spellright.dict` or a file in one of
  the artifact folders.
- Python stealer processes (the stage-3 lock file, artifact folders,
  wallet-extension IDs plus `.git-credentials`).
- `temp_auto_push.*` scripts and shell one-liners that amend the last
  commit and force-push with `--no-verify`, and `git` doing that when
  started by an interpreter.
- Interpreters with an open connection to a known C2 IP or port.

It reports PID, command line (truncated) and parent. Ordinary developer
processes (VS Code, npm, `next dev`, webpack, a `node -e` one-liner, a
web3 script that merely calls an RPC) are not flagged. With `--kill` it
sends TERM, then KILL, to the matched processes and their children only,
never to itself or its own parents.

Restarting points: `~/.node_modules` with axios and socket.io-client,
the other host artifacts in `iocs/host-artifacts.txt`,
`.vscode/tasks.json` tasks with `runOn: folderOpen` that download or run
inline code or silently run a script, `temp_auto_push.*` and
`config.bat`, systemd user units, XDG autostart entries, LaunchAgents,
cron entries, injected lines in shell startup files, global
`core.hooksPath` hooks, malicious git hooks and config inside
repositories, and PolinRider-injected build configs and fake fonts in your
project folders (it reuses the repo scanner). On Windows it also checks
the Startup folder, the `Run` and `RunOnce` registry keys, scheduled
tasks, and PowerShell profiles. A `HIGH` item is moved by
`--quarantine`. Shell startup files, cron and git config are edited
conservatively: only the matching lines are commented out, with the
original saved in the quarantine folder. A `REVIEW` item (for example a
`~/.node_modules` without axios, or a `folderOpen` task running your own
script) is never moved automatically and blocks the verdict until you
check it and pass `--accept PATH`.

### Git history report

```bash
./history-report.sh                       # repos under your home folder
./history-report.sh ~/src/one-repo --json report.json
```

For each repository it walks all branches and tags, finds the first
commit that added infected code (SHA, author, files, author and committer
dates), lists every commit that added it and the refs that contain it,
says whether HEAD, other branches and the working tree are infected now,
and ends with a summary across repositories with "infected since" dates.
Date flags are hints: PolinRider rewinds the clock when it amends a
commit, so a clean-looking date proves nothing. See
[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#history-report-and-fork-check).

To see whether copies of an infected repository on GitHub carry the same
code:

```bash
GITHUB_TOKEN=... ./history-report.sh --github owner/repo --max-forks 100
```

It lists up to `--max-forks` public forks, checks each fork's default
branch for the infected patterns, and runs a GitHub code search for the
loader fingerprints (the `global.i` marker values it found in the repos scanned in the same run, plus any `--fingerprint`; otherwise the published wallet addresses and marker strings). Code search needs a token. It stops
early, and says so, before the API rate limit runs out. Its limits are
real: private repositories, plain clones and downloaded ZIPs are
invisible, only some file types on the default branch are checked, and
code search counts files, not people, so never read it as a number of
victims.

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
checks 39 expectations. No real malware is used.

```bash
bash tests/run-live-tests.sh       # live response and history report (76 checks)
bash tests/run-live-ps1-tests.sh   # live-respond.ps1 under PowerShell 7 (13 checks)
```

The live tests start harmless fake processes (a copy of `perl` named
`node` that only sleeps, with a published marker in a comment), build
fake home folders and git repos in a temp folder, and use a local mock of
the GitHub API. Nothing real is contacted and no real malware is used.
The Windows-only parts (registry Run keys, scheduled tasks, Startup
shortcuts, the CIM process list) are written carefully but have not been
run on a real Windows machine.

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
