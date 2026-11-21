# How PolinRider infects a developer machine

This is a plain-language description of the public research, not a
re-implementation of the malware. Every step is drawn from the sources
at the end. Indicators rotate; the shape of the attack matters more than
any single IP or domain.

PolinRider is attributed to North Korean (DPRK / Lazarus) operators and
overlaps the Contagious Interview / TasksJacker cluster
(OpenSourceMalware, 2026-03-07, updated 2026-04-11). It targets
developers, not servers. The goal, as SafeDep summarises it, is to steal
developer secrets, browser credentials, and wallet data, and then to
spread through repositories and packages the victim already owns.

## Entry vectors

Researchers have documented four ways the first-stage loader gets onto a
machine or into a project (OpenSourceMalware April 10-11 update):

1. **Weaponized job-test / take-home repos.** Fake recruiters send a
   project that already contains the loader. OpenSourceMalware identified
   at least two templates: ShoeVista (a fake Tailwind e-commerce test
   whose `client/package.json` depends on `tailwindcss-style-animate
   ^1.1.6`) and StakingGame (a fake blockchain / VS Code automation
   project fingerprinted by the UUID
   `e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9` in `.vscode/tasks.json`).
   Unit 42 has separately documented fake-recruiter lures in the related
   Contagious Interview campaign.

2. **Malicious npm packages.** Lookalikes of Tailwind / PostCSS utilities
   (`tailwindcss-style-animate`, `tailwind-mainanimation`,
   `tailwind-autoanimation`, and others listed by OpenSourceMalware;
   later `tailwind-color-shades` and `safe-validate`, reversed by Melted
   in Hex). Some run at *install* time via lifecycle scripts. Melted in
   Hex also documented loaders that run when the package is *imported*,
   with no `preinstall` / `postinstall` hook at all, so "install with
   scripts off" is not enough by itself.

3. **VS Code / Cursor `tasks.json` with `runOn: "folderOpen"`** (the
   TasksJacker-side vector). Opening the folder and clicking Trust can
   run a command, including `curl | bash` against Vercel-hosted bootstrap
   hosts such as `default-configuration.vercel.app` and
   `260120.vercel.app` (OpenSourceMalware; SEAL has documented victims
   who did nothing more than click Trust).

4. **Appended JavaScript in project config files**, after the legitimate
   `export default` or `module.exports`, often behind a long run of
   spaces so it is off the edge of the editor. The loader then runs when
   a build tool imports that config (`postcss.config.mjs` is the most
   common file in OpenSourceMalware's dataset, about 62 percent, also
   `tailwind.config.*`, `eslint.config.*`, `next.config.*`,
   `vite.config.*`, `webpack.config.*`, and others). Fake font or
   dictionary files (`fa-solid-400.woff2`, `spellright.dict`) can hold
   the same kind of payload.

A later step of the same campaign *re-uses* vector 4 against the
victim's *other* repositories. That is how a person who never meant to
publish malware ends up with a poisoned commit under their own name.
See [Spreading through the victim's repos](#spreading-through-the-victims-repos) below.

## What the appended payload does at runtime

The first-stage script is heavily obfuscated (OpenSourceMalware
describes four layers of shuffle / substitution / XOR; two published
variants use markers `rmcej%otb%` / `_$_1e42` / `global['!']` and
`Cot%3t=shtP` / `MDy` / `global['_V']`). It does not hard-code a
stable C2 domain. It *resolves* the next stage from public blockchains
(a technique sometimes called EtherHiding) and then `eval`s it.

Two resolver generations are documented:

### Generation A: TRON / Aptos pointer, payload on BNB Smart Chain

Documented by OpenSourceMalware and, in a later npm sample, reversed
end-to-end by Melted in Hex (2026-06-22):

1. Query the latest outgoing transaction of a hard-coded TRON account
   (example: `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` via
   `api.trongrid.io`). Decode and reverse the data field. That value is
   a BNB Smart Chain transaction hash. Aptos
   (`fullnode.mainnet.aptoslabs.com`, account `0xbe0374…0811e`) is a
   fallback that carries the same pointer.
2. Read that BSC transaction (`eth_getTransactionByHash` against public
   RPC such as `bsc-dataseed.binance.org`). The `input` field is
   hex-decoded, split on `?.?`, XOR-decrypted with a hard-coded key
   (OpenSourceMalware publishes `2[gWfGj;<:-93Z^C` for this stage), and
   `eval`'d.
3. The decrypted stage is another resolver / update channel, not the
   final stealer. It leads to a fetch of `/$/boot` (or similar) from an
   IP the chain revealed, with a version-gating header (`Sec-V` in the
   Melted in Hex sample). The response is decrypted and evaluated.
   Melted in Hex identifies that payload as a BeaverTail stager, which
   then selects InvisibleFerret.

### Generation B: C2 IP encoded in an Ethereum `to` address

Documented by SafeDep (2026-09-30). This is the generation seen in the
oxc pull-request commit `41ab07a8` and in 35 repositories SafeDep
confirmed still carried the loader at HEAD on that date.

1. A 30-second guard (`global._p_t`) stops a second run in the same
   process.
2. The loader calls public Ethereum RPC
   (`ethereum-rpc.publicnode.com`, `eth.drpc.org`,
   `eth-mainnet.public.blastapi.io`; samples have also used
   `1rpc.io/eth` and `eth.blockscout.com/api`) to read a recent block
   window and look for a small transaction from an operator wallet
   (`0x33ff3eda…9891` or `0xa322E5f3…Ef1a`).
3. The transaction's `to` address is decoded: eight hex characters
   become an IPv4 address, the next four a port. A second pair can be
   read from a later offset in the same address.
4. The loader GETs `http://IP:port/boot` and `/0/boot`, `eval`s the
   response, and also starts a detached `node -e` process (`stdio:
   'ignore'`, `windowsHide: true`) so the infection outlives the build.
   On WSL2 it starts `node.exe` as well, which moves the infection from
   the Linux guest onto the Windows host (SafeDep).

SafeDep notes that `/0/boot` on `45.137.198.133` XOR-decrypts a 54 KB
Node stage with the key `YU7m{rE/>|==b>#~`. That stage installs
`axios` and `socket.io-client` under a private npm prefix
`~/.node_modules`, posts the complete `process.env` to `/snv` (cloud
keys and registry tokens that happen to be in the shell), skips hosts
whose names look like CI or sandboxes, installs Python if needed, and
starts a detached Python stager.

The Python stealer (SafeDep: build id `260924`, fetched from `/$/1`)
collects Chromium and Firefox passwords and cookies, `~/.git-credentials`,
and data for 153 browser extension IDs, including MetaMask, Phantom,
Coinbase Wallet, 1Password, and Bitwarden. It uploads a ZIP to the C2
(` /u/f`); if that fails it can use the Telegram Bot API, with the
token supplied at run time. A lock file
`/tmp/tmp7A863DD1.tmp` (or `%LOCALAPPDATA%\Temp\tmp7A863DD1.tmp` on
Windows) is associated with this stage. OpenSourceMalware describes the
later payload family as a BeaverTail / InvisibleFerret lineage; host
artifacts such as `~/.npl`, `~/.nlp`, `~/.n2`, `~/.pyp`, and
`store.node` come from that related cluster (Unit 42, SEAL).

This kit never runs those stages. The description above is from
published sandboxed traces and static decoding, not from executing
samples here.

## Persistence

- A detached `node -e` (and on WSL2, `node.exe`) process that continues
  after the build or editor task ends (SafeDep; OpenSourceMalware).
- `~/.node_modules` as a private npm prefix for the Node stealer
  (SafeDep).
- Related Contagious Interview / InvisibleFerret host artifacts and,
  on Windows, startup items documented by SEAL (see
  `iocs/host-artifacts.txt`).
- Re-run points on the machine: see "Stopping it" below. `live-respond.sh`
  checks them and reports whether any remain.
- OpenSourceMalware says they have seen git-history rewriting on Linux
  and macOS as well, but the *published* `temp_auto_push.bat` helper is
  a Windows batch file; they have not published an equivalent
  left-behind script for other operating systems.

## Spreading through the victim's repos

This is the part that makes a victim look like an author of malware.

OpenSourceMalware recovered `temp_auto_push.bat` from compromised
repositories (101 copies in the April 2026 corpus) and published the
script. It does not use stolen GitHub credentials. It uses the git
credentials already on the machine, as the signed-in developer:

1. Read the date, time, message, author name, and author email of the
   latest commit, and the current branch.
2. Temporarily set the system clock back to that commit's timestamp.
3. `git add .`
4. `git commit --amend` with the original message, `--no-verify` (so
   hooks do not run), under the original author identity.
5. Restore the clock.
6. `git push -uf origin <branch> --no-verify`.

Because the clock was rewound, the amended commit keeps the original
timestamp. The poisoned config (or fake font, or tasks file) is now in
the latest commit of a repo the victim already owns, looking as if it
had always been there. A `config.bat` entry in `.gitignore` hides
related helper files.

That is why an incident process should treat a surprising
malware-shaped commit under a developer's name as a possible
compromise of their laptop, not as automatic proof that they wrote the
payload. OpenSourceMalware also notes that a previously cleaned repo can
be re-infected; at least one victim (`HassanHabibTahir/testclient`)
contained markers from both obfuscator variants in different files.

## What "getting blamed" is about, in technical terms

A code review or a later scan of the developer's GitHub account can show
*them* pushing obfuscated JavaScript into `postcss.config.mjs` (or
similar) with a normal-looking commit message and timestamp. The
mechanism above is how that evidence is manufactured after the laptop
is already infected. The original infection may have been a take-home
test, a malicious package, or a `folderOpen` task in a different
folder.

## Stopping it, and why order matters when you rotate credentials

The loader does not steal "a token". It steals whatever the machine can
read at the moment it runs: `process.env`, `~/.git-credentials`, browser
stores, wallet extensions. And it can run again. Three things make that
happen after the first infection:

1. The **detached `node -e` process** keeps running after the build or
   the editor task ends (SafeDep; OpenSourceMalware). It can fetch and
   evaluate new stages for as long as it lives.
2. Every **infected file on disk is a re-run point**. The loader runs
   again whenever a build tool imports an infected `postcss.config.mjs`,
   a `folderOpen` task fires, or a fake font or `spellright.dict` is run.
   A repository you cloned weeks ago, or an old checkout of one of your
   own projects, is enough.
3. The **private npm prefix `~/.node_modules`** and the Python stager it
   starts, plus the host artifacts (`~/.npl`, `~/.nlp`, `~/.n2`, `~/.pyp`
   and similar) and, on Windows, Startup items and scheduled tasks
   documented by SEAL.

So if you rotate a GitHub token first, the next build can steal the new
token. `live-respond.sh` and `live-respond.ps1` therefore do the steps
in this order: find the running processes, find the re-run points, stop
and move them aside on request, look again, and only then print
`SAFE TO ROTATE CREDENTIALS`. If anything is left it prints
`NOT SAFE YET` and the list.

How each item is recognised, and what is deliberately **not** flagged:

| Item | Flagged when | Not flagged |
|------|--------------|-------------|
| `node -e` / `bun -e` | Inline code carries a published marker (`global.i`, `global['!']`, `_$_xxxx`, wallets, XOR keys, C2 hosts and IPs); or an RPC dead-drop host plus `eval` / `/boot` / `_p_t`; or `http://IP:port/boot`; or `~/.node_modules` with axios or socket.io | Ordinary one-liners, `next dev`, webpack, a web3 script that only calls an RPC |
| node running a file | The file is under an artifact folder, a `.woff` / `.woff2`, `spellright.dict`, or `bun_environment.js` | Any other script |
| Python | The stage-3 lock file `tmp7A863DD1`, artifact folders, C2 hosts or IPs, MetaMask or Phantom extension IDs, or `.git-credentials` together with archive or upload code | Ordinary Python tools |
| Auto-push | `temp_auto_push.*` in a shell command line; a shell one-liner that amends and force-pushes with `--no-verify`; `git` doing that when its parent is an interpreter or the script | A person typing `git push --force-with-lease` (reported as a note at most, never killed) |
| Network | A node or Python process with an open connection to a snapshot C2 IP or to ports 1224, 2242, 5918, 5978 | Other programs on those ports |
| `.vscode/tasks.json` | A `runOn: folderOpen` task that downloads, runs inline code, runs a C2 host, or silently runs a script | `folderOpen` tasks such as `npm run watch`; build-only tasks |
| `~/.node_modules` | Contains both axios and socket.io-client | A folder you chose as your npm prefix (reported as REVIEW instead) |

Limits that follow from the research: the IOC lists are snapshots, so a
new marker, a renamed binary, or code running inside a legitimate
process will not match. The Python stealer's command line has not been
published in full, so the Python rules rely on the artifacts that were.
A SAFE verdict means "none of the published indicators remain", which is
the best a user-space tool can say.

Quarantine **moves** files; it never deletes. Each moved path is
recorded with its SHA-256 and mode in `manifest.json`, execute bits are
cleared while the file sits in quarantine, and `--restore` puts it back
only if the original path is free. Files that contain both your own
content and malware (shell startup files, crontab, git config) are not
moved: only the matching lines are commented out and the original is
saved. A project config that has been injected (for example
`postcss.config.mjs`) is moved whole, because the injected tail cannot
be separated from the rest with certainty. Restore the legitimate
version from a clean commit afterwards.

## History report and fork check

`history-report.sh` is read-only. For each repository it runs
`git log --all --reverse -p` and looks at every added line for the same
markers and loader patterns the scanner uses. The first commit with a
hit is the first infected commit. For each hit it records the author and
committer dates and raises two flags:

- the committer date is more than a day after the author date (an amend,
  a rebase, or a clock rewind), or
- the commit is dated before its own parent (the history was rewritten
  or the clock was set back).

Those flags exist because `temp_auto_push.bat` sets the clock back to the
last commit's timestamp, amends that commit, and force-pushes
(see [Spreading through the victim's repos](#spreading-through-the-victims-repos)).
Be careful with them in both directions. The amended commit keeps its
original timestamp, so it can look perfectly ordinary, and an honest
rebase can raise the first flag. The dates are a lead for the incident
timeline, not proof of who wrote the code. The local reflog's
`commit (amend)` count is printed as a further hint.

It then checks every branch, remote branch and tag, and the working tree,
and reports whether `HEAD` is infected now, whether the code survives only
in history, or sits on other branches. The summary table lists, per
repository, the status and the "infected since" date of the first commit.
Documentation, text and CSV files are skipped, and this kit's own `iocs/`,
`tests/`, `docs/` and `lib/` folders are skipped when the repository is a
copy of this kit, because they quote the markers on purpose.

`--github owner/repo` extends the question to copies on GitHub:

1. It reads the repository, lists up to `--max-forks` public forks
   (newest first), and for each fork fetches the file list of the default
   branch with one API call, then reads up to 40 config, task, font and
   dictionary files from `raw.githubusercontent.com` and applies the same
   patterns. A fork is reported only with the file that matched.
2. It reads the rate-limit headers after every call and stops before the
   limit is used up, then says how many forks were not checked. Without a
   token GitHub allows about 60 API calls an hour, so expect it to stop
   early on larger forks lists. `GITHUB_TOKEN` is passed to curl on
   standard input so it never appears in a process list or in output.
3. With a token it runs GitHub code search for the loader fingerprints
   found in your own repositories (the `global.i` marker value, for
   example `A9-1403-4`) plus any `--fingerprint` you give, and prints the
   reported file counts and a few sample URLs. Code search is not
   available without authentication.

What this cannot see: private repositories, plain clones, downloaded
ZIPs and machines that never pushed to GitHub; infections outside the
default branch of a fork or outside the file types listed above; and
anything GitHub has not indexed. Code search counts matching files, not
people, and includes security write-ups and IOC lists. It is a rough
hint that the same code is in the wild, not a count of victims, and this
tool never reports one.

## Sources

- OpenSourceMalware, PolinRider README (2026-03-07, updated 2026-04-11):
  https://github.com/OpenSourceMalware/PolinRider
- SafeDep, "PolinRider Switches to Ethereum C2 in 30+ Repositories" (2026-09-30):
  https://safedep.io/blog/polinrider-ethereum-c2-github-repositories
- SafeDep campaign page and IOC notes (`~/.node_modules`, lock file, XOR keys):
  https://safedep.io/ti/campaigns/polinrider
- Melted in Hex, "Dead Drops on the Blockchain: Reversing a DPRK npm Loader" (2026-06-22):
  https://meltedinhex.com/posts/polinrider-blockchain-dead-drop-npm/
- Chollima Hunter, PolinRider config injection and history rewrite:
  https://chollimahunter.github.io/hunts/polinrider-config-injection-and-history-rewrite/
- Unit 42, campaigns targeting job hunters / fake recruiters:
  https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/
- SEAL Radar, VS Code tasks abused by Contagious Interview:
  https://radar.securityalliance.org/vs-code-tasks-abuse-by-contagious-interview-dprk/

Known disagreements and limits (also in `THREATS.md`): C2 IPs rotate;
`166.88.134.82` (OpenSourceMalware via Chollima Hunter) and
`166.88.134.62` (SafeDep) are both listed; a Git history rewrite helper
for Linux/macOS has been inferred but not published as a file artifact
the way `temp_auto_push.bat` has.
