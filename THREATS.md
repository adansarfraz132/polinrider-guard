# Threats this kit defends against (research snapshot, 2026-11-20 PT)

Plain-language summary first, then details and sources. Every indicator in `iocs/`
comes from the sources below; none were invented. Indicators rotate, so the
*behaviour* checks (config injection, autorun tasks, install scripts) matter more
than any single IP or domain.

## In one paragraph

Attackers (mostly North Korean groups) now target developers rather than servers.
They hide a small obfuscated script inside files that developers never read closely
(the end of a very long line in `postcss.config.mjs`, a fake font file, a VS Code
`tasks.json`), or inside an npm package's install script. The moment you run
`npm install`, open the folder in VS Code/Cursor and click "Trust", or run the dev
server, it steals browser passwords, crypto wallets, `.env` files, SSH keys and
GitHub/npm tokens, then uses those tokens to infect *your* repos and packages.
The defence is: scan before you install or open, install with scripts off, never
auto-run workspace tasks, and don't install brand-new package versions.

## PolinRider (DPRK; overlaps Contagious Interview / "TasksJacker")
- How it spreads: trojanised fake-interview repos, npm lookalikes of Tailwind
  plugins (e.g. `tailwindcss-style-animate`), and malicious pull requests to real
  projects (SafeDep documents an `oxc` PR).
- Hiding place: an obfuscated JS loader appended to build configs, often after
  hundreds of spaces so it is off-screen; `postcss.config.mjs` is the most common
  file (~62% in OpenSourceMalware's dataset), also `tailwind.config.*`,
  `next.config.*`, `vite.config.*`, `eslint.config.*`, and fake `fa-solid-400.woff2`
  / `spellright.dict` files that hold the payload.
- Autorun: `.vscode/tasks.json` with `"runOptions": {"runOn": "folderOpen"}`.
- Persistence in git: `temp_auto_push.bat` amends and force-pushes back-dated
  commits; `config.bat` added to `.gitignore`.
- C2: looked up from blockchain "dead drops" (TRON/Aptos, later Ethereum
  transactions where the C2 address is encoded in the data).
- Payload: Node + Python infostealer; installs `axios`/`socket.io-client` into
  `~/.node_modules`.
- Sources: OpenSourceMalware PolinRider repo and scanner
  (https://github.com/OpenSourceMalware/PolinRider,
  https://github.com/OpenSourceMalware/PolinRider/blob/main/polinrider-scanner.sh),
  SafeDep (https://safedep.io/blog/polinrider-ethereum-c2-github-repositories,
  IOC CSV https://safedep.io/ti/ioc.csv), Chollima Hunter
  (https://chollimahunter.github.io/hunts/polinrider-config-injection-and-history-rewrite/).

## Contagious Interview / BeaverTail / InvisibleFerret (DPRK)
- Fake recruiters on LinkedIn send a "take-home test" repo. Running it (or opening
  it in a trusting editor) starts BeaverTail (JS stealer), which pulls InvisibleFerret
  (Python backdoor).
- Host traces: `~/.npl`, `~/.nlp`, `~/.n2`, `~/.n3`, `~/.pyp`, `~/.npc`, `~/.myvars`,
  `~/.linvidia`, `store.node`, `~/.npm/vhost.ctl`; C2 ports 1224, 2242, 5918, 5978.
- SEAL documents victims who only clicked "Trust" on the workspace; the fix is
  `task.allowAutomaticTasks: off` (shipped in `safe-defaults/vscode-user-settings.json`).
- Sources: Unit 42 (https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/,
  https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/),
  SEAL Radar (https://radar.securityalliance.org/vs-code-tasks-abuse-by-contagious-interview-dprk/),
  Chollima Hunter (https://chollimahunter.github.io/hunts/contagious-interview-beavertail-invisibleferret-chain/),
  dev.to write-up (https://dev.to/0one/inside-a-trojanized-nextjs-project-beavertail-invisibleferret-and-a-hidden-tsunamikit-loader-815).

## Shai-Hulud 1 and 2 (npm worm)
- Stolen npm tokens are used to republish packages with a `preinstall`/`postinstall`
  hook (`bundle.js`; v2: `setup_bun.js` + `bun_environment.js`). It steals tokens,
  publishes them to new GitHub repos ("Sha1-Hulud: The Second Coming"), and v2 can
  wipe the home directory if it cannot spread.
- Sources: Securelist (https://securelist.com/shai-hulud-worm-infects-500-npm-packages-in-a-supply-chain-attack/117547/),
  Datadog (https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/),
  cirosec IOCs (https://cirosec.de/en/news/a-collection-of-shai-hulud-2-0-iocs/),
  mnemonic (https://www.mnemonic.io/resources/blog/advisory-shai-hulud-2.0-supply-chain-campaign-rapidly-spreading-through-npm-packages-and-github/),
  Palo Alto (https://www.paloaltonetworks.com/blog/cloud-security/npm-supply-chain-attack/),
  NCSC NZ (https://www.ncsc.govt.nz/alerts/supply-chain-compromise-impacting-npm-ecosystem/).

## s1ngularity (malicious Nx releases)
- `telemetry.js` ran at `postinstall`, used installed AI CLIs with
  `--dangerously-skip-permissions` / `--yolo` / `--trust-all-tools` to hunt for
  secrets, wrote `/tmp/inventory.txt`, created public `s1ngularity-repository`
  repos, and appended `sudo shutdown -h 0` to shell rc files.
- Sources: Nx advisory (https://github.com/nrwl/nx/security/advisories/ghsa-cxm3-wv7p-598c),
  Wiz (https://www.wiz.io/blog/s1ngularity-supply-chain-attack),
  Kaspersky (https://www.kaspersky.com/blog/nx-build-s1ngularity-supply-chain-attack/54223/),
  Panther (https://panther.com/blog/nx-threat-analysis), OSSPrey (https://www.ossprey.com/blog/nx-package-compromise).

## qix npm account compromise (chalk, debug, …)
- Hijacked versions (e.g. `chalk@5.6.1`, `debug@4.4.2`) carried a browser crypto
  drainer. Listed by exact version in `iocs/npm-packages.txt`.
- Sources: Socket (https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack),
  Semgrep (https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack/),
  Snyk (https://snyk.io/blog/npm-supply-chain-attack-via-open-source-maintainer-compromise/),
  Orca (https://orca.security/resources/blog/qix-npm-attack/).

## GlassWorm (malicious VS Code / Open VSX extensions)
- Extensions hide code in invisible Unicode variation selectors, use Solana for
  C2, later shipped Rust native loaders, and spread through extension auto-update.
  Mitigation: set `extensions.autoUpdate` and `extensions.autoCheckUpdates` to false
  in VS Code / Cursor user settings (`apply-dev-defaults.sh` / `.ps1` does this).
- Sources: Palo Alto (https://www.paloaltonetworks.com/blog/security-operations/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace/,
  https://www.paloaltonetworks.com/blog/security-operations/glassworm-evolution/,
  https://www.paloaltonetworks.com/blog/security-operations/glassworm-goes-native-rust-loader-vscode-openvsx/),
  Endor Labs (https://www.endorlabs.com/reports/invisible-threats-glassworm-unicode-vscode),
  BleepingComputer (https://www.bleepingcomputer.com/news/security/self-spreading-glassworm-malware-hits-openvsx-vs-code-registries/).

## Safe defaults referenced
- npm config (`ignore-scripts`, `min-release-age`): https://docs.npmjs.com/cli/v11/using-npm/config/
- pnpm 11 (`minimumReleaseAge`, `strictDepBuilds`, `allowBuilds`, `blockExoticSubdeps`,
  `trustPolicy`): https://pnpm.io/blog/releases/11.0, https://pnpm.io/supply-chain-security, https://pnpm.io/settings/build
- Release cooldowns across package managers: https://craigory.dev/blog/2026-05-29/package-manager-release-cooldown/

## Known gaps / not verified
- IP lists disagree in one place: 166.88.134.82 (OSM via Chollima Hunter) vs
  166.88.134.62 (SafeDep). Both are listed.
- One GlassWorm extension id is published with both a capital-I and lower-case-l
  spelling; both are listed.
- New variants will change strings, wallets and IPs. Run `update-iocs.sh` weekly;
  the behaviour checks still catch the shape of the attack.
