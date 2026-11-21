# Real-sample validation

All scanning was static and read-only. No sample was executed. There was
no `npm` / `yarn` / `pnpm` install, no `node`, and no editor open of an
untrusted folder. Public evidence files were fetched as raw blobs at the
commit hashes published by SafeDep. A throwaway sandbox under
`/tmp/pr-sandbox` was used and then deleted.

Scanner under test: this repository, `scan-repo.sh` (and
`scan-repo.ps1` where noted), plus `host-check.sh`.

## Infected samples

### Local historical commit (eng-adan/faraz-technier)

The GitHub account `eng-adan` is suspended, so the remote was not
fetched. The object is still present in a local clone:

- Commit: [`8e1971c700e3eca99c53e5768bb065b7992a1fde`](https://github.com/eng-adan/faraz-technier/commit/8e1971c700e3eca99c53e5768bb065b7992a1fde)
  (message: "fix(build): re-export FooterDarkCard from Footer.tsx…";
  author date 2026-07-31 02:44 +0500).
- File extracted with `git show` only (no checkout of a live working
  tree): `postcss.config.mjs`.
- SHA-256 of that blob: `b2da9559446e02fdc8c4ef1c30ef35c0c3c37a4e04e43405a871dfa9d5426651`
- Size: 9330 bytes; line 11 is 9155 characters, with 507 spaces after
  `export default config;` and then a loader starting
  `global.i="A9-1403-4"`. Raw markers include `global['_V']`. After
  JavaScript `\uXXXX` unescape, the Ethereum wallet
  `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a` and XOR keys
  `y-p_>d$0B&@^1aQk` and `q4FZkxX{!h,Sr3=@` are visible. This matches
  SafeDep's Ethereum-C2 generation (wallet `0xa322E5f3…Ef1a`, `global.i="A…"`
  markers). `eslint.config.mjs` and `next.config.ts` in the same commit
  were clean.
- The same history later contains `d55f8b367e08fd7ed4e905d9f61f2a1ee8718099`
  ("remove malware from postcss.config.mjs").
- **Result: DETECTED**, `scan-repo.sh --no-git` exit 2, HIGH findings
  including `config-hidden-tail`, `config-long-line`, `loader-pattern`,
  `ioc-string`, `config-dangerous-api`. After the unicode-unescape
  improvement, escaped wallet and XOR keys are also reported as
  `ioc-string`. `scan-repo.ps1` (PowerShell 7.7, native subset) also
  exited 2 with the same class of HIGH findings.

### SafeDep confirmed-HEAD evidence files (2026-09-30)

Source list:
https://safedep.io/data/blogs/polinrider-ethereum-infected-repositories.csv
(35 repositories). Each evidence URL was downloaded at the pinned
commit as a raw file.

| # | Repository | Commit (short) | Evidence file | Download | `scan-repo.sh` |
|---|------------|----------------|---------------|----------|----------------|
| 1 | technext/100-template-list | 9c70c9b1 | `64 gentelella/vendors/autosize/build.js` | OK (after encoding the space in the path) | DETECTED (HIGH `loader-pattern`) |
| 2 | aboozaid/react-native-facerecognition | 3f49c10a | `example/metro.config.js` | OK | DETECTED |
| 3 | efstathiosntonas/react-native-style-libraries-benchmark | 5d8216b8 | `tailwind.config.js` | OK | DETECTED |
| 4 | SFARPak/AliFullStack | c34f5cfe | `Roo-Code/src/esbuild.mjs` | OK | DETECTED |
| 5 | aliezzahn/event-timeline-roadmap | ac6232d8 | `postcss.config.mjs` | OK | DETECTED |
| 6 | gumlau/nextjs-seo-blog-starter | a76b91d8 | `next.config.ts` | OK | DETECTED |
| 7 | flecs-hub/flecs-polyglot | a200d50c | `ts/examples/basic/src/index.ts` | OK | DETECTED |
| 8 | TheSentora/Crypto-Web3-Copilot-App | 5869c7c4 | `copilot-app/Ai/Ai/next.config.js` | OK | DETECTED |
| 9 | subramanianv/CertificateVerification | a4d2f786 | `webpack.config.js` | OK | DETECTED |
| 10 | morganjweaver/liquibet | a789efb0 | `frontend/postcss.config.js` | OK | DETECTED |
| 11 | Dhruvone8/iChat | 2dcef82f | `backend/server.js` | OK | DETECTED |
| 12 | Web3-Builders-Alliance/convergence | e2e92e2a | `app/postcss.config.js` | OK | DETECTED |
| 13 | Lynxverse/lynxverse.io | d29d777d | `postcss.config.js` | OK | DETECTED |
| 14 | creativetimofficial/black-dashboard-django | f55a30c3 | `postcss.config.js` | OK | DETECTED |
| 15 | creativetimofficial/argon-dashboard-django | f3c0a8f8 | `apps/static/assets/vendor/bootstrap-datetimepicker.js` | OK | DETECTED |
| 16 | creativetimofficial/material-dashboard-django | fab45b23 | `postcss.config.js` | OK | DETECTED |
| 17 | creativetimofficial/argon-dashboard-flask | 0ca59941 | `apps/static/assets/vendor/bootstrap-datetimepicker.js` | OK | DETECTED |
| 18 | CommunityPro/portfolio-html | 724291e1 | `public/fonts/fa-solid-400.woff2` | OK | DETECTED (HIGH `fake-asset`) |
| 19 | Mshandev/Food-Delivery | 81e064ef | `admin/vite.config.js` | OK | DETECTED |
| 20 | tailwindadmin/admin | e818e8e7 | `postcss.config.js` | **404** (commit and file no longer on GitHub) | not retrievable; not a scanner miss |
| 21 | richardokonicha/parsesig | e0457487 | `public/fonts/fa-solid-400.woff2` | OK | DETECTED |
| 22 | Iamzaryab/Flutter-Movie-App-with-Clean-Architecture-and-RiverPod-State-Management | 6c1c25b5 | `public/fonts/fa-solid-400.woff2` | OK | DETECTED |
| 23 | ZahraShahid/MyRealEstateWebsite | cf1dd1f0 | `Backend/routes/AboutUs.js` | OK | DETECTED |
| 24 | gigabytedevelopers/FireFiles | 99216df3 | `public/fonts/fa-solid-500.woff2` | OK | DETECTED |
| 25 | umairjameel321/next-auth-mongodb | 79409570 | `postcss.config.js` | OK | DETECTED |
| 26 | umairjameel321/next14-restapis | c16c2676 | `postcss.config.mjs` | OK | DETECTED |
| 27 | mE-uMAr/fastapi-crons | f4700286 | `public/fonts/fa-solid-400.woff2` | OK | DETECTED |
| 28 | umairjameel321/authjsv5nextjs | 906ca62e | `postcss.config.mjs` | OK | DETECTED |
| 29 | oslabs-beta/projectArtemis | a4d3e4a6 | `public/fonts/fa-solid-400.woff2` | OK | DETECTED |
| 30 | boostcampwm-2022/android04-BEEP | 8ce55b1c | `public/fonts/fa-solid-400.woff2` | OK | DETECTED |
| 31 | suleman-the-stammer/zeropark-master | 93e9ccc8 | `vite.config.js` | OK | DETECTED |
| 32 | echo-riga/Help-Desk-System | 7a5f9963 | `frontend/vite.config.js` | OK | DETECTED |
| 33 | SahilSharan/multimart-react-ecommerce-main | 3ab63f2a | `src/index.js` | OK | DETECTED |
| 34 | Leoneldev532/Free-Ui-game | d531092c | `postcss.config.mjs` | OK | DETECTED |
| 35 | devpardo/mannylapidamaker | 74939f47 | `postcss.config.mjs` | OK | DETECTED |

Full commit SHAs and blob URLs are in the SafeDep CSV above. Two
additional public `tasks.json` lures named in OpenSourceMalware
(`Devba/lmng-top-`, `wyrustaaruz/cal-eco-platform`) also returned 404
and were not counted as misses.

### Published `temp_auto_push.bat`

The Windows propagation script was extracted from the OpenSourceMalware
PolinRider README (the text OpenSourceMalware published as the
fingerprint) and scanned as a file named `temp_auto_push.bat`.

- **Result: DETECTED**, exit 2, HIGH `ioc-filename`.

### Infected-sample totals

- Available infected samples tested: **36** (34 SafeDep evidence files
  + local `8e1971c` postcss + published `temp_auto_push.bat`).
- Detected (exit 2 / at least one HIGH): **36**.
- Missed: **0** among available samples.
- Not retrievable: **1** SafeDep repo (`tailwindadmin/admin`, HTTP 404).

## Clean repositories (false positives)

Default-branch tarballs of 20 popular projects were fetched from
GitHub's `codeload` (no git hooks, no install) and scanned with
`--no-git`.

| Repository | Branch | After fixes, HIGH | After fixes, MEDIUM (review only) |
|------------|--------|-------------------|-----------------------------------|
| expressjs/express | master | 0 | 0 |
| axios/axios | main | 0 | 4 |
| lodash/lodash | main | 0 | 4 |
| typicode/json-server | main | 0 | 0 |
| socketio/socket.io | main | 0 | 7 |
| cheeriojs/cheerio | main | 0 | 0 |
| jaredpalmer/formik | main | 0 | 7 |
| reduxjs/redux | master | 0 (was 1) | 10 |
| moment/moment | master | 0 | 1 |
| nodemailer/nodemailer | master | 0 | 0 |
| prettier/prettier | main | 0 (was 1) | 10 |
| eslint/eslint | main | 0 | 4 |
| caolan/async | master | 0 | 1 |
| preactjs/preact | main | 0 | 3 |
| tailwindlabs/tailwindcss | main | 0 | 1 |
| vitejs/vite-plugin-react | main | 0 | 1 |
| typicode/husky | main | 0 | 0 |
| iamkun/dayjs | main | 0 | 0 |
| markedjs/marked | master | 0 | 2 |
| webpack/webpack-cli | main | 0 (was 1) | 5 |

- Clean repos scanned: **20**.
- HIGH false positives **before** the fixes below: **3** (prettier,
  redux, webpack-cli).
- HIGH false positives **after** the fixes: **0**.
- MEDIUM findings remain on several clean repos (typically
  `feed-domain` hits on `www.youtube.com` / `gist.github.com` from the
  SafeDep IOC snapshot, lockfile source comments, or `lifecycle-script`
  on `prepare`). Those are exit code 1 ("review"), not a stop.

The three HIGH false positives, and the fixes, were:

1. **prettier/prettier** `knip.config.js:16` — a *comment* mentioning
   `` new Function() `` was treated as `config-dangerous-api`. The
   check now ignores matches that sit after `//` on the same line (or
   inside `/* */`).
2. **reduxjs/redux** `website/src/pages/index.js:91` — a 2406-character
   SVG `path` in a page component, not a build config. For `index.js` /
   `App.js`, a long line is now MEDIUM unless it also looks like an
   appended loader (hidden tail, `eval`, `global.i` / `global['_V']`,
   or a line longer than 8000 characters).
3. **webpack/webpack-cli**
   `test/build/compile-cache/webpack.config.js:3` — a test helper that
   imports `node:child_process` and nothing else malicious.
   `child_process` alone in a build config is now MEDIUM; `eval`,
   `new Function`, `atob`, `global.i=` and similar stay HIGH.

Re-scans after the fixes still DETECTED the local `8e1971c` sample and
spot-checked SafeDep samples (`aliezzahn/event-timeline-roadmap`,
`CommunityPro/portfolio-html`). The CertificateVerification
`webpack.config.js` infection had also been DETECTED via hidden-tail,
long-line, and loader-pattern, so downgrading isolated `child_process`
does not drop that case.

`scan-repo.ps1` on the local faraz sample: exit 2, HIGH. On
webpack-cli: HIGH 0, MEDIUM 4, exit 1.

## Host-check

`host-check.sh` was pointed at throwaway directories via `HOME=`:

- Empty fake home: exit 0 (no artifacts). The INFO note that npm
  `ignore-scripts` is off reflects the *real* user config on the test
  machine, not the fake home.
- Fake home containing empty `.npl`, `.nlp`, `.n2`, `.n3`,
  `store.node`, `.npm/vhost.ctl`, and `.node_modules`: exit 2, seven
  HIGH artifact hits.
- A temporary `/tmp/tmp7A863DD1.tmp` (SafeDep Python-stealer lock
  file), then deleted: exit 2, HIGH on that path.

Process and socket checks in `host-check.sh` still inspect the live
machine; they did not fire during these runs.

## Coverage added from the deep dive

- npm package names `tailwind-color-shades` and `safe-validate` (Melted
  in Hex, 2026-06-22).
- Host artifacts `/tmp/tmp7A863DD1.tmp` and
  `AppData/Local/Temp/tmp7A863DD1.tmp` (SafeDep, 2026-09-30).
- JavaScript `\uXXXX` / `\xHH` unescape before `ioc-string` matching,
  so escaped wallets and XOR keys in configs are still found. Defanged
  regression fixture only (no live loader) is in `tests/run-tests.sh`.
- `scan-repo.ps1` no longer calls `Join-Path` on empty
  `ProgramFiles` / `LOCALAPPDATA` (so the native subset can run on
  non-Windows).

## Tests

`bash tests/run-tests.sh`: **39 passed, 0 failed** (31 original
expectations plus 8 regression checks). `shellcheck -x` on the shell
scripts and hooks: exit 0.

## What was not tested

- A live `.vscode/tasks.json` `folderOpen` lure from a still-public
  victim repo (the OpenSourceMalware example repos named above are
  gone). The synthetic fixture in `tests/run-tests.sh` still covers
  this shape.
- Running the later Node/Python stealer stages (deliberately out of
  scope).
- Windows Defender / osquery / Fleet live policies.
