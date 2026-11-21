# IOC lists used by scan-repo.sh / scan-repo.ps1 and the optional Fleet queries in extras/

Every value here comes from a public source named next to it (see ../THREATS.md
for the full citations). Nothing was invented. Lines starting with `#` are
comments. Format is one value per line; `|` separates value and note where used.

Snapshot date: 2026-11-20 (PT). IP and domain lists rotate. Refresh with
`../update-iocs.sh`, which downloads the public SafeDep IOC CSV into
`feeds/` as *data only* (it is never executed).

Files
- strings-high.txt      Fixed strings that are campaign fingerprints (block).
- regex-high.txt        Extended regexes (grep -E / .NET compatible) for loader shapes (block).
- regex-medium.txt      Heuristics that also match some legit code (review).
- domains-high.txt      Attacker-controlled hosts (block).
- domains-medium.txt    Legit services the loaders abuse as dead drops (review in non-web3 repos).
- ips-high.txt          C2 IPs (snapshot; rotate often).
- hashes.txt            sha256 / sha1 / md5 of known malicious files.
- npm-packages.txt      Malicious npm package names, or name@version for hijacked versions.
- vscode-extensions.txt Malicious VS Code / Open VSX extension ids (publisher.name[@version]).
- host-artifacts.txt    Paths left on infected machines (used by host-check and the optional Fleet queries).
