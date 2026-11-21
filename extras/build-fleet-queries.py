#!/usr/bin/env python3
"""Generate optional Fleet osquery reports and policies from iocs/.

Re-run after editing the IOC lists:
    python3 extras/build-fleet-queries.py

Writes YAML into extras/generated/. These use Fleet free/open-source features
(reports + visibility policies) and core osquery tables shipped with fleetd
(file, processes, process_open_sockets, vscode_extensions, npm_packages,
yara_file, scheduled_tasks, startup_items, launchd, crontab). Optional; the
rest of this kit does not depend on Fleet.
"""
import os, re, textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
IOC = os.path.join(HERE, "..", "iocs")
OUT = os.path.join(HERE, "generated")

def lst(name):
    out = []
    with open(os.path.join(IOC, name)) as f:
        for l in f:
            l = l.strip()
            if l and not l.startswith("#"):
                out.append(l)
    return out

def q(s):  # SQL string literal
    return "'" + s.replace("'", "''") + "'"

ips = lst("ips-high.txt")
ext = [e.lower() for e in lst("vscode-extensions.txt")]
npm = [p.lower() for p in lst("npm-packages.txt")]
npm_any = sorted({p for p in npm if "@" not in p.lstrip("@")})
npm_ver = sorted({p for p in npm if "@" in p.lstrip("@")})
C2_PORTS = "1224, 2242, 5918, 5978"

# ---- home-folder artifacts (host-artifacts.txt, sourced in THREATS.md)
HOME_FILES = [".npl", ".nlp", ".npc", ".myvars", ".linvidia", "store.node", ".npm/vhost.ctl", ".npm/npm-compiler.log"]
HOME_DIRS = [".n2", ".n3", ".pyp", ".node_modules", ".npm/scoped_dir"]  # matched as prefix% (dirs come back as path/)
def home_patterns(roots, sep):
    pats = []
    for r in roots:
        for f in HOME_FILES:
            pats.append(r + f.replace("/", sep))
        for d in HOME_DIRS:
            pats.append(r + d.replace("/", sep) + "%")
    return pats
MAC_PATS = home_patterns(["/Users/%/"], "/") + ["/tmp/inventory.txt%", "/private/tmp/inventory.txt%"]
LIN_PATS = home_patterns(["/home/%/", "/root/"], "/") + ["/tmp/inventory.txt%"]
WIN_PATS = home_patterns(["C:\\Users\\%\\"], "\\") + [
    "C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Windows\\Applications\\Runtime Broker.exe",
    "C:\\Users\\%\\AppData\\Local\\Microsoft\\Windows\\Applications\\msedge.exe",
    "C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Windows Update Script.pyw",
    "C:\\Users\\%\\.vscode\\argv.exe",
]
def file_where(pats):
    return "\n   OR ".join("path LIKE " + q(p) for p in pats)

# ---- extension directories (folder name = publisher.name-version)
def ext_dirs(roots):
    out = []
    for r in roots:
        for d in [".vscode/extensions", ".vscode-insiders/extensions", ".cursor/extensions", ".vscode-oss/extensions", ".windsurf/extensions"]:
            out.append(r + d + "/%")
    return out
def ext_match(col="lower(filename)"):
    exact = [e.replace("@", "-") for e in ext if "@" in e]
    anyv = [e for e in ext if "@" not in e]
    parts = [col + " IN (" + ", ".join(q(e) for e in exact) + ")"] if exact else []
    parts += [col + " LIKE " + q(e + "-%") for e in anyv]
    return "\n     OR ".join(parts)
def ext_query(roots, sep):
    pats = [p.replace("/", sep) for p in ext_dirs(roots)]
    # Directories come back as 'path/' with filename '.', so match on the path instead.
    col = "lower(rtrim(replace(path, " + q(sep) + ", '/'), '/'))"
    exact = [e.replace("@", "-") for e in ext if "@" in e]
    anyv = [e for e in ext if "@" not in e]
    conds = ["{} LIKE {}".format(col, q("%/" + e)) for e in exact] + ["{} LIKE {}".format(col, q("%/" + e + "-%")) for e in anyv]
    return ("SELECT path, datetime(mtime, 'unixepoch') AS modified_utc FROM file\nWHERE (" + "\n   OR ".join("path LIKE " + q(p) for p in pats) +
            ")\n  AND type = 'directory'\n  AND (" + "\n    OR ".join(conds) + ")")

# ---- YARA rules (inline, no external rule files needed)
def yara_rule(name, strings, cond, regexes=()):
    body = " ".join('$s{} = "{}" nocase'.format(i, s.replace("\\", "\\\\").replace('"', '\\"')) for i, s in enumerate(strings))
    body += " " + " ".join("$r{} = /{}/".format(i, r) for i, r in enumerate(regexes))
    return "rule {} {{ strings: {} condition: {} }}".format(name, body.strip(), cond)
POLIN = yara_rule("polinrider_config",
    ["rmcej%otb%", "Cot%3t=shtP", "_$_1e42", "global['!']", "global['_V']", "0x33ff3edaf55a8e03dcbc7cb40d498a49cd499891", "0xa322e5f3d311d3080e6f0121063e9adc2490ef1a", "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP"],
    "any of them", [r"[^ \t\r\n][ ]{200,}[^ \t\r\n]", r"global\.[oi] *= *['\"]A?[0-9]+-"])
TASKS = yara_rule("vscode_folderopen_loader",
    ["folderOpen"], "$s0 and any of ($r*)",
    [r"node +[^ \"]+\.(woff2?|ttf|otf|dict|png|jpe?g|svg|ico)", r"(curl|wget|iwr|irm|Invoke-WebRequest)[^\"]*\|", r"vercel\.app", r"e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"])
SHUT = yara_rule("s1ngularity_shutdown", ["sudo shutdown -h 0"], "any of them")
VSOFF = yara_rule("vscode_autotasks_off", [], "$r0", [r"\"task\.allowAutomaticTasks\" *: *\"off\""])
NPMOFF = yara_rule("npm_ignore_scripts", [], "$r0", [r"(^|\n) *ignore-scripts *= *true"])

CFG_NAMES = ["postcss.config.%", "tailwind.config.%", "eslint.config.%", "next.config.%", "vite.config.%", "webpack.config.%", "astro.config.%", "babel.config.%"]
def project_paths(home, sep, names, depths=(1, 2, 3, 4)):
    out = []
    for d in depths:
        for n in names:
            out.append(home + sep.join(["%"] * d) + sep + n)
    return out

def yara_q(paths, rule, extra_cols="path, matches, strings"):
    return "SELECT {} FROM yara_file\nWHERE ({})\n  AND sigrule = {}\n  AND count > 0".format(extra_cols, "\n   OR ".join("path LIKE " + q(p) for p in paths), q(rule))

PROC_SUS = [
    "%.woff2%", "%.woff %", "%spellright.dict%", "%/.n2/%", "%\\.n2\\%", "%/.npl%", "%\\.npl%", "%/.nlp%", "%\\.nlp%",
    "%/.pyp/%", "%\\.pyp\\%", "%bun_environment.js%", "%setup_bun.js%", "%/.npm/scoped_dir%", "%\\.npm\\scoped_dir%",
    "%global.r=require%", "%global.i=''%", "%global.o=''%",
]
def proc_query():
    names = "('node', 'node.exe', 'bun', 'bun.exe', 'python', 'python3', 'python.exe', 'pythonw.exe')"
    likes = "\n      OR ".join("p.cmdline LIKE " + q(s.replace("''", "'")) for s in PROC_SUS)
    return textwrap.dedent("""\
        SELECT p.pid, p.name, p.path, substr(p.cmdline, 1, 400) AS cmdline, p.uid, p.parent,
               datetime(p.start_time, 'unixepoch') AS started_utc
        FROM processes p
        WHERE (lower(p.name) IN {names} AND (
              {likes}))
           OR (lower(p.name) IN ('cmd.exe', 'bash', 'sh') AND p.cmdline LIKE '%temp_auto_push.bat%')
           OR (lower(p.name) IN ('claude', 'gemini', 'q', 'node', 'node.exe')
               AND (p.cmdline LIKE '%--dangerously-skip-permissions -p%' OR p.cmdline LIKE '%--yolo -p%' OR p.cmdline LIKE '%--trust-all-tools --no-interactive%'))""").format(names=names, likes=likes)

def sock_query():
    return textwrap.dedent("""\
        SELECT DISTINCT s.pid, p.name, p.path, s.remote_address, s.remote_port, substr(p.cmdline, 1, 300) AS cmdline
        FROM process_open_sockets s LEFT JOIN processes p USING (pid)
        WHERE s.remote_address IN ({ips})
           OR (s.remote_port IN ({ports}) AND s.remote_address NOT IN ('', '0.0.0.0', '::', '127.0.0.1', '::1'))""").format(
        ips=", ".join(q(i) for i in ips), ports=C2_PORTS)

def npm_query():
    return ("SELECT name, version, path, directory FROM npm_packages\nWHERE lower(name) IN (" + ", ".join(q(n) for n in npm_any) +
            ")\n   OR lower(name) || '@' || version IN (" + ", ".join(q(n) for n in npm_ver) + ")")

# ---------------------------------------------------------------- reports
reports = []
def report(name, desc, query, platform, interval=86400):
    reports.append(dict(name=name, description=desc, query=query, platform=platform, interval=interval))

src = " Sources: THREATS.md."
report("Dev malware - home-folder artifacts (macOS)", "Files/folders left by BeaverTail/InvisibleFerret (Contagious Interview), PolinRider stage 3 and s1ngularity/Nx. Any row is a likely infection." + src,
       "SELECT path, type, size, datetime(mtime, 'unixepoch') AS modified_utc FROM file\nWHERE " + file_where(MAC_PATS), "darwin", 3600)
report("Dev malware - home-folder artifacts (Linux)", "Same as the macOS report, for Linux laptops." + src,
       "SELECT path, type, size, datetime(mtime, 'unixepoch') AS modified_utc FROM file\nWHERE " + file_where(LIN_PATS), "linux", 3600)
report("Dev malware - home-folder artifacts (Windows)", "Same as the macOS report plus the Contagious Interview persistence files SEAL documented on Windows." + src,
       "SELECT path, type, size, datetime(mtime, 'unixepoch') AS modified_utc FROM file\nWHERE " + file_where(WIN_PATS), "windows", 3600)
report("Dev malware - suspicious node/python/bun processes", "Processes whose command line matches the loaders: node running a .woff2/.dict file, ~/.n2 or ~/.npl Python, Shai-Hulud bun_environment.js, PolinRider detached node -e (global.r=require), and AI CLIs started with the s1ngularity flags.",
       proc_query(), "darwin,linux,windows", 300)
report("Dev malware - connections to known C2 (snapshot)", "Open sockets to C2 IPs from the research (they rotate) or to the Contagious Interview ports 1224/2242/5918/5978.",
       sock_query(), "darwin,linux,windows", 300)
report("VS Code-family extensions (inventory)", "Every VS Code / Cursor / Windsurf extension per user, for spotting new or unknown publishers (GlassWorm spread through extensions).",
       "SELECT u.username, e.name, e.publisher, e.version, e.path, e.vscode_edition,\n       datetime(e.installed_at, 'unixepoch') AS installed_utc\nFROM users u CROSS JOIN vscode_extensions e USING (uid)", "darwin,linux,windows")
report("Known-malicious editor extensions installed (macOS/Linux)", "Extension folders that match the GlassWorm lists (Koi / Palo Alto Networks).",
       ext_query(["/Users/%/", "/home/%/", "/root/"], "/"), "darwin,linux")
report("Known-malicious editor extensions installed (Windows)", "Same as above for Windows profiles.",
       ext_query(["C:\\Users\\%\\"], "\\"), "windows")
report("Known-malicious npm packages (global installs)", "Globally installed npm packages that match the malicious list (PolinRider lookalikes, BeaverTail carriers, hijacked Nx and qix/chalk versions).",
       npm_query(), "darwin,linux,windows")
report("PolinRider markers in project build configs (macOS)", "YARA scan of postcss/tailwind/eslint/next/vite/webpack/astro/babel configs 2-4 folders below each home folder for the PolinRider markers or a payload hidden after 200+ spaces.",
       yara_q(project_paths("/Users/%/", "/", CFG_NAMES), POLIN), "darwin")
report("PolinRider markers in project build configs (Linux)", "Same YARA scan for Linux home folders.",
       yara_q(project_paths("/home/%/", "/", CFG_NAMES), POLIN), "linux")
report("PolinRider markers in project build configs (Windows)", "Same YARA scan for Windows profiles.",
       yara_q(project_paths("C:\\Users\\%\\", "\\", CFG_NAMES), POLIN), "windows")
report("VS Code autorun loader tasks in projects (macOS/Linux)", "Project .vscode/tasks.json files with runOn: folderOpen that run a fake font, pipe a download to a shell, or reference the PolinRider Vercel hosts / template UUID.",
       yara_q(project_paths("/Users/%/", "/", [".vscode/tasks.json"], (1, 2, 3)) + project_paths("/home/%/", "/", [".vscode/tasks.json"], (1, 2, 3)), TASKS, "path, matches"), "darwin,linux")
report("VS Code autorun loader tasks in projects (Windows)", "Same as above for Windows profiles.",
       yara_q(project_paths("C:\\Users\\%\\", "\\", [".vscode\\tasks.json"], (1, 2, 3)), TASKS, "path, matches"), "windows")
report("s1ngularity shutdown line in shell startup files", "The Nx/s1ngularity malware appended 'sudo shutdown -h 0' to ~/.bashrc and ~/.zshrc (Wiz).",
       yara_q([h + f for h in ("/Users/%/", "/home/%/", "/root/") for f in (".bashrc", ".zshrc", ".bash_profile", ".profile", ".zprofile")], SHUT, "path, matches"), "darwin,linux")
report("Persistence pointing at dev-malware paths (Windows)", "Scheduled tasks and startup items used by the Contagious Interview miner (task 'Runtime Broker', Startup 'Windows Update Script.pyw') or running node/python from ~/.n2, ~/.npl, ~/.npm.",
       textwrap.dedent("""\
        SELECT 'scheduled_task' AS kind, name, action AS command, path FROM scheduled_tasks
        WHERE name = 'Runtime Broker' OR action LIKE '%\\.n2\\%' OR action LIKE '%\\.npl%' OR action LIKE '%\\.nlp%' OR action LIKE '%\\.npm\\%'
        UNION ALL
        SELECT 'startup_item', name, args, path FROM startup_items
        WHERE path LIKE '%Windows Update Script.pyw%' OR path LIKE '%\\.n2\\%' OR args LIKE '%\\.n2\\%' OR args LIKE '%\\.npl%' OR args LIKE '%\\.npm\\%'"""), "windows", 3600)
report("Persistence pointing at dev-malware paths (macOS/Linux)", "LaunchAgents, cron entries and startup items that run node/python from the malware folders.",
       textwrap.dedent("""\
        SELECT 'startup_item' AS kind, name, args AS command, path FROM startup_items
        WHERE path LIKE '%/.n2/%' OR args LIKE '%/.n2/%' OR args LIKE '%/.npl%' OR args LIKE '%/.nlp%' OR args LIKE '%/.npm/%' OR args LIKE '%/.node_modules/%'
        UNION ALL
        SELECT 'crontab', event, command, path FROM crontab
        WHERE command LIKE '%/.n2/%' OR command LIKE '%/.npl%' OR command LIKE '%/.nlp%' OR command LIKE '%/.npm/%' OR command LIKE '%/.node_modules/%'"""), "darwin,linux", 3600)

# ---------------------------------------------------------------- policies (pass = returns a row)
policies = []
def policy(name, platform, desc, resolution, query):
    policies.append(dict(name=name, platform=platform, description=desc, resolution=resolution, query=query))
def none_of(inner):
    return "SELECT 1 WHERE NOT EXISTS (\n" + textwrap.indent(inner, "  ") + "\n)"
INC = "Treat as an incident: take the laptop off the network, tell your security team, and rotate GitHub/npm/cloud/SSH credentials from a clean device. See README.md."
policy("No dev-malware artifacts in home folders (macOS)", "darwin", "Fails if any BeaverTail/InvisibleFerret, PolinRider or s1ngularity artifact exists.", INC,
       none_of("SELECT 1 FROM file WHERE " + file_where(MAC_PATS)))
policy("No dev-malware artifacts in home folders (Linux)", "linux", "Fails if any BeaverTail/InvisibleFerret, PolinRider or s1ngularity artifact exists.", INC,
       none_of("SELECT 1 FROM file WHERE " + file_where(LIN_PATS)))
policy("No dev-malware artifacts in home folders (Windows)", "windows", "Fails if any BeaverTail/InvisibleFerret or Contagious Interview persistence file exists.", INC,
       none_of("SELECT 1 FROM file WHERE " + file_where(WIN_PATS)))
policy("No known-malicious editor extensions (macOS/Linux)", "darwin,linux", "Fails if a GlassWorm-listed VS Code/Cursor extension folder exists.",
       "Uninstall the extension, then treat as an incident (GlassWorm steals GitHub/npm/Open VSX tokens). " + INC, none_of(ext_query(["/Users/%/", "/home/%/", "/root/"], "/")))
policy("No known-malicious editor extensions (Windows)", "windows", "Fails if a GlassWorm-listed VS Code/Cursor extension folder exists.",
       "Uninstall the extension, then treat as an incident. " + INC, none_of(ext_query(["C:\\Users\\%\\"], "\\")))
policy("No known-malicious global npm packages", "darwin,linux,windows", "Fails if a globally installed npm package is on the malicious list.",
       "npm uninstall -g <package>, then treat as an incident. " + INC, none_of(npm_query()))
policy("No s1ngularity shutdown line in shell startup files", "darwin,linux", "Fails if ~/.bashrc or ~/.zshrc contains 'sudo shutdown -h 0'.",
       "Remove the line, delete /tmp/inventory.txt*, check GitHub for s1ngularity-repository repos, rotate tokens.",
       none_of(yara_q([h + f for h in ("/Users/%/", "/home/%/", "/root/") for f in (".bashrc", ".zshrc")], SHUT, "1")))
def vscode_settings(sep, roots):
    out = []
    for r in roots:
        for app in ["Code", "Cursor", "Code - Insiders", "Windsurf"]:
            out.append(r.format(app=app))
    return out
MAC_SET = vscode_settings("/", ["/Users/%/Library/Application Support/{app}/User/settings.json"])
LIN_SET = vscode_settings("/", ["/home/%/.config/{app}/User/settings.json"])
WIN_SET = vscode_settings("\\", ["C:\\Users\\%\\AppData\\Roaming\\{app}\\User\\settings.json"])
def autotasks_policy(paths):
    return ("SELECT 1 WHERE NOT EXISTS (\n  SELECT 1 FROM yara_file\n  WHERE (" + "\n     OR ".join("path LIKE " + q(p) for p in paths) +
            ")\n    AND sigrule = " + q(VSOFF) + "\n    AND count = 0\n)")
RES_VS = 'In VS Code/Cursor user settings set "task.allowAutomaticTasks": "off" (apply-dev-defaults.sh does this). Hosts without the editor pass.'
policy("VS Code/Cursor automatic tasks are off (macOS)", "darwin", "Blocks .vscode/tasks.json runOn: folderOpen autorun (SEAL Intel). Fails if any user's editor settings lack task.allowAutomaticTasks off.", RES_VS, autotasks_policy(MAC_SET))
policy("VS Code/Cursor automatic tasks are off (Linux)", "linux", "Same check for Linux.", RES_VS, autotasks_policy(LIN_SET))
policy("VS Code/Cursor automatic tasks are off (Windows)", "windows", "Same check for Windows.", RES_VS, autotasks_policy(WIN_SET))
policy("npm install scripts are off for every user who has an .npmrc (macOS/Linux)", "darwin,linux",
       "Fails if a user's ~/.npmrc exists without ignore-scripts=true. Users with no ~/.npmrc are not counted (they may not use npm).",
       "Run: npm config set ignore-scripts true  (or apply-dev-defaults.sh --apply).",
       "SELECT 1 WHERE NOT EXISTS (\n  SELECT 1 FROM yara_file\n  WHERE (path LIKE '/Users/%/.npmrc' OR path LIKE '/home/%/.npmrc' OR path LIKE '/root/.npmrc')\n    AND sigrule = " + q(NPMOFF) + "\n    AND count = 0\n)")
policy("Repo scanner git hooks installed (macOS/Linux)", "darwin,linux", "Visibility: the security kit's global git hooks are installed for at least one user.",
       "Run install-hooks.sh as the developer (not root).",
       "SELECT 1 FROM file WHERE path LIKE '/Users/%/.polinrider-guard/hooks/post-checkout' OR path LIKE '/home/%/.polinrider-guard/hooks/post-checkout'")
policy("Repo scanner git hooks installed (Windows)", "windows", "Visibility: the security kit's global git hooks are installed for at least one user.",
       "Run install-hooks.ps1 as the developer.", "SELECT 1 FROM file WHERE path LIKE 'C:\\Users\\%\\.polinrider-guard\\hooks\\post-checkout'")

# ---------------------------------------------------------------- write YAML
os.makedirs(OUT, exist_ok=True)
def block(s, n):
    return "\n".join((" " * n + l) if l else "" for l in s.splitlines())
def yq(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
hdr = "# GENERATED by extras/build-fleet-queries.py from iocs/. Do not edit by hand.\n"
with open(os.path.join(OUT, "security-reports.yml"), "w") as f:
    f.write(hdr + "# Developer-malware detection reports for Fleet free / open-source tier.\n#   fleetctl apply -f extras/generated/security-reports.yml\n")
    for r in reports:
        f.write("---\napiVersion: v1\nkind: report\nspec:\n  name: {}\n  description: {}\n  query: |\n{}\n  platform: {}\n  interval: {}\n  observer_can_run: false\n  automations_enabled: false\n  discard_data: false\n".format(
            yq(r["name"]), yq(r["description"]), block(r["query"], 4), r["platform"], r["interval"]))
with open(os.path.join(OUT, "security-policies.yml"), "w") as f:
    f.write(hdr + "# Visibility-only security policies (free tier: no automations). A passing host returns a row.\n#   fleetctl apply -f extras/generated/security-policies.yml\n")
    for p in policies:
        f.write("---\napiVersion: v1\nkind: policy\nspec:\n  name: {}\n  platform: {}\n  description: {}\n  resolution: {}\n  query: |\n{}\n".format(
            yq(p["name"]), p["platform"], yq(p["description"]), yq(p["resolution"]), block(p["query"], 4)))
print("wrote {} reports, {} policies".format(len(reports), len(policies)))
