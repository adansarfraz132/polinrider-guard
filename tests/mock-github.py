#!/usr/bin/env python3
"""Tiny fake of the GitHub REST API and raw.githubusercontent.com for tests/run-live-tests.sh.
Serves canned JSON on 127.0.0.1. Nothing here talks to the real GitHub.
Usage: mock-github.py PORT_FILE [REMAINING]
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT_FILE = sys.argv[1]
REMAINING = [int(sys.argv[2]) if len(sys.argv) > 2 else 5000]
LOG = PORT_FILE + ".log"

# Inert stand-in for an infected config: legit start, many spaces, then a published marker string.
INFECTED = "export default { plugins: {} };" + " " * 300 + "global['!']='0-mock';var _$_1e42=function(){return 'inert'};\n"
CLEAN = "export default { plugins: { tailwindcss: {} } };\n"
REPOS = {
    "owner/repo": {"default_branch": "main", "forks_count": 3, "stargazers_count": 1, "files": {"postcss.config.mjs": CLEAN}},
    "f1/repo": {"default_branch": "main", "files": {"postcss.config.mjs": INFECTED, "package.json": "{}"}},
    "f2/repo": {"default_branch": "main", "files": {"postcss.config.mjs": CLEAN, "src/index.js": "x"}},
    "f3/repo": {"default_branch": "dev", "files": {"tailwind.config.js": INFECTED, ".vscode/tasks.json": "{}"}},
}
FORKS = [{"full_name": n, "html_url": "https://github.com/" + n, "default_branch": REPOS[n]["default_branch"]} for n in ("f1/repo", "f2/repo", "f3/repo")]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", api=True):
        data = body if isinstance(body, bytes) else (json.dumps(body) if not isinstance(body, str) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if api:
            self.send_header("X-RateLimit-Remaining", str(max(REMAINING[0], 0)))
            self.send_header("X-RateLimit-Reset", "2000000000")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        parts = [p for p in u.path.split("/") if p]
        has_auth = "yes" if self.headers.get("Authorization") else "no"
        with open(LOG, "a") as f:
            f.write("%s auth=%s\n" % (u.path, has_auth))
        if parts and parts[0] == "raw":
            repo = "/".join(parts[1:3])
            path = "/".join(parts[4:])
            r = REPOS.get(repo)
            if r and path in r["files"]:
                return self.send(200, r["files"][path], "text/plain", api=False)
            return self.send(404, "not found", "text/plain", api=False)
        # API
        if REMAINING[0] <= 0:
            return self.send(403, {"message": "API rate limit exceeded"})
        REMAINING[0] -= 1
        if len(parts) == 3 and parts[0] == "repos":
            r = REPOS.get(parts[1] + "/" + parts[2])
            if not r:
                return self.send(404, {"message": "Not Found"})
            return self.send(200, {"full_name": parts[1] + "/" + parts[2], "default_branch": r["default_branch"],
                                   "forks_count": r.get("forks_count", 0), "stargazers_count": r.get("stargazers_count", 0), "private": False})
        if len(parts) == 4 and parts[0] == "repos" and parts[3] == "forks":
            page = int(parse_qs(u.query).get("page", ["1"])[0])
            return self.send(200, FORKS if page == 1 and parts[1] + "/" + parts[2] == "owner/repo" else [])
        if len(parts) >= 6 and parts[0] == "repos" and parts[3] == "git" and parts[4] == "trees":
            r = REPOS.get(parts[1] + "/" + parts[2])
            if not r:
                return self.send(404, {"message": "Not Found"})
            return self.send(200, {"truncated": False, "tree": [{"path": p, "type": "blob"} for p in r["files"]]})
        if parts == ["search", "code"]:
            if not self.headers.get("Authorization"):
                return self.send(401, {"message": "Requires authentication"})
            q = parse_qs(u.query).get("q", [""])[0]
            return self.send(200, {"total_count": 7, "items": [{"html_url": "https://github.com/someone/else/blob/main/postcss.config.mjs", "q": q}]})
        return self.send(404, {"message": "Not Found"})


srv = HTTPServer(("127.0.0.1", 0), H)
with open(PORT_FILE, "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
