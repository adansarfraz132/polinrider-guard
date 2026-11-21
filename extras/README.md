# Optional Fleet osquery queries

The rest of this kit runs on a laptop with bash or PowerShell, perl, and
git. You do not need Fleet.

If you already run Fleet (the free or open-source tier is enough),
`build-fleet-queries.py` turns the same `iocs/` lists into visibility
reports and policies. They look for infection artifacts, C2 connections,
malicious extensions and npm packages, YARA hits on build configs,
autorun tasks, and whether the safe defaults from this kit are on.

```bash
python3 extras/build-fleet-queries.py
# writes extras/generated/security-reports.yml
#       extras/generated/security-policies.yml
fleetctl apply -f extras/generated/security-reports.yml
fleetctl apply -f extras/generated/security-policies.yml
```

These use core osquery tables shipped with fleetd. They do not use paid
Fleet features such as automatically running a script when a policy fails.
