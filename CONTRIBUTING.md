# Contributing

Thank you for helping keep this kit accurate. A few rules keep it safe
for other developers to run.

## Tests first

```bash
bash tests/run-tests.sh
```

The suite builds harmless clean and "dirty" sample repos in a temp folder
and checks 31 expectations. Nothing in the tests is real malware: the
payloads are inert strings that only carry published marker text.

If you change detection logic, add or adjust a test. All tests must pass.

## Shellcheck

```bash
shellcheck -x scan-repo.sh host-check.sh safe-clone.sh safe-pull.sh \
  safe-install.sh install-hooks.sh apply-dev-defaults.sh update-iocs.sh \
  tests/run-tests.sh hooks/*
```

## Adding or updating indicators

Every value in `iocs/` must come from a public source named in `THREATS.md`
or in a comment next to the value. Do not invent hashes, IPs, domains, or
package names. Indicators rotate; behaviour checks (hidden config tails,
`folderOpen` tasks, install scripts) matter more than any single IOC.

Refresh the SafeDep snapshot with `./update-iocs.sh`. The CSV is treated
as data only and is never executed.

If you add Fleet-related checks, re-run `python3 extras/build-fleet-queries.py`
and leave generated YAML out of pull requests (`extras/generated/` is
gitignored). Reviewers can regenerate it.

## What not to include

- Real malware samples, packed payloads, or working exploit code.
- Secrets, tokens, private emails, or environment-specific infrastructure.
- A repo-shipped ignore list that a malicious project could use to hide
  itself. `--skip` stays command-line only.

## License

By contributing you agree that your work is licensed under the MIT License
in `LICENSE`.
