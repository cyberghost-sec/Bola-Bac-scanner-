# Contributing

Thanks for helping make APIs safer.

## Ground rules

- **Authorized testing only.** Never add examples, issues, or test data from a system you don't own or weren't permitted to test. No real tokens, IDs, or user data — ever.
- Keep the scanner **single-file and dependency-light** (Bash + curl). New dependencies need a strong justification.
- Keep it **safe by default**: no new state-changing behaviour without an explicit opt-in flag.

## Development

```bash
bash -n bola-scanner.sh                 # syntax
python3 tests/mock-server.py &          # start the lab
# run the vulnerable and /secure scans from the README "Quick start"
```

Any change to detection logic should be demonstrated against the mock lab:
the vulnerable routes must still be flagged, and the `/secure` routes must still pass.

## Pull requests

1. Fork, branch from `main`, keep the change focused.
2. Update `README.md` and `CHANGELOG.md` if behaviour changes.
3. Describe the false-positive / false-negative case your change addresses.
