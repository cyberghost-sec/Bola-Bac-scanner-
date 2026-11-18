# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning follows [SemVer](https://semver.org/).

## [1.0.0] - 2026-11-18

### Added
- Differential BOLA/IDOR detection: owner baseline vs. other-user attack vs. anonymous request.
- Owner-marker confirmation for high-confidence findings.
- Negative-control calibration using a non-existent ID to recognise generic not-found pages.
- Vertical Broken Access Control check for admin endpoints with a low-privilege token.
- Response fingerprinting with SHA-256 body hashes and size-delta comparison.
- Reports in TXT, JSON and CSV; `--fail-on-vuln` CI exit code (2).
- Safety controls: `--authorized` gate, GET/HEAD by default, `--allow-unsafe` required for state-changing methods, rate limiting via `--delay`.
- Tokens/cookies via environment variables; custom auth header/scheme; proxy, extra headers, `--insecure`, `--dry-run`, `--verbose`.
- Bundled intentionally vulnerable mock lab (`tests/mock-server.py`) with vulnerable and fixed routes.
- Examples, config template, GitHub Actions example in the README.
