# BAC / BOLA Scanner — IDOR & Broken Access Control Detector for Modern Web APIs

![Bash](https://img.shields.io/badge/Bash-4.0%2B-4EAA25?logo=gnubash&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![OWASP API Top 10](https://img.shields.io/badge/OWASP%20API-API1%3A2023%20BOLA-red)
![Status](https://img.shields.io/badge/status-v1.0.0-blue)

> A clean, dependency-light **Bash scanner** that detects **Broken Object Level Authorization (BOLA / IDOR)** and **Broken Access Control (BAC)** in web APIs — using *differential authorization testing*, not blind ID fuzzing.
>
> ⚠️ **For authorized testing only.** Scan only systems you own or have explicit written permission to test. See [Legal & Ethics](#-legal--ethics).

---

## Table of Contents

- [What is BOLA / IDOR?](#what-is-bola--idor)
- [Why this scanner is different](#why-this-scanner-is-different)
- [Features](#features)
- [How it works](#how-it-works)
- [Detection logic](#detection-logic)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start — prove it works in 60 seconds](#quick-start--prove-it-works-in-60-seconds)
- [Testing your own application](#testing-your-own-application)
- [Usage & options](#usage--options)
- [Input file formats](#input-file-formats)
- [Output & reports](#output--reports)
- [How to fix BOLA / BAC](#how-to-fix-bola--bac)
- [CI / GitHub Actions](#ci--github-actions)
- [Project structure](#project-structure)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Legal & Ethics](#-legal--ethics)
- [License](#license)

---

## What is BOLA / IDOR?

**BOLA (Broken Object Level Authorization)**, historically called **IDOR (Insecure Direct Object Reference)**, is **#1 in the OWASP API Security Top 10 (API1:2023)**.

It happens when an API checks *“is the user logged in?”* but never checks *“does this object belong to this user?”*

```http
GET /api/v1/users/1001/profile        ← Alice (id 1001) — OK
Authorization: Bearer <alice-token>

GET /api/v1/users/1001/profile        ← Bob changes nothing but the token…
Authorization: Bearer <bob-token>     ← …and still gets Alice's profile. 💥
```

The ID can be a number, a UUID, a filename, an order number — anything that directly references an object. Changing it should never grant access. When it does, attackers can read, modify or delete other users' data at scale simply by enumerating IDs.

**Broken Access Control (BAC)** is the wider family: a regular user reaching admin functions (vertical), or anyone reaching data with no login at all.

---

## Why this scanner is different

Most “IDOR scanners” just increment IDs and report every `200 OK`. That produces noise, because a `200` on a *public* resource is not a vulnerability.

This scanner proves authorization failure the way a human tester does:

| Step | Request | What it proves |
|------|---------|----------------|
| **Baseline** | User A → A's own resource | The test case is valid (should be `200`) |
| **Attack** | User B → *same* resource | If B succeeds with A's data, it's BOLA |
| **Anonymous** | No token → same resource | If this succeeds, it's Broken Access Control |
| **Control** | User B → non-existent ID | Calibrates generic `200`/SPA pages so they aren't misreported |
| **Privilege** | Low-priv user → admin endpoint | If this succeeds, it's vertical BAC |

Add an **owner marker** — a string only A should ever see (A's email, a planted private note) — and a “possible” becomes a **high-confidence, evidence-backed finding**.

---

## Features

- ✅ **Horizontal BOLA / IDOR** — cross-account object access (user → user)
- ✅ **Vertical BAC** — low-privilege user reaching admin-only endpoints
- ✅ **Unauthenticated access** — no-token access to private objects
- ✅ **Owner-marker confirmation** — eliminates most false positives
- ✅ **Negative control calibration** — generic not-found / SPA-shell pages are recognised
- ✅ **Response fingerprinting** — status code, SHA-256 body hash, and size-delta comparison
- ✅ **Safe by default** — `GET`/`HEAD` only; state-changing methods require `--allow-unsafe`
- ✅ **Authorization gate** — refuses to run without `--authorized`
- ✅ **Secrets stay secret** — tokens come from environment variables, never CLI flags (no shell-history / `ps` leakage)
- ✅ **Rate-limited, sequential** requests with configurable delay and timeout
- ✅ **Burp / proxy support**, custom headers, cookie *or* bearer-token auth, self-signed lab certs
- ✅ **Machine-readable reports** — `report.txt`, `findings.json`, `findings.csv`
- ✅ **CI-ready** — `--fail-on-vuln` exits with code `2` when findings exist
- ✅ **No heavy dependencies** — Bash + `curl` (+ optional `jq` for pretty JSON)
- ✅ **Bundled vulnerable lab** — a tiny mock server to verify the scanner safely, offline

---

## How it works

```text
                ┌────────────────────┐
 endpoints.txt  │  For each endpoint │
   + ids.txt ──►│  and each ID:      │
                └─────────┬──────────┘
                          │
        ┌─────────────────┼──────────────────┐
        ▼                 ▼                  ▼
  Owner (A)         Attacker (B)        Anonymous
  GET /users/1001   GET /users/1001     GET /users/1001
        │                 │                  │
     baseline          compare           compare
     200 + hash  ───►  hash / marker ──► leaked?
                          │
                   ┌──────┴───────┐
                   ▼              ▼
              401/403/404     200 + A's data
                SECURE           VULNERABLE
```

---

## Detection logic

| Verdict | Condition |
|---------|-----------|
| **VULNERABLE — High (BOLA)** | B gets `2xx`, response is byte-identical to A's, **or** contains A's owner marker |
| **VULNERABLE — Critical (Anon BAC)** | Unauthenticated request gets `2xx` with A's data / marker |
| **VULNERABLE — High (Vertical BAC)** | Low-privilege token gets `2xx` on an admin endpoint |
| **POSSIBLE — Medium** | B gets `2xx` with a response size within 5% of A's (add a marker to confirm) |
| **REVIEW — Low** | B gets `2xx` but a materially different body (may be B's own view, or a public resource) |
| **SECURE** | B / anon / low-priv gets `401`, `403` or `404`, or the calibrated generic not-found page |
| **SKIPPED** | Baseline failed — A couldn't read the resource either, so the test case is invalid |

---

## Requirements

- Bash 4+
- `curl`
- `sha256sum` or `shasum` (standard on Linux/macOS)
- Optional: `jq` (pretty-prints the JSON report), Python 3 (only for the bundled mock lab)

## Installation

```bash
git clone https://github.com/cyberghost-sec/Bola-Bac-scanner-.git
cd bac-bola-scanner
chmod +x bola-scanner.sh
./bola-scanner.sh --help
```

No build step. No pip installs. No Docker required.

---

## Quick start — prove it works in 60 seconds

The repo ships an **intentionally vulnerable lab server** so you can see real findings without touching any real application.

**Terminal 1 — start the lab:**

```bash
python3 tests/mock-server.py     # 127.0.0.1:8000 — alice-token owns 1001, bob-token owns 1002
```

**Terminal 2 — scan the vulnerable routes:**

```bash
cat > /tmp/endpoints.txt <<'EOF'
/api/v1/users/{id}/profile
EOF
printf '1001,alice@lab.local\n' > /tmp/ids.txt
printf '/api/v1/admin/users\n'  > /tmp/admin.txt

TOKEN_A='alice-token' TOKEN_B='bob-token' TOKEN_LOW='bob-token' \
  ./bola-scanner.sh --authorized \
  --base-url http://127.0.0.1:8000 \
  --endpoints /tmp/endpoints.txt --ids /tmp/ids.txt \
  --admin-endpoints /tmp/admin.txt
```

**Verified output (v1.0.0):**

```text
[VULN] BOLA    /api/v1/users/1001/profile  (other=200, owner's private marker leaked)
[VULN] BAC/VERTICAL /api/v1/admin/users  (low-privilege user got 200)

Summary  total=2  vulnerable=2  possible=0  secure=0  skipped=0
```

**Now scan the fixed routes** (same app, under `/secure`, with ownership + role checks):

```bash
sed 's|^/|/secure/|' /tmp/endpoints.txt > /tmp/endpoints-secure.txt
sed 's|^/|/secure/|' /tmp/admin.txt     > /tmp/admin-secure.txt

TOKEN_A='alice-token' TOKEN_B='bob-token' TOKEN_LOW='bob-token' \
  ./bola-scanner.sh --authorized \
  --base-url http://127.0.0.1:8000 \
  --endpoints /tmp/endpoints-secure.txt --ids /tmp/ids.txt \
  --admin-endpoints /tmp/admin-secure.txt
```

```text
[+] SECURE  /secure/api/v1/users/1001/profile  (owner=200, other=403)
[+] SECURE  /secure/api/v1/admin/users  (low-privilege denied: 403)

Summary  total=2  vulnerable=0  possible=0  secure=2  skipped=0
```

That contrast — vulnerable vs. fixed, same scanner, same IDs — is exactly the regression test you want in CI after a fix.

---

## Testing your own application

### 1. Create two test accounts in *your* lab / staging environment
Create **User A** and **User B** with the *same role*. Give A some private data. Plant a unique marker in A's data if you can (e.g. a private note: `MARKER-A-7f3d`), or use A's email as the marker.

> Never use real customer accounts, IDs, or data.

### 2. Capture fresh tokens
Log in as A and B in your browser / API client and copy each session token or JWT. Export them — do **not** paste them as command-line flags:

```bash
export TOKEN_A='...'   # Alice
export TOKEN_B='...'   # Bob
export TOKEN_LOW='...' # optional: a low-privilege account for admin checks
# Cookie-based app instead? Use COOKIE_A / COOKIE_B and leave the tokens unset.
```

### 3. List A's object IDs and endpoints

`examples/ids.txt`:

```text
1001,alice@lab.local
1002,alice@lab.local
```

`examples/endpoints.txt`:

```text
/api/v1/users/{id}/profile
/api/v1/users/{id}/orders
/api/v1/documents/{id}
/api/v1/invoices/{id}
```

### 4. Run it

```bash
./bola-scanner.sh --authorized \
  --base-url https://staging.your-lab.local \
  --endpoints examples/endpoints.txt \
  --ids examples/ids.txt \
  --admin-endpoints examples/admin-endpoints.txt \
  --fail-on-vuln
```

Useful extras: `--proxy http://127.0.0.1:8080` to watch traffic in Burp, `--insecure` for self-signed lab certs, `--id-range 1001-1100` instead of an IDs file, `--dry-run` to preview the test plan first.

### 5. Read the reports

Everything lands in `./results/<timestamp>/` — see [Output & reports](#output--reports).

---

## Usage & options

```text
--authorized              REQUIRED. Confirms you own / may test the target.
--base-url URL            Target origin, e.g. https://lab.example.com
--endpoints FILE          Endpoints with a {id} placeholder (required)
--ids FILE                IDs owned by User A:  id[,owner_marker]
--id-range A-B            Alternative to --ids (max 1000 IDs per run)
--admin-endpoints FILE    Admin-only endpoints for the vertical BAC check
--method METHOD           GET (default) / HEAD. Others need --allow-unsafe
--allow-unsafe            Allow POST/PUT/PATCH/DELETE — disposable lab only
--output-dir DIR          Default: ./results/<timestamp>
--delay SECONDS           Between requests (default 0.3)
--timeout SECONDS         Per request (default 10)
--proxy URL               e.g. http://127.0.0.1:8080
--header 'Name: value'    Extra header on every request (repeatable)
--insecure                Skip TLS verification (lab certs)
--fail-on-vuln            Exit 2 if any vulnerability is found
--dry-run                 Print the plan, send nothing
--verbose                 Debug logging
```

**Environment:** `TOKEN_A`, `TOKEN_B`, `TOKEN_LOW`, `COOKIE_A`, `COOKIE_B`, `COOKIE_LOW`, `AUTH_HEADER` (default `Authorization`), `AUTH_SCHEME` (default `Bearer`; set to `""` for a raw token / API key), `DELAY`, `TIMEOUT`, `NO_COLOR`.

**Exit codes:** `0` clean · `1` usage/config error · `2` vulnerabilities found (with `--fail-on-vuln`)

---

## Input file formats

**Endpoints** — one per line, `{id}` is mandatory for BOLA checks, `#` comments allowed:

```text
/api/v1/users/{id}/profile
/api/v1/orders/{id}
```

**IDs** — `id,owner_marker`. The marker is optional but strongly recommended:

```text
1001,alice@lab.local
550e8400-e29b-41d4-a716-446655440000,MARKER-A-7f3d
```

**Admin endpoints** — no placeholder:

```text
/api/v1/admin/users
/api/v1/admin/settings
```

UUIDs, slugs and other non-numeric IDs work fine — use `--ids`, since `--id-range` is numeric only.

---

## Output & reports

```text
results/20261118-192542/
├── report.txt      # human-readable findings + summary
├── findings.json   # machine-readable, for CI / dashboards / ticketing
└── findings.csv    # spreadsheet-friendly
```

Example `findings.json` (from the bundled lab):

```json
{
  "tool": "bola-scanner",
  "version": "1.0.0",
  "target": "http://127.0.0.1:8000",
  "findings": [
    {
      "severity": "high",
      "type": "BOLA/IDOR",
      "method": "GET",
      "url": "http://127.0.0.1:8000/api/v1/users/1001/profile",
      "owner_status": 200,
      "attacker_status": 200,
      "detail": "User B read User A's resource and the response contained A's private marker."
    }
  ],
  "summary": { "total": 2, "vulnerable": 2, "possible": 0, "secure": 0, "skipped": 0 }
}
```

---

## How to fix BOLA / BAC

Finding it is half the job. The fix is always the same principle: **authorize every object access, on the server, on every request.**

### ❌ Vulnerable (checks authentication only)

```js
// Express — anyone logged in can read anyone's profile
app.get('/api/v1/users/:id/profile', requireAuth, async (req, res) => {
  const user = await db.users.findById(req.params.id);
  res.json(user);
});
```

### ✅ Fixed (checks ownership / authorization)

```js
app.get('/api/v1/users/:id/profile', requireAuth, async (req, res) => {
  const user = await db.users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'not found' });
  if (user.id !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ error: 'forbidden' });
  res.json(user);
});
```

```python
# Flask — same idea: scope the query to the caller, don't fetch then forget to check
@app.get("/api/v1/users/<int:user_id>/profile")
@login_required
def profile(user_id):
    user = db.session.query(User).filter_by(id=user_id, owner_id=current_user.id).first()
    if user is None:
        abort(404)   # 404 (not 403) also avoids leaking which IDs exist
    return jsonify(user.to_dict())
```

**Defence checklist:**

1. **Check ownership on every object access** — in a shared middleware / policy layer, not ad-hoc per handler.
2. **Scope queries to the caller** (`WHERE owner_id = :current_user`) instead of fetching by ID alone.
3. **Deny by default** — admin routes need an explicit role check, every time.
4. **Use unguessable IDs (UUIDs)** as defence-in-depth — *never* as a substitute for authorization. An unguessable ID that leaks is still fully accessible without a check.
5. **Return `404` for objects the caller may not see** where feasible, to avoid ID enumeration oracles.
6. **Log and alert** on repeated `403`s and cross-account access attempts.
7. **Add authorization tests** — for every endpoint, a test that User B *cannot* access User A's object. Run this scanner in CI to keep it true.

---

## CI / GitHub Actions

```yaml
name: bola-scan
on: [push, pull_request]
jobs:
  bola:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start the lab app
        run: python3 tests/mock-server.py &
      - name: Run BOLA scan against the FIXED routes
        env:
          TOKEN_A: alice-token
          TOKEN_B: bob-token
          TOKEN_LOW: bob-token
        run: |
          printf '/secure/api/v1/users/{id}/profile\n' > /tmp/ep.txt
          printf '1001,alice@lab.local\n' > /tmp/ids.txt
          ./bola-scanner.sh --authorized --fail-on-vuln \
            --base-url http://127.0.0.1:8000 \
            --endpoints /tmp/ep.txt --ids /tmp/ids.txt
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: bola-results, path: results/ }
```

> In real pipelines, inject tokens from your CI secrets store and point the scanner at a disposable staging environment — never production.

---

## Project structure

```text
bac-bola-scanner/
├── bola-scanner.sh            # the scanner (single file, no build step)
├── README.md
├── LICENSE                    # MIT
├── CHANGELOG.md
├── CONTRIBUTING.md
├── config.example.env         # copy → config.env (git-ignored when filled in)
├── examples/
│   ├── endpoints.txt
│   ├── ids.txt
│   └── admin-endpoints.txt
├── tests/
│   └── mock-server.py         # intentionally vulnerable lab (do not deploy)
└── results/                   # scan output (git-ignored)
```

---

## Limitations

- **Read-oriented by design.** Write-path BOLA (`PUT`/`PATCH`/`DELETE` on someone else's object) is where data destruction happens, but testing it safely needs disposable data — hence the explicit `--allow-unsafe` gate.
- **It tests the endpoints and IDs you give it.** It is not a crawler. Pair it with your API spec (OpenAPI) to generate endpoint/ID lists for full coverage.
- **Auth flows are out of scope.** MFA, token refresh, and login are handled by you supplying valid tokens/cookies.
- **GraphQL / nested objects:** object IDs inside GraphQL variables and nested resources (`/users/{id}/posts/{post_id}`) need a dedicated pass — see the roadmap. The current template supports a single `{id}` placeholder.
- A `POSSIBLE`/`REVIEW` verdict is an invitation to verify manually, not proof — usually of a public resource or a per-user view.

## Roadmap

- [ ] Multiple `{id}` placeholders (nested objects)
- [ ] OpenAPI/Swagger import to auto-generate endpoint lists
- [ ] GraphQL variable fuzzing mode
- [ ] HTML report
- [ ] Wordlist of IDs harvested from User A's own responses

## Contributing

Issues and PRs welcome — especially new detection heuristics, false-positive reductions, and fix examples in more frameworks. Please include a mock-lab test case with any detection change, and never include real targets, tokens, or data in an issue. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## ⚖️ Legal & Ethics

This tool is provided for **defensive security, education, and authorized testing only** — for example, testing your own applications in a lab or staging environment, or a system you have explicit written permission to assess.

- Scanning systems you do not own or have permission to test may be illegal in your jurisdiction and is not an intended use.
- The scanner refuses to run without `--authorized`. That flag is your attestation, not a formality.
- You are solely responsible for how you use this tool. The author accepts no liability for misuse or damage.
- If you find BOLA/BAC in a third-party system during authorized work, follow responsible disclosure.

## License

MIT — see [LICENSE](LICENSE).

---

*Built to make API1:2023 boring: every object, every request, checked against its owner.*
