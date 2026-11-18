#!/usr/bin/env bash
#
# bola-scanner.sh — BOLA / IDOR & Broken Access Control (BAC) scanner
# =================================================================
# Author      : Baldwin (GitHub: @cyberghost-sec)
# Version     : 1.0.0
# Licence     : MIT
# Description :
#   Detects Broken Object Level Authorization (BOLA / IDOR) and
#   Broken Access Control in modern web APIs using the only method
#   that is actually reliable: *differential authorization testing*.
#
#   A blind ID fuzzer cannot tell a public resource from a private
#   one. This scanner can, because it compares identities:
#
#     1. OWNER   — User A requests a resource that belongs to User A.
#                  This is the baseline. It should succeed (200).
#     2. ATTACKER— User B requests *the exact same resource*.
#                  If B also succeeds and sees A's data, that is BOLA.
#     3. ANON    — No credentials request the same resource.
#                  If that succeeds, that is Broken Access Control.
#     4. CONTROL — User B requests a non-existent resource.
#                  Calibrates generic 200 / SPA-shell responses so
#                  they are not misreported as vulnerabilities.
#     5. PRIVILEGE — A low-privilege user requests admin endpoints.
#                  If that succeeds, that is vertical BAC.
#
# Safety by design:
#   * GET / HEAD only by default. Unsafe methods require an
#     explicit --allow-unsafe flag.
#   * Refuses to run without --authorized (see Legal in README).
#   * Sequential, rate-limited requests. No destructive actions.
#   * Tokens are read from environment variables, never from the
#     command line, so they do not leak into shell history / ps.
#
# Usage:
#   TOKEN_A='...' TOKEN_B='...' ./bola-scanner.sh \
#     --authorized \
#     --base-url https://lab.example.com \
#     --endpoints examples/endpoints.txt \
#     --ids examples/ids.txt
#
# =================================================================

set -uo pipefail
IFS=$'\n\t'

readonly VERSION="1.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly NONEXISTENT_ID="999999999999"

# ------------------------------------------------------------------
# Defaults (all overridable via flags / environment)
# ------------------------------------------------------------------
BASE_URL=""
ENDPOINTS_FILE=""
IDS_FILE=""
ADMIN_ENDPOINTS_FILE=""
OUTPUT_DIR=""
METHOD="GET"
DELAY="${DELAY:-0.3}"            # seconds between requests
TIMEOUT="${TIMEOUT:-10}"         # curl --max-time
AUTH_HEADER="${AUTH_HEADER:-Authorization}"
AUTH_SCHEME="${AUTH_SCHEME:-Bearer}"
USER_AGENT="${USER_AGENT:-bola-scanner/${VERSION} (+authorized-security-testing)}"
PROXY="${PROXY:-}"
VERBOSE=0
DRY_RUN=0
INSECURE=0
AUTHORIZED=0
ALLOW_UNSAFE=0
FAIL_ON_VULN=0
ID_RANGE=""
MAX_IDS=1000

TOKEN_A="${TOKEN_A:-}"
TOKEN_B="${TOKEN_B:-}"
TOKEN_LOW="${TOKEN_LOW:-${TOKEN_B:-}}"     # low-privilege token (defaults to B)
COOKIE_A="${COOKIE_A:-}"
COOKIE_B="${COOKIE_B:-}"
COOKIE_LOW="${COOKIE_LOW:-${COOKIE_B:-}}"

EXTRA_HEADERS=()
IDS=()            # parallel arrays: IDS[i] owns MARKERS[i]
MARKERS=()
ENDPOINTS=()
ADMIN_ENDPOINTS=()

# Counters
TOTAL=0; VULNERABLE=0; POSSIBLE=0; SECURE=0; SKIPPED=0; ANON_VULN=0; BAC_VULN=0

# Temp / report state
WORK_DIR=""; REPORT_TXT=""; REPORT_CSV=""; REPORT_JSON=""; JSON_FIRST=1

# Colours (disabled when not a TTY or NO_COLOR is set)
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RED=$'\033[0;31m'; C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[1;33m'
  C_BLUE=$'\033[0;34m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

# ------------------------------------------------------------------
# Logging / helpers
# ------------------------------------------------------------------
log_info()  { printf '%s[*]%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
log_ok()    { printf '%s[+]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
log_warn()  { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
log_vuln()  { printf '%s[VULN]%s %s\n' "$C_RED" "$C_RESET" "$*"; }
log_debug() { [[ "$VERBOSE" -eq 1 ]] && printf '[debug] %s\n' "$*" >&2 || true; }
die()       { printf '%sError:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

cleanup() {
  [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

sha256_of() {
  # Portable sha256 of a file.
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "sha256sum/shasum not found"; fi
}

json_escape() {
  # Minimal JSON string escaping (no jq dependency for reporting).
  local s="$1"
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

csv_escape() {
  local s="$1"
  if [[ "$s" == *[,\"$'\n']* ]]; then printf '"%s"' "${s//\"/\"\"}"; else printf '%s' "$s"; fi
}

size_delta_pct() {
  # size_delta_pct <a> <b> -> integer % difference of b relative to a (0 if a=0)
  local a="$1" b="$2"
  [[ "$a" -eq 0 ]] && { printf '100'; return; }
  local diff=$(( b > a ? b - a : a - b ))
  printf '%s' $(( diff * 100 / a ))
}

check_deps() {
  local missing=()
  command -v curl >/dev/null 2>&1 || missing+=("curl")
  command -v awk  >/dev/null 2>&1 || missing+=("awk")
  [[ "${#missing[@]}" -gt 0 ]] && die "Missing dependencies: ${missing[*]}"
  if ! command -v jq >/dev/null 2>&1; then
    log_warn "jq not found — JSON report will still be written, pretty-printing skipped."
  fi
}

usage() {
  cat <<EOF
${C_BOLD}${SCRIPT_NAME} v${VERSION} — BOLA/IDOR & Broken Access Control scanner${C_RESET}

USAGE
  TOKEN_A='...' TOKEN_B='...' ./${SCRIPT_NAME} --authorized [options]

REQUIRED
  --authorized              Confirm you own / have written permission to test the target.
  --base-url URL            e.g. https://lab.example.com  (no trailing path needed)
  --endpoints FILE          One endpoint per line, using {id} as the placeholder.
  --ids FILE | --id-range A-B
                            IDs owned by User A. File format per line:  id[,owner_marker]
                            owner_marker is a string only A should see (e.g. A's email).
                            It turns a "possible" finding into a high-confidence one.

IDENTITIES (via environment — never pass secrets as flags)
  TOKEN_A                   Owner's token           COOKIE_A   Owner's cookie header value
  TOKEN_B                   Other user's token      COOKIE_B   Other user's cookie header value
  TOKEN_LOW                 Low-privilege token (defaults to TOKEN_B)
  AUTH_HEADER               Default: Authorization  AUTH_SCHEME  Default: Bearer (use '' for raw)

OPTIONAL
  --admin-endpoints FILE    Endpoints only admins should reach (vertical BAC check).
  --method METHOD           GET (default) or HEAD. Others require --allow-unsafe.
  --allow-unsafe            Allow PUT/PATCH/POST/DELETE. Use only in a disposable lab.
  --output-dir DIR          Default: ./results/<timestamp>
  --delay SECONDS           Delay between requests. Default: 0.3
  --timeout SECONDS         Per-request timeout. Default: 10
  --proxy URL               e.g. http://127.0.0.1:8080 (Burp)
  --header 'Name: value'    Extra header to send with every request. Repeatable.
  --insecure                Skip TLS verification (self-signed lab certs).
  --fail-on-vuln            Exit with code 2 if any vulnerability is found (for CI).
  --dry-run                 Print the test plan and exit without sending requests.
  --verbose                 Debug logging.
  -h, --help                This help.
  -v, --version             Print version.

EXAMPLES
  # Classic BOLA test: A owns the IDs, B should NOT be able to read them
  TOKEN_A=\$ALICE_JWT TOKEN_B=\$BOB_JWT ./${SCRIPT_NAME} --authorized \\
    --base-url http://127.0.0.1:8000 \\
    --endpoints examples/endpoints.txt --ids examples/ids.txt

  # Through Burp, against a staging lab, failing CI on findings
  TOKEN_A=... TOKEN_B=... TOKEN_LOW=... ./${SCRIPT_NAME} --authorized \\
    --base-url https://staging.lab.local --proxy http://127.0.0.1:8080 --insecure \\
    --endpoints examples/endpoints.txt --id-range 1001-1100 \\
    --admin-endpoints examples/admin-endpoints.txt --fail-on-vuln

EXIT CODES  0 = no findings / scan ok   1 = usage/config error   2 = vulnerabilities found (--fail-on-vuln)
EOF
}

# ------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --authorized) AUTHORIZED=1 ;;
      --base-url)   [[ $# -ge 2 ]] || die "--base-url needs a value"; BASE_URL="$2"; shift ;;
      --endpoints)  [[ $# -ge 2 ]] || die "--endpoints needs a value"; ENDPOINTS_FILE="$2"; shift ;;
      --ids)        [[ $# -ge 2 ]] || die "--ids needs a value"; IDS_FILE="$2"; shift ;;
      --id-range)   [[ $# -ge 2 ]] || die "--id-range needs a value"; ID_RANGE="$2"; shift ;;
      --admin-endpoints) [[ $# -ge 2 ]] || die "--admin-endpoints needs a value"; ADMIN_ENDPOINTS_FILE="$2"; shift ;;
      --method)     [[ $# -ge 2 ]] || die "--method needs a value"; METHOD="${2^^}"; shift ;;
      --allow-unsafe) ALLOW_UNSAFE=1 ;;
      --output-dir) [[ $# -ge 2 ]] || die "--output-dir needs a value"; OUTPUT_DIR="$2"; shift ;;
      --delay)      [[ $# -ge 2 ]] || die "--delay needs a value"; DELAY="$2"; shift ;;
      --timeout)    [[ $# -ge 2 ]] || die "--timeout needs a value"; TIMEOUT="$2"; shift ;;
      --proxy)      [[ $# -ge 2 ]] || die "--proxy needs a value"; PROXY="$2"; shift ;;
      --header)     [[ $# -ge 2 ]] || die "--header needs a value"; EXTRA_HEADERS+=("$2"); shift ;;
      --insecure)   INSECURE=1 ;;
      --fail-on-vuln) FAIL_ON_VULN=1 ;;
      --dry-run)    DRY_RUN=1 ;;
      --verbose)    VERBOSE=1 ;;
      -h|--help)    usage; exit 0 ;;
      -v|--version) printf '%s\n' "$VERSION"; exit 0 ;;
      *) die "Unknown option: $1 (see --help)" ;;
    esac
    shift
  done
}

validate_config() {
  [[ "$AUTHORIZED" -eq 1 ]] || die "Refusing to run without --authorized. Only scan systems you own or have written permission to test."
  [[ -n "$BASE_URL" ]]       || die "--base-url is required"
  [[ "$BASE_URL" =~ ^https?:// ]] || die "--base-url must start with http:// or https://"
  BASE_URL="${BASE_URL%/}"
  [[ -n "$ENDPOINTS_FILE" ]] || die "--endpoints is required"
  [[ -f "$ENDPOINTS_FILE" ]] || die "Endpoints file not found: $ENDPOINTS_FILE"
  [[ -n "$IDS_FILE" || -n "$ID_RANGE" ]] || die "Provide --ids FILE or --id-range A-B"
  if [[ -n "$IDS_FILE" && ! -f "$IDS_FILE" ]]; then die "IDs file not found: $IDS_FILE"; fi
  if [[ -n "$ADMIN_ENDPOINTS_FILE" && ! -f "$ADMIN_ENDPOINTS_FILE" ]]; then die "Admin endpoints file not found: $ADMIN_ENDPOINTS_FILE"; fi
  if [[ -z "$TOKEN_A" && -z "$COOKIE_A" ]]; then die "TOKEN_A (or COOKIE_A) is not set — the owner identity is required for a baseline"; fi
  if [[ -z "$TOKEN_B" && -z "$COOKIE_B" ]]; then die "TOKEN_B (or COOKIE_B) is not set — BOLA cannot be proven with a single identity"; fi
  case "$METHOD" in
    GET|HEAD) ;;
    POST|PUT|PATCH|DELETE)
      [[ "$ALLOW_UNSAFE" -eq 1 ]] || die "Method $METHOD may change state. Re-run with --allow-unsafe only in a disposable lab."
      log_warn "Unsafe method enabled: $METHOD — use disposable test data only." ;;
    *) die "Unsupported method: $METHOD" ;;
  esac
}

# ------------------------------------------------------------------
# Input loading
# ------------------------------------------------------------------
load_lines_into() {
  # load_lines_into <file> <array-name> — skips blanks and # comments
  local file="$1" array_name="$2" line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"; line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    eval "$array_name+=(\"\$line\")"
  done < "$file"
}

load_ids() {
  if [[ -n "$ID_RANGE" ]]; then
    local start end i
    [[ "$ID_RANGE" =~ ^([0-9]+)-([0-9]+)$ ]] || die "--id-range must look like 1001-1100"
    start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
    [[ "$end" -ge "$start" ]] || die "--id-range end must be >= start"
    local count=$(( end - start + 1 ))
    [[ "$count" -le "$MAX_IDS" ]] || die "Range has $count IDs (limit $MAX_IDS). Narrow it or split the scan."
    for (( i=start; i<=end; i++ )); do IDS+=("$i"); MARKERS+=(""); done
    return
  fi
  local line id marker
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"; [[ -z "${line//[[:space:]]/}" ]] && continue
    id="$(printf '%s' "${line%%,*}" | tr -d '[:space:]')"
    marker=""; [[ "$line" == *,* ]] && marker="$(printf '%s' "${line#*,}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -n "$id" ]] && { IDS+=("$id"); MARKERS+=("$marker"); }
  done < "$IDS_FILE"
  [[ "${#IDS[@]}" -gt 0 ]] || die "No IDs loaded from $IDS_FILE"
}

# ------------------------------------------------------------------
# HTTP layer
# ------------------------------------------------------------------
# Globals set by perform_request: R_CODE R_SIZE R_TIME R_HASH R_BODY
R_CODE=""; R_SIZE=0; R_TIME="0"; R_HASH=""; R_BODY=""
perform_request() {
  local profile="$1" url="$2"
  R_BODY="$WORK_DIR/body.$$.$RANDOM"
  local -a curl_args=(
    -sS --max-time "$TIMEOUT" --output "$R_BODY"
    --write-out '%{http_code} %{size_download} %{time_total}'
    --user-agent "$USER_AGENT" --request "$METHOD"
  )
  [[ "$INSECURE" -eq 1 ]] && curl_args+=(--insecure)
  [[ -n "$PROXY" ]] && curl_args+=(--proxy "$PROXY")
  local h
  for h in "${EXTRA_HEADERS[@]:-}"; do [[ -n "$h" ]] && curl_args+=(--header "$h"); done

  local token="" cookie=""
  case "$profile" in
    owner) token="$TOKEN_A";   cookie="$COOKIE_A" ;;
    other) token="$TOKEN_B";   cookie="$COOKIE_B" ;;
    low)   token="$TOKEN_LOW"; cookie="$COOKIE_LOW" ;;
    anon)  token="";           cookie="" ;;
  esac
  if [[ -n "$token" ]]; then
    if [[ -n "$AUTH_SCHEME" ]]; then curl_args+=(--header "$AUTH_HEADER: $AUTH_SCHEME $token")
    else curl_args+=(--header "$AUTH_HEADER: $token"); fi
  fi
  [[ -n "$cookie" ]] && curl_args+=(--header "Cookie: $cookie")
  [[ "$METHOD" == "HEAD" ]] && curl_args+=(--head)

  local meta=""
  log_debug "$METHOD [$profile] $url"
  if [[ "$DRY_RUN" -eq 1 ]]; then R_CODE="000"; R_SIZE=0; R_TIME="0"; R_HASH="dry-run"; return 0; fi
  meta="$(curl "${curl_args[@]}" "$url" 2>/dev/null)" || meta="000 0 0"
  # shellcheck disable=SC2086
  IFS=' ' read -r R_CODE R_SIZE R_TIME <<< "$meta"
  [[ -f "$R_BODY" ]] || : > "$R_BODY"
  R_HASH="$(sha256_of "$R_BODY")"
  sleep "$DELAY"
}

is_success() { [[ "$1" =~ ^2[0-9][0-9]$ ]]; }
is_denied()  { [[ "$1" =~ ^(401|403|404)$ ]]; }

# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
init_reports() {
  [[ -n "$OUTPUT_DIR" ]] || OUTPUT_DIR="./results/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$OUTPUT_DIR"
  REPORT_TXT="$OUTPUT_DIR/report.txt"; REPORT_CSV="$OUTPUT_DIR/findings.csv"; REPORT_JSON="$OUTPUT_DIR/findings.json"
  : > "$REPORT_TXT"
  printf 'severity,type,method,url,owner_status,attacker_status,detail\n' > "$REPORT_CSV"
  printf '{\n  "tool": "bola-scanner", "version": "%s", "target": "%s", "started_at": "%s",\n  "findings": [\n' \
    "$VERSION" "$(json_escape "$BASE_URL")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$REPORT_JSON"
  {
    printf 'BOLA/BAC Scan Report — %s\nTarget: %s\nStarted: %s\n\n' "$VERSION" "$BASE_URL" "$(date)"
  } >> "$REPORT_TXT"
}

record_finding() {
  # record_finding <severity> <type> <url> <owner_code> <attacker_code> <detail>
  local severity="$1" type="$2" url="$3" oc="$4" ac="$5" detail="$6"
  printf '[%s] %s %s %s (owner=%s attacker=%s) — %s\n' "$severity" "$type" "$METHOD" "$url" "$oc" "$ac" "$detail" >> "$REPORT_TXT"
  printf '%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_escape "$severity")" "$(csv_escape "$type")" "$METHOD" "$(csv_escape "$url")" "$oc" "$ac" "$(csv_escape "$detail")" >> "$REPORT_CSV"
  [[ "$JSON_FIRST" -eq 1 ]] && JSON_FIRST=0 || printf ',\n' >> "$REPORT_JSON"
  printf '    {"severity":"%s","type":"%s","method":"%s","url":"%s","owner_status":%s,"attacker_status":%s,"detail":"%s"}' \
    "$(json_escape "$severity")" "$(json_escape "$type")" "$METHOD" "$(json_escape "$url")" \
    "${oc:-0}" "${ac:-0}" "$(json_escape "$detail")" >> "$REPORT_JSON"
}

finish_reports() {
  printf '\n  ],\n  "summary": {"total": %s, "vulnerable": %s, "possible": %s, "secure": %s, "skipped": %s}\n}\n' \
    "$TOTAL" "$VULNERABLE" "$POSSIBLE" "$SECURE" "$SKIPPED" >> "$REPORT_JSON"
  if command -v jq >/dev/null 2>&1; then
    local pretty; pretty="$(mktemp)"; jq . "$REPORT_JSON" > "$pretty" 2>/dev/null && mv "$pretty" "$REPORT_JSON" || rm -f "$pretty"
  fi
  {
    printf '\nSummary: total=%s vulnerable=%s possible=%s secure=%s skipped=%s\n' "$TOTAL" "$VULNERABLE" "$POSSIBLE" "$SECURE" "$SKIPPED"
  } >> "$REPORT_TXT"
}

# ------------------------------------------------------------------
# Core checks
# ------------------------------------------------------------------
check_bola_for() {
  # check_bola_for <endpoint-template> <id> <owner_marker>
  local template="$1" id="$2" marker="$3"
  local path="${template//\{id\}/$id}"
  local url="${BASE_URL}${path}"
  TOTAL=$((TOTAL + 1))

  # 1) Baseline — owner reads their own resource
  perform_request owner "$url"; local a_code="$R_CODE" a_hash="$R_HASH" a_size="$R_SIZE" a_body="$R_BODY"
  if ! is_success "$a_code"; then
    log_warn "SKIP baseline failed (owner got $a_code) for $path — check the ID really belongs to User A"
    SKIPPED=$((SKIPPED + 1)); return
  fi

  # 2) Control — other user reads a non-existent resource (generic-page calibration)
  local control_path="${template//\{id\}/$NONEXISTENT_ID}"
  perform_request other "${BASE_URL}${control_path}"; local c_hash="$R_HASH"

  # 3) Attack — other user reads owner's resource
  perform_request other "$url"; local b_code="$R_CODE" b_hash="$R_HASH" b_size="$R_SIZE" b_body="$R_BODY"

  if is_denied "$b_code"; then
    log_ok "SECURE  $path  (owner=$a_code, other=$b_code)"; SECURE=$((SECURE + 1))
  elif is_success "$b_code"; then
    if [[ "$b_hash" == "$c_hash" && "$b_hash" != "$a_hash" ]]; then
      log_ok "SECURE  $path  (other got the generic not-found page)"; SECURE=$((SECURE + 1))
    elif [[ -n "$marker" ]] && grep -Fq -- "$marker" "$b_body"; then
      log_vuln "BOLA    $path  (other=$b_code, owner's private marker leaked)"
      VULNERABLE=$((VULNERABLE + 1))
      record_finding "high" "BOLA/IDOR" "$url" "$a_code" "$b_code" "User B read User A's resource and the response contained A's private marker."
    elif [[ "$b_hash" == "$a_hash" ]]; then
      log_vuln "BOLA    $path  (other=$b_code, response identical to owner's)"
      VULNERABLE=$((VULNERABLE + 1))
      record_finding "high" "BOLA/IDOR" "$url" "$a_code" "$b_code" "User B received a byte-identical response to the owner for the same object ID."
    elif [[ "$(size_delta_pct "$a_size" "$b_size")" -le 5 ]]; then
      log_vuln "POSSIBLE BOLA  $path  (other=$b_code, response size within 5% of owner's)"
      POSSIBLE=$((POSSIBLE + 1))
      record_finding "medium" "POSSIBLE_BOLA" "$url" "$a_code" "$b_code" "User B got 2xx with a near-identical size. Add an owner_marker to ids file to confirm."
    else
      log_warn "REVIEW  $path  (other=$b_code but body differs — may be B's own view or a public resource)"
      POSSIBLE=$((POSSIBLE + 1))
      record_finding "low" "REVIEW" "$url" "$a_code" "$b_code" "User B got 2xx with a different body. Manual review required."
    fi
  else
    log_ok "SECURE  $path  (other=$b_code)"; SECURE=$((SECURE + 1))
  fi

  # 4) Anonymous — no credentials at all
  perform_request anon "$url"; local n_code="$R_CODE" n_hash="$R_HASH" n_body="$R_BODY"
  if is_success "$n_code"; then
    if [[ -n "$marker" ]] && grep -Fq -- "$marker" "$n_body"; then
      log_vuln "BAC/ANON $path  (unauthenticated, owner's marker leaked)"
      ANON_VULN=$((ANON_VULN + 1)); VULNERABLE=$((VULNERABLE + 1))
      record_finding "critical" "BROKEN_ACCESS_CONTROL_ANON" "$url" "$a_code" "$n_code" "Unauthenticated request returned the owner's private data."
    elif [[ "$n_hash" == "$a_hash" ]]; then
      log_vuln "BAC/ANON $path  (unauthenticated, identical to owner's response)"
      ANON_VULN=$((ANON_VULN + 1)); VULNERABLE=$((VULNERABLE + 1))
      record_finding "critical" "BROKEN_ACCESS_CONTROL_ANON" "$url" "$a_code" "$n_code" "Unauthenticated request returned the owner's resource."
    fi
  fi
  rm -f "$a_body" "$b_body" "$n_body" 2>/dev/null || true
}

check_admin_endpoint() {
  # Vertical BAC: a low-privilege identity must not reach admin routes.
  local path="$1"
  local url="${BASE_URL}${path}"
  TOTAL=$((TOTAL + 1))
  perform_request low "$url"; local l_code="$R_CODE" l_hash="$R_HASH"
  if is_success "$l_code"; then
    perform_request anon "$url"; local n_code="$R_CODE"
    log_vuln "BAC/VERTICAL $path  (low-privilege user got $l_code)"
    BAC_VULN=$((BAC_VULN + 1)); VULNERABLE=$((VULNERABLE + 1))
    record_finding "high" "BROKEN_ACCESS_CONTROL_VERTICAL" "$url" "$l_code" "$n_code" "Low-privilege user accessed an admin-only endpoint (hash: $l_hash)."
  elif is_denied "$l_code"; then
    log_ok "SECURE  $path  (low-privilege denied: $l_code)"; SECURE=$((SECURE + 1))
  else
    log_warn "REVIEW  $path  (low-privilege got $l_code)"; POSSIBLE=$((POSSIBLE + 1))
  fi
}

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
main() {
  parse_args "$@"
  check_deps
  validate_config
  load_lines_into "$ENDPOINTS_FILE" ENDPOINTS
  [[ -n "$ADMIN_ENDPOINTS_FILE" ]] && load_lines_into "$ADMIN_ENDPOINTS_FILE" ADMIN_ENDPOINTS
  load_ids
  [[ "${#ENDPOINTS[@]}" -gt 0 ]] || die "No endpoints loaded from $ENDPOINTS_FILE"

  WORK_DIR="$(mktemp -d)"
  init_reports

  printf '%sbola-scanner v%s%s\n' "$C_BOLD" "$VERSION" "$C_RESET"
  log_info "Target:     $BASE_URL"
  log_info "Endpoints:  ${#ENDPOINTS[@]} template(s), ${#IDS[@]} ID(s) = $((${#ENDPOINTS[@]} * ${#IDS[@]})) BOLA case(s)"
  log_info "Method:     $METHOD   Delay: ${DELAY}s   Output: $OUTPUT_DIR"
  [[ "$DRY_RUN" -eq 1 ]] && log_warn "DRY RUN — no requests will be sent"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    local ep id
    for ep in "${ENDPOINTS[@]}"; do for id in "${IDS[@]}"; do printf 'PLAN  %s %s%s\n' "$METHOD" "$BASE_URL" "${ep//\{id\}/$id}"; done; done
    for ep in "${ADMIN_ENDPOINTS[@]:-}"; do [[ -n "$ep" ]] && printf 'PLAN  %s [low-priv] %s%s\n' "$METHOD" "$BASE_URL" "$ep"; done
    return 0
  fi

  local ep i
  for ep in "${ENDPOINTS[@]}"; do
    if [[ "$ep" != *"{id}"* ]]; then log_warn "Skipping endpoint without {id} placeholder: $ep"; continue; fi
    for i in "${!IDS[@]}"; do check_bola_for "$ep" "${IDS[$i]}" "${MARKERS[$i]}"; done
  done

  for ep in "${ADMIN_ENDPOINTS[@]:-}"; do [[ -n "$ep" ]] && check_admin_endpoint "$ep"; done

  finish_reports
  printf '\n%sSummary%s  total=%s  %svulnerable=%s%s  possible=%s  secure=%s  skipped=%s\n' \
    "$C_BOLD" "$C_RESET" "$TOTAL" "$C_RED" "$VULNERABLE" "$C_RESET" "$POSSIBLE" "$SECURE" "$SKIPPED"
  log_info "Reports: $REPORT_TXT | $REPORT_JSON | $REPORT_CSV"

  if [[ "$FAIL_ON_VULN" -eq 1 && "$VULNERABLE" -gt 0 ]]; then exit 2; fi
}

main "$@"
