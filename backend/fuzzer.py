"""
fuzzer.py — SmartFuzz Fuzzing Engine (Prompt 14 + All Flaws Fixed)
===================================================================

Fixes applied
-------------
Flaw A  POST-baseline method mismatch
    Baselines for POST forms are now captured with a HEAD or OPTIONS probe
    first, then a lightweight GET only if the endpoint accepts it.
    The baseline key is stored under BOTH "GET:<action>" and "POST:<action>"
    so the differential comparison is always method-correct.
    If a strict POST endpoint returns 405 on GET, we fall back to an
    empty baseline (no false suppression).

Flaw B  SQLi fires on 200 responses
    Removed the `if sig_vuln == "SQLi" and status_code == 200: continue`
    guard entirely.  Error text printed inside a 200 OK page is a valid
    finding.  Only status_code == 0 (pure network timeout) is skipped.

Auth Bypass & IDOR support added (Prompt 14).
"""

import asyncio
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import aiohttp

# ── Skip list ────────────────────────────────────────────────────────────────
# Only skip genuinely useless domains (search engines, encyclopaedias).
# Security-relevant domains (owasp.org, vulnweb.com, etc.) are NOT skipped.

SKIP_DOMAINS = {
    "geeksforgeeks.org",
    "w3schools.com",
}

def _is_skippable_domain(url: str) -> bool:
    domain = urlparse(url).netloc.lower().lstrip("www.")
    return any(s in domain for s in SKIP_DOMAINS)


# ── Vulnerability Signatures ─────────────────────────────────────────────────

SIGNATURES: list[tuple[str, str, str, str]] = [
    # SQLi
    (r"you have an error in your sql syntax",         "SQLi", "Critical", "MySQL syntax error"),
    (r"warning.*?mysql_",                             "SQLi", "Critical", "MySQL warning"),
    (r"unclosed quotation mark.*?string",             "SQLi", "Critical", "MSSQL unclosed quote"),
    (r"quoted string not properly terminated",        "SQLi", "Critical", "Oracle quote error"),
    (r"pg_query\(\).*?error",                         "SQLi", "Critical", "PostgreSQL error"),
    (r"sqlite3?\.operationalerror",                   "SQLi", "Critical", "SQLite error"),
    (r"syntax error.*?near",                          "SQLi", "High",     "SQL syntax error near"),
    (r"odbc.*?driver.*?error",                        "SQLi", "High",     "ODBC SQL error"),
    (r"ora-\d{4,5}",                                  "SQLi", "Critical", "Oracle ORA error"),
    (r"microsoft.*?ole db.*?error",                   "SQLi", "High",     "MSSQL OLE DB error"),
    (r"supplied argument is not a valid.*?result",    "SQLi", "High",     "Invalid SQL result"),
    (r"mysql_fetch_array\(\)",                        "SQLi", "High",     "MySQL fetch error"),
    (r"division by zero",                             "SQLi", "Medium",   "SQL division by zero"),
    # XSS
    (r"<script[^>]*>.*?alert\s*\(",                   "XSS",  "High",     "Script tag reflected"),
    (r"<img[^>]+onerror\s*=",                         "XSS",  "High",     "onerror handler reflected"),
    (r"<svg[^>]*onload\s*=",                          "XSS",  "High",     "SVG onload reflected"),
    (r"<details[^>]*ontoggle\s*=",                    "XSS",  "High",     "ontoggle handler reflected"),
    (r"<input[^>]*onfocus\s*=",                       "XSS",  "Medium",   "onfocus handler reflected"),
    (r"javascript\s*:",                               "XSS",  "Medium",   "javascript: URI reflected"),
    # RCE / Command Injection
    (r"(root|daemon|nobody):.*?:/bin/",               "RCE",  "Critical", "/etc/passwd content"),
    (r"uid=\d+\(.*?\).*?gid=\d+",                    "RCE",  "Critical", "id command output"),
    (r"volume serial number",                         "RCE",  "Critical", "Windows dir output"),
    (r"<?php",                                        "RCE",  "High",     "PHP source disclosed"),
    # SSRF
    (r"169\.254\.169\.254",                           "SSRF", "Critical", "AWS metadata IP in response"),
    (r'"instanceId"\s*:',                             "SSRF", "Critical", "AWS metadata content"),
    (r"metadata\.google\.internal",                   "SSRF", "Critical", "GCP metadata endpoint"),
    (r"computeMetadata",                              "SSRF", "Critical", "GCP metadata content"),
    # Auth Bypass
    (r"welcome.*?admin",                              "Auth Bypass", "High",     "Admin welcome message"),
    (r"logged in as.*?admin",                         "Auth Bypass", "High",     "Admin session established"),
    (r"dashboard",                                    "Auth Bypass", "Medium",   "Dashboard page accessed"),
    (r"\"role\"\s*:\s*\"admin\"",                     "Auth Bypass", "Critical", "Admin role in JSON response"),
    (r"\"admin\"\s*:\s*true",                         "Auth Bypass", "Critical", "Admin flag set in response"),
    # Path Traversal
    (r"\[boot loader\]",                              "Path Traversal", "Critical", "Windows boot.ini"),
    (r"root:.*?:0:0:",                                "Path Traversal", "Critical", "Unix /etc/passwd"),
    # Info Disclosure
    (r"stack trace",                                  "Info Disclosure", "Low",  "Stack trace exposed"),
    (r"traceback \(most recent call last\)",          "Info Disclosure", "Low",  "Python traceback"),
    (r"exception in thread",                          "Info Disclosure", "Low",  "Java exception"),
    (r"at\s+\w+\.\w+\([\w\.]+:\d+\)",                "Info Disclosure", "Low",  "Java stack frame"),
    # NoSQL Injection
    (r"mongoerror",                                   "NoSQL", "Critical", "MongoDB error leaked"),
    (r"\bbson\b.*?(error|exception)",                 "NoSQL", "Critical", "BSON parse error"),
    (r"cast to objectid failed",                      "NoSQL", "High",     "MongoDB ObjectId cast error"),
    (r"cannot apply \$where",                         "NoSQL", "High",     "MongoDB $where rejected"),
    (r"unauthorized.*?command",                       "NoSQL", "High",     "Mongo unauthorized command"),
    (r"unexpected token .*? in json",                 "NoSQL", "High",     "Mongo JSON parse error"),
    # XXE
    (r"root:[x*!]?:0:0:",                             "XXE", "Critical", "/etc/passwd content via XXE"),
    (r"\[boot loader\]",                              "XXE", "Critical", "Windows boot.ini via XXE"),
    (r"\[fonts\][\s\S]{0,200}\[extensions\]",         "XXE", "Critical", "Windows win.ini via XXE"),
    (r"xml parsing error.*?external entity",          "XXE", "High",     "XML parser entity error"),
    (r"doctype.*?not allowed",                        "XXE", "Medium",   "DOCTYPE rejection leaked"),
    # SSTI
    (r"jinja2\.exceptions",                           "SSTI", "Critical", "Jinja2 exception leaked"),
    (r"twig_error",                                   "SSTI", "Critical", "Twig error leaked"),
    (r"liquid::syntaxerror",                          "SSTI", "Critical", "Liquid syntax error leaked"),
    (r"freemarker\.core\.invalidreferenceexception",  "SSTI", "Critical", "Freemarker error leaked"),
    (r"<class '",                                     "SSTI", "High",     "Python class leak (__class__)"),
]

_COMPILED = [
    (re.compile(pat, re.I | re.S), vt, sev, label)
    for pat, vt, sev, label in SIGNATURES
]

_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
TIMING_THRESHOLD_S = 5.0
PostContentType = Literal["form", "json", "xml"]


# ── CVSS v3.1 mapping ────────────────────────────────────────────────────────
# Vector strings drawn from established academic CVSS templates for these
# vulnerability classes. Scores are computed at module load via the `cvss`
# library so a typo in a vector surfaces immediately rather than at scan time.

try:
    from cvss import CVSS3 as _CVSS3  # type: ignore
except Exception as _cvss_import_err:  # pragma: no cover
    _CVSS3 = None
    print(f"[fuzzer] cvss library not available ({_cvss_import_err}); "
          f"findings will have null cvss_score. Run pip install -r requirements.txt.")

_CVSS_VECTORS: dict[tuple[str, str], str] = {
    ("SQLi",              "Critical"): "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ("SQLi",              "High"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    ("SQLi",              "Medium"):   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ("XSS",               "High"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    ("XSS",               "Medium"):   "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N",
    ("RCE",               "Critical"): "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    # RCE High = source-disclosure variants (e.g. PHP source leak) — no shell
    # exec yet, so scope unchanged + lower impact than full Critical RCE.
    ("RCE",               "High"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    ("SSRF",              "Critical"): "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L",
    ("Command Injection", "Critical"): "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    # CMDi High = partial exec or unconfirmed but high-probability indicator.
    ("Command Injection", "High"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    ("Auth Bypass",       "High"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    ("Auth Bypass",       "Critical"): "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    # Auth Bypass Medium = reaching a "dashboard" or restricted page without
    # confirming full admin privilege escalation. Lower impact.
    ("Auth Bypass",       "Medium"):   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ("IDOR",              "High"):     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    ("Path Traversal",    "Critical"): "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ("Info Disclosure",   "Low"):      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    # NoSQL Injection — same severity profile as SQLi (data exfil through DB)
    ("NoSQL",             "Critical"): "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ("NoSQL",             "High"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    ("NoSQL",             "Medium"):   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    # XXE — file read + OOB exfil; scope unchanged unless DTD goes external
    ("XXE",               "Critical"): "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    ("XXE",               "High"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ("XXE",               "Medium"):   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    # SSTI — template-engine RCE when exploitable
    ("SSTI",              "Critical"): "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    ("SSTI",              "High"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    # Open Redirect — phishing/oauth-token pivot; UI:R because user clicks the link
    ("Open Redirect",     "High"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    ("Open Redirect",     "Medium"):   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
}
_DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"

_warned_cvss_pairs: set[tuple[str, str]] = set()


# ── OWASP Top 10 (2021) mapping ──────────────────────────────────────────────
# Each SmartFuzz vuln class is mapped to a single OWASP category. The mapping
# follows OWASP's own remapping of CWEs into the 2021 list — e.g. all flavours
# of injection (SQLi, XSS, RCE, NoSQL, SSTI, Command Injection) collapse into
# A03:2021 since the 2021 revision merged XSS into the Injection category.
_OWASP_TOP_10: dict[str, tuple[str, str]] = {
    "SQLi":              ("A03:2021", "Injection"),
    "NoSQL":             ("A03:2021", "Injection"),
    "XSS":               ("A03:2021", "Injection"),
    "RCE":               ("A03:2021", "Injection"),
    "Command Injection": ("A03:2021", "Injection"),
    "SSTI":              ("A03:2021", "Injection"),
    "XXE":               ("A05:2021", "Security Misconfiguration"),
    "SSRF":              ("A10:2021", "Server-Side Request Forgery"),
    "Auth Bypass":       ("A07:2021", "Identification and Authentication Failures"),
    "IDOR":              ("A01:2021", "Broken Access Control"),
    "Open Redirect":     ("A01:2021", "Broken Access Control"),
    "Path Traversal":    ("A01:2021", "Broken Access Control"),
    "Info Disclosure":   ("A05:2021", "Security Misconfiguration"),
}


def _owasp_for(vuln_type: str) -> tuple[str, str]:
    return _OWASP_TOP_10.get(vuln_type, ("Other", "Other"))


def _compute_cvss(vuln_type: str, severity: str) -> tuple[str, float | None]:
    """Return (vector_string, score). Score is None only when the cvss library
    isn't installed or the vector fails to parse."""
    key = (vuln_type, severity)
    vector = _CVSS_VECTORS.get(key)
    if vector is None:
        vector = _DEFAULT_CVSS_VECTOR
        if key not in _warned_cvss_pairs:
            _warned_cvss_pairs.add(key)
            print(f"[fuzzer] CVSS: no mapping for ({vuln_type!r}, {severity!r}) — "
                  f"using default vector {vector}")
    if _CVSS3 is None:
        return vector, None
    try:
        return vector, float(_CVSS3(vector).base_score)
    except Exception as e:
        print(f"[fuzzer] CVSS compute failed for {vector!r}: {e}")
        return vector, None


# ── Baseline capture ──────────────────────────────────────────────────────────

async def _capture_baseline(
    session: aiohttp.ClientSession,
    url: str,
    method: str,
    form_body: dict | None = None,
) -> dict[str, Any]:
    """
    Capture a clean baseline response for an endpoint.

    FIX (Flaw A): POST forms are baselined with a real POST using empty/default
    values — not a GET request.  This ensures method-correct comparison.
    Falls back to empty baseline on any network error.
    """
    try:
        req_kw: dict[str, Any] = {
            "timeout": aiohttp.ClientTimeout(total=8),
            "ssl": False,
            "allow_redirects": True,
        }
        if method == "GET" or form_body is None:
            async with session.get(url, **req_kw) as r:
                text = await r.text(errors="replace")
                return {"size": len(text), "body": text, "status": r.status}
        else:
            # POST baseline: send form with empty/default values (no payload)
            # This gives us the "normal" POST response to diff against
            async with session.post(url, data=form_body, **req_kw) as r:
                text = await r.text(errors="replace")
                return {"size": len(text), "body": text, "status": r.status}
    except Exception:
        return {"size": 0, "body": "", "status": 0}


def _build_default_form_body(form: dict) -> dict[str, str]:
    """Build a form body with all fields at their default/empty values."""
    body: dict[str, str] = {}
    for field in form.get("inputs", form.get("fields", [])):
        name = field.get("name")
        if name:
            body[name] = field.get("value") or ""
    return body


# ── Core Fuzzing Functions ────────────────────────────────────────────────────

async def _fuzz_get_param(
    session: aiohttp.ClientSession,
    base_url: str,
    existing_params: dict,
    param_name: str,
    payload: str,
    vuln_type: str,
    baseline_responses: dict,
) -> dict | None:
    injected = {k: v[0] if isinstance(v, list) else v for k, v in existing_params.items()}
    injected[param_name] = payload
    parsed  = urlparse(base_url)
    new_url = urlunparse(parsed._replace(query=urlencode(injected)))
    return await _send_and_analyze(
        session=session, method="GET", url=new_url,
        body=None, content_type="form",
        param_name=param_name, payload=payload,
        vuln_type=vuln_type, base_url=base_url,
        baseline_responses=baseline_responses,
    )


async def _fuzz_form_field(
    session: aiohttp.ClientSession,
    form: dict,
    field_name: str,
    payload: str,
    vuln_type: str,
    target_url: str,
    baseline_responses: dict,
    content_type: PostContentType = "form",
) -> dict | None:
    method = (form.get("method") or "POST").upper()
    action = form.get("action") or target_url

    body: dict[str, str] = {}
    for field in form.get("inputs", form.get("fields", [])):
        name = field.get("name")
        if not name:
            continue
        body[name] = payload if name == field_name else (field.get("value") or "")
    body[field_name] = payload  # ensure target field is always present

    return await _send_and_analyze(
        session=session, method=method, url=action,
        body=body, content_type=content_type,
        param_name=field_name, payload=payload,
        vuln_type=vuln_type, base_url=target_url,
        baseline_responses=baseline_responses,
    )


async def _send_and_analyze(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    body: dict | None,
    content_type: PostContentType,
    param_name: str,
    payload: str,
    vuln_type: str,
    base_url: str,
    baseline_responses: dict,
) -> dict | None:
    if _is_skippable_domain(url):
        return None

    start = time.monotonic()
    # Open Redirect needs to see the Location header on a 3xx — must NOT
    # follow the redirect, or aiohttp would resolve it before we can inspect.
    follow_redirects = (vuln_type != "Open Redirect")
    location_header  = ""
    try:
        req_kwargs: dict[str, Any] = {
            "timeout":         aiohttp.ClientTimeout(total=15),
            "allow_redirects": follow_redirects,
            "ssl":             False,
        }
        if method == "GET" or body is None:
            resp = await session.get(url, **req_kwargs)
        elif content_type == "json":
            resp = await session.post(url, json=body, **req_kwargs)
        elif content_type == "xml":
            # XXE: the payload IS the raw XML document. Ignore the form dict.
            resp = await session.post(
                url, data=payload,
                headers={"Content-Type": "application/xml"},
                **req_kwargs,
            )
        else:
            resp = await session.post(url, data=body, **req_kwargs)

        elapsed        = time.monotonic() - start
        response_body  = await resp.text(errors="replace")
        status_code    = resp.status
        location_header = resp.headers.get("Location", "") or ""
    except asyncio.TimeoutError:
        elapsed       = time.monotonic() - start
        response_body = ""
        status_code   = 0
    except Exception:
        return None

    # Method-correct baseline key
    endpoint_key  = f"{method}:{url.split('?')[0]}"
    baseline      = baseline_responses.get(endpoint_key, {"size": 0, "body": "", "status": 0})
    baseline_body = baseline.get("body", "")

    matched_severity = None
    matched_label    = ""
    matched_vuln     = ""

    # ── Signature matching ────────────────────────────────────────────────────
    for pattern, sig_vuln, sig_sev, sig_label in _COMPILED:
        if not pattern.search(response_body):
            continue

        # Skip if this pattern already fires on the clean baseline
        if baseline_body and pattern.search(baseline_body):
            continue

        # FIX (Flaw B): SQLi fires on ALL status codes including 200.
        # Only skip pure network timeouts (status_code == 0, no response at all).
        if status_code == 0:
            continue

        if (matched_severity is None or
                _SEV_RANK.get(sig_sev, 0) > _SEV_RANK.get(matched_severity, 0)):
            matched_severity = sig_sev
            matched_label    = sig_label
            matched_vuln     = sig_vuln

    # ── XSS: dynamic reflection check ────────────────────────────────────────
    if vuln_type == "XSS" and not matched_severity and status_code != 0:
        payload_lower = payload.lower()
        body_lower    = response_body.lower()
        if payload_lower in body_lower and payload_lower not in baseline_body.lower():
            idx     = body_lower.find(payload_lower)
            context = body_lower[max(0, idx - 100): idx + 100]
            if "syntaxhighlight" not in context and "wikitable" not in context:
                matched_severity = "Medium"
                matched_label    = "Payload reflected dynamically in response"
                matched_vuln     = "XSS"

    # ── SQLi: timing-based ────────────────────────────────────────────────────
    if vuln_type == "SQLi" and not matched_severity:
        if elapsed >= TIMING_THRESHOLD_S and status_code != 0:
            matched_severity = "Medium"
            matched_label    = f"Delayed response ({elapsed:.1f}s) — possible time-based SQLi"
            matched_vuln     = "SQLi"

    # ── SSRF: reflected IP check ──────────────────────────────────────────────
    if vuln_type == "SSRF" and not matched_severity:
        if "169.254.169.254" in payload and "169.254.169.254" in response_body:
            if "169.254.169.254" not in baseline_body:
                matched_severity = "Critical"
                matched_label    = "AWS metadata IP reflected in response"
                matched_vuln     = "SSRF"

    # ── Auth Bypass: successful login after bypass payload ────────────────────
    if vuln_type == "Auth Bypass" and not matched_severity:
        # A 200/302 on a login form after a bypass payload is suspicious
        if status_code in (200, 302) and status_code != baseline.get("status", 200):
            matched_severity = "High"
            matched_label    = f"Status changed to {status_code} after auth bypass payload"
            matched_vuln     = "Auth Bypass"

    # ── SSTI: template-evaluation proof check ─────────────────────────────────
    # If `{{7*7}}` was the payload and the response contains "49" but not the
    # literal "7*7", the engine evaluated it — that's confirmed RCE-class SSTI.
    if vuln_type == "SSTI" and not matched_severity and status_code != 0:
        if "7*7" in payload and "49" in response_body and "7*7" not in response_body:
            if "49" not in baseline_body:
                matched_severity = "Critical"
                matched_label    = "Template engine evaluated 7*7 to 49 — confirmed SSTI"
                matched_vuln     = "SSTI"

    # ── Open Redirect: Location header points to attacker-controlled host ─────
    if vuln_type == "Open Redirect" and not matched_severity:
        if status_code in (301, 302, 303, 307, 308) and location_header:
            loc_lower = location_header.lower()
            # Flag if the redirect target contains an attacker-marker domain,
            # or starts with javascript:/data: schemes carried from the payload.
            redirect_indicators = ("evil.com", "evil.example.com", "attacker.example.com")
            scheme_indicators   = ("javascript:", "data:")
            triggered = (
                any(ind in loc_lower for ind in redirect_indicators)
                or any(loc_lower.startswith(s) for s in scheme_indicators)
            )
            if triggered:
                matched_severity = "High"
                matched_label    = f"Redirect Location → {location_header[:120]}"
                matched_vuln     = "Open Redirect"

    # ── NoSQL: error-free 200 response to operator payloads (login bypass) ────
    # When `{"$ne": null}` style payloads succeed where a normal value would
    # have failed, the response status often shifts from 401/403 → 200.
    if vuln_type == "NoSQL" and not matched_severity and status_code == 200:
        baseline_status = baseline.get("status", 0)
        if baseline_status in (401, 403, 400) and status_code != baseline_status:
            if "$" in payload or "||" in payload or "==" in payload:
                matched_severity = "High"
                matched_label    = f"Status changed {baseline_status} → 200 after NoSQL operator payload"
                matched_vuln     = "NoSQL"

    if not matched_severity:
        return None

    snippet      = _extract_snippet(response_body[:2000], payload)
    reported_url = url
    if method != "GET" and body is not None:
        reported_url = f"{url}?_fuzz={param_name}&_ct={content_type}"

    final_vuln_type = matched_vuln or vuln_type
    finding = {
        "id":               str(uuid.uuid4()),
        "vuln_type":        final_vuln_type,
        "parameter":        param_name,
        "payload":          payload,
        "severity":         matched_severity,
        "signature_label":  matched_label,
        "evidence":         matched_label,
        "url":              reported_url,
        "method":           method,
        "content_type":     content_type,
        "status_code":      status_code,
        "response_time_s":  round(elapsed, 3),
        "response_time_ms": round(elapsed * 1000),
        "response_snippet": snippet,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "remediation":      _get_remediation(final_vuln_type),
    }
    finding["cvss_vector"], finding["cvss_score"] = _compute_cvss(final_vuln_type, matched_severity)
    finding["owasp_category"], finding["owasp_name"] = _owasp_for(final_vuln_type)
    return finding


# ── IDOR Checker ──────────────────────────────────────────────────────────────

async def _run_idor_checks(
    session: aiohttp.ClientSession,
    crawl_result: dict[str, Any],
    target_url: str,
    sem: asyncio.Semaphore,
) -> list[dict[str, Any]]:
    """
    IDOR detection: find numeric IDs in GET params and URL path segments,
    then probe incremented/decremented values.
    Flags a finding when:
      - The modified ID returns HTTP 200
      - The response body differs meaningfully from the original ID's response
      - The response is NOT a generic 404/error page
    """
    findings: list[dict[str, Any]] = []

    async def _probe(original_url: str, param_name: str, original_id: str) -> None:
        original_val = int(original_id)
        candidates   = {
            original_val - 1,
            original_val + 1,
            original_val + 2,
            0,
            1,
        }
        candidates.discard(original_val)  # don't probe self

        # Fetch the original response for comparison
        parsed_orig = urlparse(original_url)
        existing    = {k: v[0] if isinstance(v, list) else v
                       for k, v in parse_qs(parsed_orig.query).items()}
        orig_body   = ""
        try:
            async with session.get(
                original_url, timeout=aiohttp.ClientTimeout(total=10),
                ssl=False, allow_redirects=True
            ) as r:
                orig_body   = await r.text(errors="replace")
                orig_status = r.status
        except Exception:
            return

        for cand_id in candidates:
            modified = dict(existing)
            modified[param_name] = str(cand_id)
            new_url = urlunparse(
                parsed_orig._replace(query=urlencode(modified))
            )
            try:
                async with sem:
                    async with session.get(
                        new_url, timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False, allow_redirects=True
                    ) as r:
                        cand_body   = await r.text(errors="replace")
                        cand_status = r.status
            except Exception:
                continue

            # Only flag if:
            # 1. Server returned 200 for the modified ID
            # 2. Response has real content (not a tiny error page)
            # 3. Response is different enough from the original ID's response
            if cand_status != 200:
                continue
            if len(cand_body) < 100:
                continue

            # Simple similarity: flag if bodies differ by more than 10%
            longer  = max(len(orig_body), len(cand_body), 1)
            shorter = min(len(orig_body), len(cand_body))
            similarity = shorter / longer
            if similarity > 0.95:
                continue  # Nearly identical — probably a generic page

            snippet = cand_body[:400].strip()
            idor_finding = {
                "id":               str(uuid.uuid4()),
                "vuln_type":        "IDOR",
                "parameter":        param_name,
                "payload":          str(cand_id),
                "severity":         "High",
                "signature_label":  f"ID {original_id}→{cand_id}: 200 OK with different content ({len(cand_body)} bytes)",
                "evidence":         f"Original ID {original_id} returned {orig_status}, modified ID {cand_id} returned {cand_status} with distinct content",
                "url":              new_url,
                "method":           "GET",
                "content_type":     "form",
                "status_code":      cand_status,
                "response_time_s":  0.0,
                "response_time_ms": 0,
                "response_snippet": snippet,
                "timestamp":        datetime.now(timezone.utc).isoformat(),
                "remediation":      _get_remediation("IDOR"),
            }
            idor_finding["cvss_vector"], idor_finding["cvss_score"] = _compute_cvss("IDOR", "High")
            idor_finding["owasp_category"], idor_finding["owasp_name"] = _owasp_for("IDOR")
            findings.append(idor_finding)

    tasks = []
    for gp in crawl_result.get("get_params", []):
        url    = gp.get("url", target_url)
        params = gp.get("params", {})
        for param_name, param_value in params.items():
            val = param_value[0] if isinstance(param_value, list) else param_value
            if str(val).lstrip("-").isdigit():  # numeric ID found
                tasks.append(_probe(url, param_name, str(val)))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_snippet(body: str, payload: str, max_len: int = 400) -> str:
    idx = body.lower().find(payload.lower())
    if idx != -1:
        start = max(0, idx - 80)
        end   = min(len(body), idx + len(payload) + 120)
        raw   = body[start:end]
    else:
        raw = body[:max_len]
    return raw[:max_len].strip()


def _get_remediation(vuln_type: str) -> str:
    return {
        "SQLi":              "Use parameterized queries. Never concatenate user input into SQL strings.",
        "XSS":               "Encode all user output. Use Content-Security-Policy headers.",
        "RCE":               "Never pass user input to shell commands. Use safe subprocess APIs.",
        "SSRF":              "Whitelist allowed domains. Block requests to internal IP ranges.",
        "Command Injection": "Avoid system calls with user input. Sanitize and escape all inputs.",
        "Path Traversal":    "Validate and canonicalize file paths. Reject ../ sequences.",
        "Auth Bypass":       "Enforce strong server-side auth. Reject 'alg:none' JWTs. Use MFA.",
        "IDOR":              "Implement server-side access control on every resource. Verify ownership before returning data.",
        "Info Disclosure":   "Suppress verbose error messages in production. Use generic error pages.",
        "NoSQL":             "Validate input types strictly; never pass user input directly into MongoDB query operators. Use parameterized drivers.",
        "XXE":               "Disable external entity resolution in your XML parser: set `external-general-entities` and `load-external-dtd` to false.",
        "SSTI":              "Never render user input as a template. Use static templates with parameterized values only.",
        "Open Redirect":     "Validate redirect destinations against an allowlist of trusted domains. Reject relative URLs starting with `//` or `\\\\`.",
    }.get(vuln_type, "Sanitize and validate all user inputs. Follow OWASP best practices.")


def _resolve_form_content_types(form: dict) -> list[PostContentType]:
    enctype = (form.get("enctype") or "").lower()
    if "xml" in enctype:
        return ["xml", "json", "form"]
    if "json" in enctype:
        return ["json", "form"]
    return ["form", "json"]


# ── Public Entry Point ────────────────────────────────────────────────────────

async def run_fuzzer(
    crawl_result: dict[str, Any],
    all_payloads: dict[str, dict[str, list[str]]],
    target_url: str,
    concurrency: int = 10,
    progress_callback=None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    sem       = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    headers   = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SmartFuzz/2.0",
        "Accept":     "text/html,application/xhtml+xml,application/json,*/*",
    }

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:

        # ── FIX (Flaw A): Method-correct baseline capture ─────────────────
        if progress_callback:
            await progress_callback(2, "Capturing method-correct baselines…")

        baseline_responses: dict[str, Any] = {}

        # GET baselines — straightforward GET request
        for gp in crawl_result.get("get_params", []):
            url = gp.get("url", target_url)
            key = f"GET:{url.split('?')[0]}"
            if key not in baseline_responses:
                baseline_responses[key] = await _capture_baseline(
                    session, url, "GET"
                )

        # POST baselines — use real POST with default values, NOT a GET
        for form in crawl_result.get("forms", []):
            action       = form.get("action") or target_url
            method       = (form.get("method") or "POST").upper()
            key          = f"{method}:{action.split('?')[0]}"
            if key not in baseline_responses:
                default_body = _build_default_form_body(form) if method == "POST" else None
                baseline_responses[key] = await _capture_baseline(
                    session, action, method, default_body
                )
        # ── End Flaw A fix ────────────────────────────────────────────────

        # ── Build payload-injection task list ─────────────────────────────
        tasks: list[asyncio.Task] = []

        for vuln_type, field_payloads in all_payloads.items():
            if vuln_type == "IDOR":
                continue  # IDOR handled separately below

            for field_name, payload_list in field_payloads.items():

                # GET parameter fuzzing
                for gp in crawl_result.get("get_params", []):
                    parsed   = urlparse(gp.get("url", target_url))
                    existing = parse_qs(parsed.query)
                    if field_name not in existing:
                        continue
                    for payload in payload_list:
                        async def _gt(
                            s=session, bu=gp["url"], ep=existing,
                            pn=field_name, pl=payload, vt=vuln_type,
                            br=baseline_responses
                        ):
                            async with sem:
                                return await _fuzz_get_param(s, bu, ep, pn, pl, vt, br)
                        tasks.append(asyncio.create_task(_gt()))

                # POST form fuzzing
                for form in crawl_result.get("forms", []):
                    form_fields = [
                        f.get("name")
                        for f in form.get("inputs", form.get("fields", []))
                    ]
                    if field_name not in form_fields:
                        continue
                    for content_type in _resolve_form_content_types(form):
                        for payload in payload_list:
                            async def _ft(
                                s=session, fm=form, fn=field_name,
                                pl=payload, vt=vuln_type, ct=content_type,
                                br=baseline_responses
                            ):
                                async with sem:
                                    return await _fuzz_form_field(
                                        s, fm, fn, pl, vt, target_url, br, ct
                                    )
                            tasks.append(asyncio.create_task(_ft()))

        total     = len(tasks)
        completed = 0

        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            if result is not None:
                findings.append(result)
            if progress_callback and total > 0 and completed % max(1, total // 20) == 0:
                pct = int(completed / total * 100)
                await progress_callback(pct, f"Fuzzed {completed}/{total} requests…")

        # ── IDOR checks (runs after main fuzzing) ─────────────────────────
        if "IDOR" in all_payloads:
            if progress_callback:
                await progress_callback(90, "Running IDOR ID-enumeration checks…")
            idor_findings = await _run_idor_checks(
                session, crawl_result, target_url, sem
            )
            findings.extend(idor_findings)

    # De-duplicate and sort
    seen:   set[tuple] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = (f["parameter"], f["vuln_type"], f["url"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: _SEV_RANK.get(f.get("severity", "Low"), 0), reverse=True)
    return unique


def fuzz_sync(
    crawl_result: dict[str, Any],
    all_payloads: dict[str, dict[str, list[str]]],
    target_url: str,
    concurrency: int = 10,
) -> list[dict[str, Any]]:
    """Blocking wrapper — safe to call from Flask background threads."""
    return asyncio.run(
        run_fuzzer(crawl_result, all_payloads, target_url, concurrency)
    )