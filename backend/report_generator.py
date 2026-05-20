import os
from datetime import datetime, timezone, timedelta
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)

# ─── FONT CONFIGURATION (Pandoc Style) ─────────────────────────────────────────
FONT_MAIN = "Times-Roman"
FONT_BOLD = "Times-Bold"
FONT_MONO = "Courier"

FONT_SIZE = 12
LEADING = 15
MARGIN = 0.8 * inch

# ─── RICHER ACADEMIC COLOR PALETTE ────────────────────────────────────────────
PRIMARY    = colors.HexColor("#1A365D")  # Deep Navy Blue
SECONDARY  = colors.HexColor("#4C51BF")  # Deep Indigo
ACCENT     = colors.HexColor("#EBF8FF")  # Richer Ice Blue for headers
ALT_ROW    = colors.HexColor("#F7FAFC")  # Alternating row color
LINE_COL   = colors.HexColor("#A0AEC0")  # Muted Gray
RIBBON_BG  = colors.HexColor("#E0F2FE")  # Sleek, professional Light Sky Blue

SEV_COLOR = {
    "Critical": colors.HexColor("#9B2C2C"),  # Crimson
    "High":     colors.HexColor("#C05621"),  # Burnt Orange
    "Medium":   colors.HexColor("#B7791F"),  # Goldenrod
    "Low":      colors.HexColor("#2C5282"),  # Muted Blue
}


def _cvss_color(score):
    """Map a CVSS base score to the same severity colour band used elsewhere
    in the report. Returns black if score is None."""
    if score is None:
        return colors.black
    if score >= 9.0:
        return SEV_COLOR["Critical"]
    if score >= 7.0:
        return SEV_COLOR["High"]
    if score >= 4.0:
        return SEV_COLOR["Medium"]
    return SEV_COLOR["Low"]


# ─── EXPANDED REMEDIATION DICTIONARY ──────────────────────────────────────────
REMEDIATION = {
    "SQLi": [
        "Use parameterized queries (Prepared Statements) for all database access to strictly separate code logic from user data.",
        "Utilize modern Object-Relational Mapping (ORM) libraries that automatically escape SQL inputs by default.",
        "Enforce the Principle of Least Privilege (PoLP) on the database account used by the application (e.g., revoke DROP or ALTER permissions).",
        "Implement strict input validation using allowlists for any user data that must be dynamically inserted into queries.",
        "Deploy a Web Application Firewall (WAF) to detect and block common SQL injection signatures.",
        "Reference: OWASP Top 10 A03:2021 — Injection",
    ],
    "XSS": [
        "Contextually output-encode all user-supplied data before rendering it in the browser (HTML, JavaScript, CSS, or URL contexts).",
        "Implement a strict, restrictive Content-Security-Policy (CSP) HTTP response header to prevent the execution of inline scripts and untrusted sources.",
        "Set the 'HttpOnly' and 'Secure' flags on all sensitive cookies (e.g., session tokens) to prevent theft via client-side scripts.",
        "Sanitize any rich-text (HTML) input on the server side using a robust, actively maintained library (e.g., DOMPurify or Bleach).",
        "Utilize modern frontend frameworks (React, Angular, Vue) that safely bind data to the DOM by default.",
        "Reference: OWASP Top 10 A03:2021 — Injection",
    ],
    "RCE": [
        "Never pass user-supplied data directly to system shells or dynamic code evaluation functions (e.g., `eval()`, `exec()`, `os.system()`).",
        "Replace system command invocations with equivalent, safe language-native APIs (e.g., use `os.mkdir()` instead of executing `mkdir` in a shell).",
        "If shell execution is completely unavoidable, strictly validate input against an allowlist and rigorously escape all arguments.",
        "Run the application with the absolute minimum OS privileges required, and isolate the environment using containers (Docker) or jails (AppArmor).",
        "Reference: OWASP Top 10 A03:2021 — Injection",
    ],
    "SSRF": [
        "Implement a strict allowlist of permitted destination domains, IP addresses, and protocols for any outbound server requests.",
        "Actively block and reject network requests targeting internal, loopback, or reserved IP ranges (e.g., 10.0.0.0/8, 169.254.169.254, 127.0.0.1).",
        "Disable HTTP redirection for server-side requests, or strictly re-validate the target URL against the allowlist after following any redirect.",
        "Route all outbound application traffic through a dedicated egress proxy that explicitly drops internal network access.",
        "Reference: OWASP Top 10 A10:2021 — Server-Side Request Forgery",
    ],
    "Command Injection": [
        "Avoid invoking host operating system commands with user-supplied data whenever possible.",
        "When executing system commands, parameterize the arguments instead of concatenating strings, ensuring the shell does not interpret the input.",
        "Implement strict input validation (allowlisting) ensuring only alphanumeric characters are accepted for command arguments.",
        "Drop unnecessary system privileges and utilize seccomp filters or AppArmor to restrict the system calls available to the application.",
        "Reference: OWASP Top 10 A03:2021 — Injection",
    ],
    "Auth Bypass": [
        "Enforce a centralized, robust authentication framework rather than relying on custom or ad-hoc login scripts.",
        "If using JWTs, strictly verify the token's cryptographic signature on every request and outright reject tokens utilizing the 'none' algorithm.",
        "Ensure all authentication queries use parameterized statements to prevent SQL-based login bypasses.",
        "Implement multi-factor authentication (MFA) and strict rate-limiting to mitigate brute-force and credential stuffing attacks.",
        "Reference: OWASP Top 10 A07:2021 — Identification and Authentication Failures",
    ],
    "IDOR": [
        "Implement strict Authorization and Access Control checks on *every* request attempting to access, modify, or delete a resource.",
        "Verify that the currently authenticated user session actually owns or has explicit permission to access the requested Object ID.",
        "Replace predictable, sequential integer IDs with unpredictable, mathematically secure identifiers (e.g., UUIDv4 or GUIDs).",
        "Ensure the API does not blindly trust client-provided IDs for operations affecting the current user's profile or financial state.",
        "Reference: OWASP Top 10 A01:2021 — Broken Access Control",
    ],
    "NoSQL": [
        "Validate input types strictly; never pass user input directly into NoSQL query operators ($where, $ne, $gt, $regex).",
        "Reject payloads containing $-prefixed keys where the field expects a scalar value.",
        "Disable server-side JavaScript in the database engine ($where, mapReduce) unless absolutely required.",
        "Reference: OWASP API Security A08:2023 — Security Misconfiguration",
    ],
    "XXE": [
        "Disable external entity resolution in the XML parser (set external-general-entities and load-external-dtd to false).",
        "Disable inline DTDs entirely where business logic allows.",
        "Prefer JSON over XML for new endpoints; XXE is an XML-only failure mode.",
        "Reference: OWASP Top 10 A05:2021 — Security Misconfiguration",
    ],
    "SSTI": [
        "Never render user input as a template. Use static templates with parameterised values only.",
        "Sandbox the template engine; deny access to language internals (__class__, __subclasses__, getClass()).",
        "Strip or reject template syntax ({{ }}, ${ }, <% %>) in any field rendered through a template.",
        "Reference: PortSwigger Web Security Academy — Server-Side Template Injection",
    ],
    "Open Redirect": [
        "Validate redirect destinations against an allowlist of trusted domains.",
        "Reject relative URLs starting with // or \\ and non-http(s) schemes (javascript:, data:).",
        "Prefer server-side indirection: redirect via short tokens that map to URLs server-side.",
        "Reference: OWASP Top 10 A01:2021 — Broken Access Control",
    ],
}

# ─── STYLE HELPERS ────────────────────────────────────────────────────────────

def _p(text, font=FONT_MAIN, size=FONT_SIZE, align=TA_JUSTIFY, color=colors.black, bold=False):
    fname = FONT_BOLD if bold and font == FONT_MAIN else font
    return Paragraph(str(text), ParagraphStyle(
        "CustomStyle",
        fontName=fname,
        fontSize=size,
        leading=size * 1.25,
        alignment=align,
        textColor=color,
        spaceAfter=0,
        spaceBefore=0
    ))

def _h1(text):
    return Paragraph(str(text), ParagraphStyle(
        "H1", fontName=FONT_BOLD, fontSize=16, leading=20, spaceAfter=12, spaceBefore=24, textColor=PRIMARY
    ))

def _h2(text):
    return Paragraph(str(text), ParagraphStyle(
        "H2", fontName=FONT_BOLD, fontSize=13, leading=16, spaceAfter=8, spaceBefore=16, textColor=SECONDARY
    ))

def _sp(h=12): return Spacer(1, h)

def get_booktabs_style(row_count):
    cmds = [
        ("BACKGROUND", (0,0), (-1,0), ACCENT),
        ("LINEABOVE", (0,0), (-1,0), 1.5, PRIMARY),
        ("LINEBELOW", (0,0), (-1,0), 1.0, PRIMARY),
        ("LINEBELOW", (0,-1), (-1,-1), 1.5, PRIMARY),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ]
    for i in range(1, row_count):
        if i % 2 == 0:
            cmds.append(("BACKGROUND", (0, i), (-1, i), ALT_ROW))
    return TableStyle(cmds)

# ─── TIMEZONE HELPER ──────────────────────────────────────────────────────────

def convert_to_ist(utc_date_str):
    """Converts a UTC ISO string to an Indian Standard Time (IST) 24h formatted string."""
    IST = timezone(timedelta(hours=5, minutes=30), "IST")
    try:
        clean_str = str(utc_date_str).replace("Z", "+00:00")
        if "+" not in clean_str and "-" not in clean_str[10:]:
            clean_str += "+00:00"

        dt_utc = datetime.fromisoformat(clean_str)
        dt_ist = dt_utc.astimezone(IST)

        # Returns format: 2026-05-18 14:25 IST
        return dt_ist.strftime("%Y-%m-%d %H:%M IST")
    except Exception:
        return datetime.now(IST).strftime("%Y-%m-%d %H:%M IST")

# ─── EDGE-TO-EDGE MINIMAL PAGE HEADER/FOOTER ──────────────────────────────────

def _make_page_fn(short_id, target_url, date_str):
    def fn(canvas, doc):
        canvas.saveState()
        w, h = A4
        band_height = 0.35 * inch

        # --- TOP HEADER BAND ---
        canvas.setFillColor(RIBBON_BG)
        canvas.rect(0, h - band_height, w, band_height, fill=1, stroke=0)

        # Header Text
        canvas.setFillColor(PRIMARY)
        canvas.setFont(FONT_BOLD, 9)
        canvas.drawString(MARGIN, h - band_height + 0.12 * inch, "SmartFuzz Security Report")

        canvas.setFont(FONT_MAIN, 9)
        target_display = target_url[:50] + ("..." if len(target_url) > 50 else "")
        canvas.drawRightString(w - MARGIN, h - band_height + 0.12 * inch, f"Target: {target_display}")

        # --- BOTTOM FOOTER BAND ---
        canvas.setFillColor(RIBBON_BG)
        canvas.rect(0, 0, w, band_height, fill=1, stroke=0)

        # Footer Text
        canvas.setFillColor(PRIMARY)
        canvas.setFont(FONT_MAIN, 9)
        canvas.drawString(MARGIN, 0.12 * inch, f"Ref: {short_id}")
        canvas.drawCentredString(w / 2.0, 0.12 * inch, f"- {doc.page} -")

        # Exact Timestamp String
        canvas.drawRightString(w - MARGIN, 0.12 * inch, date_str)

        canvas.restoreState()
    return fn

# ─── REPORT GENERATION ────────────────────────────────────────────────────────

def generate_pdf_report(scan: dict, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)

    scan_id    = scan.get("id", scan.get("scan_id", "unknown"))
    short_id   = scan_id[:8] if len(scan_id) >= 8 else scan_id
    filename   = f"smartfuzz_report_{short_id}.pdf"
    filepath   = os.path.join(output_dir, filename)

    findings   = scan.get("findings", [])
    stats      = scan.get("stats", {})
    target_url = scan.get("target_url", "—")

    raw_date = (scan.get("completed_at") or scan.get("created_at") or
                scan.get("scan_date") or datetime.now(timezone.utc).isoformat())

    # Process the raw UTC date into IST
    date_str = convert_to_ist(raw_date)

    # ── CVSS aggregates ───────────────────────────────────────────────────────
    cvss_scores = [
        float(f["cvss_score"]) for f in findings
        if f.get("cvss_score") is not None
    ]
    max_cvss  = max(cvss_scores) if cvss_scores else None
    avg_cvss  = (sum(cvss_scores) / len(cvss_scores)) if cvss_scores else None

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN + 0.2 * inch,
        bottomMargin=MARGIN + 0.2 * inch,
        title=f"Security Assessment: {target_url}",
        author="SmartFuzz Engine",
    )

    story = []

    # ── TITLE PAGE ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.5 * inch))
    story.append(_p("Security Assessment Report", font=FONT_BOLD, size=26, align=TA_CENTER, color=PRIMARY))
    story.append(Spacer(1, 0.25 * inch))
    story.append(_p("Automated Vulnerability Discovery", font=FONT_MAIN, size=14, align=TA_CENTER, color=SECONDARY))
    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="60%", thickness=2.0, color=PRIMARY, spaceAfter=30, spaceBefore=30))

    story.append(_p(f"<b>Target Infrastructure:</b> {target_url}", align=TA_CENTER))
    story.append(_p(f"<b>Date of Assessment:</b> {date_str}", align=TA_CENTER))
    story.append(_p(f"<b>Reference ID:</b> {scan_id}", align=TA_CENTER, size=10, color=LINE_COL))

    story.append(PageBreak())

    # ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────────────
    story.append(_h1("1. Executive Summary"))

    overall = "Clean"
    for lvl in ("Critical", "High", "Medium", "Low"):
        if stats.get(lvl.lower(), 0) > 0:
            overall = lvl
            break

    summary_text = (
        f"This document presents the findings of an automated security assessment conducted against "
        f"<b>{target_url}</b> on {date_str}. The assessment utilized the SmartFuzz testing engine to "
        f"evaluate the target against a predefined set of vulnerability classes. "
        f"The overall risk posture of the application is currently evaluated as <b>{overall}</b>."
    )
    story.append(_p(summary_text))
    story.append(_sp(15))

    # CVSS aggregates shown alongside the standard metrics
    max_cvss_str = f"{max_cvss:.1f}" if max_cvss is not None else "—"
    avg_cvss_str = f"{avg_cvss:.1f}" if avg_cvss is not None else "—"

    metrics_data = [
        [_p("Assessment Metric", bold=True, color=PRIMARY), _p("Value", bold=True, color=PRIMARY)],
        [_p("Total Payloads Generated"), _p(str(stats.get("total_payloads_generated", 0)), color=SECONDARY, bold=True)],
        [_p("Total Findings Confirmed"), _p(str(stats.get("total_findings", 0)), color=SECONDARY, bold=True)],
        [_p("Critical Risk Findings"), _p(str(stats.get("critical", 0)), color=SEV_COLOR["Critical"], bold=True)],
        [_p("High Risk Findings"), _p(str(stats.get("high", 0)), color=SEV_COLOR["High"], bold=True)],
        [_p("Medium Risk Findings"), _p(str(stats.get("medium", 0)), color=SEV_COLOR["Medium"], bold=True)],
        [_p("Maximum CVSS v3.1 Score"), _p(max_cvss_str, color=_cvss_color(max_cvss), bold=True)],
        [_p("Average CVSS v3.1 Score"), _p(avg_cvss_str, color=_cvss_color(avg_cvss), bold=True)],
    ]
    t = Table(metrics_data, colWidths=[doc.width * 0.6, doc.width * 0.4])
    t.setStyle(get_booktabs_style(len(metrics_data)))
    story.append(t)
    story.append(PageBreak())

    # ── 2. AUTHORIZATION & CONSENT ────────────────────────────────────────────
    story.append(_h1("2. Authorization & Consent"))

    consent_intro = (
        "Before this assessment was launched, the SmartFuzz operator was presented with a "
        "mandatory legal consent dialog. The scan only proceeded once the operator explicitly "
        "confirmed each of the following statements."
    )
    story.append(_p(consent_intro))
    story.append(_sp(10))

    story.append(_h2("Confirmation Statements"))
    consent_items = [
        "I own this target, or I have written authorization from the owner.",
        "I understand this scan will send potentially malicious payloads.",
        "I accept full legal responsibility for the consequences of this scan.",
    ]
    for idx, line in enumerate(consent_items, 1):
        story.append(_p(f"{idx}. {line}"))
    story.append(_sp(15))

    story.append(_h2("Legal Reference — Information Technology Act, 2000"))
    legal_text = (
        "Unauthorized access to a computer resource, including the unauthorized scanning of "
        "computer systems for vulnerabilities, constitutes a punishable offence under the "
        "Information Technology Act, 2000 (India), <b>Section 43</b> (penalty for damage to "
        "computer, computer system, etc.) and <b>Section 66</b> (computer-related offences). "
        "Comparable statutes exist in most jurisdictions worldwide — notably the Computer Fraud "
        "and Abuse Act (United States), the Computer Misuse Act 1990 (United Kingdom), and the "
        "Council of Europe Convention on Cybercrime. SmartFuzz records the operator's "
        "authorization before each scan to ensure all testing activity is performed in "
        "compliance with applicable law."
    )
    story.append(_p(legal_text))
    story.append(PageBreak())

    # ── 3. FINDINGS SUMMARY ───────────────────────────────────────────────────
    story.append(_h1("3. Findings Summary"))

    if not findings:
        story.append(_p("No vulnerabilities were confirmed during this assessment.", align=TA_CENTER))
    else:
        summary_data = [
            [
                _p("ID",            bold=True, color=PRIMARY),
                _p("Vulnerability", bold=True, color=PRIMARY),
                _p("Parameter",     bold=True, color=PRIMARY),
                _p("Severity",      bold=True, color=PRIMARY),
                _p("CVSS",          bold=True, color=PRIMARY),
            ]
        ]
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity", "Low")
            sc    = SEV_COLOR.get(sev, colors.black)
            score = f.get("cvss_score")
            score_str   = f"{float(score):.1f}" if score is not None else "—"
            score_color = _cvss_color(float(score)) if score is not None else colors.black
            summary_data.append([
                _p(str(i)),
                _p(f.get("vuln_type", "")),
                _p(f.get("parameter", "—")),
                _p(sev,       color=sc,          bold=True),
                _p(score_str, color=score_color, bold=True),
            ])

        t_sum = Table(
            summary_data,
            colWidths=[
                doc.width * 0.07,
                doc.width * 0.35,
                doc.width * 0.27,
                doc.width * 0.17,
                doc.width * 0.14,
            ],
        )
        t_sum.setStyle(get_booktabs_style(len(summary_data)))
        story.append(t_sum)
        story.append(PageBreak())

        # ── 4. DETAILED FINDINGS ──────────────────────────────────────────────
        story.append(_h1("4. Detailed Findings Analysis"))

        for i, f in enumerate(findings, 1):
            sev   = f.get("severity", "Low")
            sc    = SEV_COLOR.get(sev, colors.black)
            score = f.get("cvss_score")
            score_str   = f"{float(score):.1f}" if score is not None else "—"
            score_color = _cvss_color(float(score)) if score is not None else colors.black
            vector_str  = f.get("cvss_vector") or "—"

            story.append(_h2(f"Finding {i}: {f.get('vuln_type', 'Unknown')} in parameter '{f.get('parameter', '—')}'"))

            payload_str = (f.get("payload", "") or "—").replace("<", "&lt;").replace(">", "&gt;")
            snippet = (f.get("response_snippet") or f.get("evidence") or "—").strip()
            safe_snip = snippet[:500].replace("<", "&lt;").replace(">", "&gt;")

            detail_data = [
                [_p("Severity:",         bold=True), _p(sev, color=sc, bold=True)],
                [_p("CVSS v3.1 Score:",  bold=True), _p(score_str, color=score_color, bold=True)],
                [_p("CVSS Vector:",      bold=True), _p(vector_str, font=FONT_MONO, size=9, color=SECONDARY, align=TA_LEFT)],
                [_p("Target URL:",       bold=True), _p(f.get("url", "—"), font=FONT_MONO, size=10, color=SECONDARY, align=TA_LEFT)],
                [_p("Method:",           bold=True), _p(f.get("method", "—"))],
                [_p("Status Code:",      bold=True), _p(str(f.get("status_code", "—")))],
                [_p("Response Time:",    bold=True), _p(f"{f.get('response_time_s', '—')} seconds")],
                [_p("Injected Payload:", bold=True), _p(payload_str, font=FONT_MONO, size=10, color=SEV_COLOR["Critical"], align=TA_LEFT)],
                [_p("Evidence:",         bold=True), _p(safe_snip, font=FONT_MONO, size=10, color=colors.HexColor("#4A5568"), align=TA_LEFT)],
            ]

            t_det = Table(detail_data, colWidths=[doc.width * 0.25, doc.width * 0.75])
            t_det.setStyle(TableStyle([
                ("VALIGN", (0,0), (-1,-1), "TOP"),
                ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ]))
            story.append(t_det)

            story.append(HRFlowable(width="100%", thickness=0.5, color=LINE_COL, spaceAfter=20, spaceBefore=20))

    # ── 5. REMEDIATION REFERENCE ──────────────────────────────────────────────
    if findings:
        story.append(PageBreak())
        story.append(_h1("5. Remediation Guidance"))

        seen_types = list(dict.fromkeys(f.get("vuln_type", "") for f in findings))
        for vt in seen_types:
            story.append(_h2(vt))
            steps = REMEDIATION.get(vt, ["Sanitize and validate all user inputs."])
            for step_idx, step_text in enumerate(steps, 1):
                story.append(_p(f"{step_idx}. {step_text}"))
            story.append(_sp(15))

    # ── DISCLAIMER ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="100%", thickness=1.0, color=PRIMARY, spaceAfter=15, spaceBefore=15))
    story.append(_p("Disclaimer", bold=True, color=PRIMARY))
    story.append(_p(
        "This report was generated automatically. Results should be "
        "reviewed and validated by a qualified security professional. "
        "False positives may be present."
    ))

    # Build PDF with the edge-to-edge ribbon header/footer carrying the timestamp
    page_func = _make_page_fn(short_id, target_url, date_str)
    doc.build(story, onFirstPage=page_func, onLaterPages=page_func)

    return os.path.abspath(filepath)
