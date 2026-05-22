"""
app.py — SmartFuzz Flask Backend
=========================================================
- SQLite database backed
- Differential fuzzing engine with progress hooks
- Auth Bypass + IDOR support
- PDF report generation
"""

import asyncio
import ipaddress
import os
import socket
import time
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, join_room

from crawler import crawl
from payload_generator import generate_all_payloads, refine_payloads
from fuzzer import run_fuzzer
from report_generator import generate_pdf_report
import database as db

app = Flask(__name__)
CORS(app)

# Threading mode chosen over eventlet because the scan worker already uses
# asyncio.run(run_fuzzer(...)); mixing eventlet's monkey-patches with asyncio
# is fragile. Threading lets SocketIO co-exist with the existing pattern.
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

db.init_db()


def _emit_scan_event(scan_id: str) -> None:
    """No-op. The frontend polls /status over HTTP instead of using WebSockets
    (the threading-mode server can't serve WS), so there are no room subscribers.
    Skipping the emit avoids two extra locked DB reads per progress update while
    a scan is running — keeping the DB lock free for page reads."""
    return


def _progress(scan_id: str, percent: int, step: str, status: str | None = None) -> None:
    """Persist progress to DB AND push it to all room subscribers in one call.
    Replaces direct db.update_scan_progress() calls inside the scan worker."""
    db.update_scan_progress(scan_id, percent, step, status=status)
    _emit_scan_event(scan_id)


@socketio.on("connect")
def _on_socket_connect():
    """Client joins the room named after its scan_id (passed as query string).
    Emits the current state immediately so the client doesn't have to wait
    for the next progress tick."""
    scan_id = request.args.get("scan_id")
    if scan_id:
        join_room(scan_id)
        _emit_scan_event(scan_id)


# ── SSRF guard ────────────────────────────────────────────────────────────────
# Reject target_urls that would let SmartFuzz be used as a launchpad against
# internal infra (loopback, RFC1918, link-local, cloud metadata, CGNAT, etc.).
# Set SMARTFUZZ_ALLOW_LOCAL=1 in the env to permit loopback/RFC1918 targets when
# scanning local Docker instances (Juice Shop, DVWA) during development.

_FORBIDDEN_HOSTNAMES = {"localhost", "metadata.google.internal", "metadata.aws"}

_BLOCKED_V4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_BLOCKED_V6_NETWORKS = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _ip_is_blocked(ip) -> bool:
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_unspecified or ip.is_multicast:
        return True
    networks = _BLOCKED_V4_NETWORKS if isinstance(ip, ipaddress.IPv4Address) else _BLOCKED_V6_NETWORKS
    return any(ip in net for net in networks)


def _resolve_all(hostname: str) -> list[str]:
    """Return every distinct IP (v4 + v6) that `hostname` resolves to.
    Used to block DNS-rebinding attempts that hide a private IP behind a public name."""
    infos = socket.getaddrinfo(hostname, None)
    seen: set[str] = set()
    out: list[str] = []
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        if ip_str not in seen:
            seen.add(ip_str)
            out.append(ip_str)
    return out


def _validate_target_url(url: str) -> tuple[bool, str]:
    allow_local = os.environ.get("SMARTFUZZ_ALLOW_LOCAL") == "1"

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "Malformed URL"

    if parsed.scheme not in ("http", "https"):
        return False, f"scheme must be http or https (got '{parsed.scheme}')"

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        return False, "URL has no hostname"

    if not allow_local:
        if hostname in _FORBIDDEN_HOSTNAMES or hostname.endswith(".local"):
            return False, f"hostname '{hostname}' is forbidden"

    # If the hostname is already a literal IP, validate it directly — no DNS.
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not allow_local and _ip_is_blocked(literal_ip):
            return False, f"target IP {literal_ip} is in a blocked range (private/loopback/metadata)"
        return True, ""

    # Resolve and inspect *every* returned IP. 5s timeout — getaddrinfo has no
    # native timeout, so we run it on a worker we can abandon on overrun.
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(_resolve_all, hostname)
        try:
            ips = future.result(timeout=5)
        except FuturesTimeoutError:
            return False, "Could not resolve target hostname"
        except (socket.gaierror, OSError, UnicodeError):
            return False, "Could not resolve target hostname"
    finally:
        executor.shutdown(wait=False)

    if not ips:
        return False, "Could not resolve target hostname"

    if not allow_local:
        for raw_ip in ips:
            # IPv6 sockaddrs may include a scope id like "fe80::1%eth0".
            bare = raw_ip.split("%", 1)[0]
            try:
                ip = ipaddress.ip_address(bare)
            except ValueError:
                continue
            if _ip_is_blocked(ip):
                return False, f"hostname resolves to blocked IP {ip} (private/loopback/metadata)"

    return True, ""

# Per-scan cancellation events — set by the cancel endpoint, polled by the scan thread
_cancel_events: dict[str, threading.Event] = {}
_cancel_events_lock = threading.Lock()


def _get_cancel_event(scan_id: str) -> threading.Event:
    with _cancel_events_lock:
        if scan_id not in _cancel_events:
            _cancel_events[scan_id] = threading.Event()
        return _cancel_events[scan_id]


def _cleanup_cancel_event(scan_id: str):
    with _cancel_events_lock:
        _cancel_events.pop(scan_id, None)


def _build_crawl_kwargs(auth: dict | None) -> dict:
    """Translate the optional `auth` block from /api/scan/new into crawl() kwargs.
    Returns {} when auth is None or empty so crawl() runs in its default mode."""
    if not auth or not isinstance(auth, dict):
        return {}
    kwargs: dict = {}
    cookies = auth.get("cookies")
    if isinstance(cookies, list) and cookies:
        kwargs["auth_cookies"] = cookies
    headers = auth.get("headers")
    if isinstance(headers, dict) and headers:
        kwargs["auth_headers"] = headers
    login = auth.get("login")
    if isinstance(login, dict) and login.get("url"):
        kwargs["login_url"] = login.get("url")
        kwargs["login_username"] = login.get("username")
        kwargs["login_password"] = login.get("password")
        if login.get("username_field"):
            kwargs["login_username_field"] = login["username_field"]
        if login.get("password_field"):
            kwargs["login_password_field"] = login["password_field"]
    return kwargs


def run_scan(scan_id: str, vuln_classes: list, target_url: str, auth: dict | None = None):
    cancel_event = _get_cancel_event(scan_id)

    def cancelled() -> bool:
        return cancel_event.is_set()

    try:
        _progress(scan_id, 5, "Resolving target host...", status="running")
        time.sleep(0.5)
        if cancelled(): return

        _progress(scan_id, 15, "Crawling target URL for attack surfaces...")
        crawl_kwargs = _build_crawl_kwargs(auth)
        crawl_result = crawl(target_url, **crawl_kwargs)
        if cancelled(): return

        if not crawl_result["reachable"]:
            db.fail_scan(scan_id, f"Target unreachable: {crawl_result['error']}")
            _emit_scan_event(scan_id)
            return

        _progress(scan_id, 30,
            f"Found {len(crawl_result['forms'])} form(s) and "
            f"{len(crawl_result['get_params'])} GET parameter set(s).")
        time.sleep(0.5)
        if cancelled(): return

        _progress(scan_id, 40,
            "Asking Gemini AI to generate context-aware payloads...")
        all_payloads = generate_all_payloads(
            vuln_classes=vuln_classes,
            crawl_data=crawl_result,
        )
        if cancelled(): return

        total_payloads = sum(
            len(p) for fields in all_payloads.values() for p in fields.values()
        )

        _progress(scan_id, 48,
            f"Generated {total_payloads} AI payloads across "
            f"{len(vuln_classes)} vulnerability classes.")
        time.sleep(0.3)
        if cancelled(): return

        _progress(scan_id, 52,
            "Configuring heuristic response baselines...")

        async def progress_hook(percentage: int, message: str):
            if not cancelled():
                scaled = int(55 + (percentage * 0.35))
                _progress(scan_id, scaled, message)

        findings = asyncio.run(run_fuzzer(
            crawl_result=crawl_result,
            all_payloads=all_payloads,
            target_url=target_url,
            concurrency=8,
            progress_callback=progress_hook,
        ))
        if cancelled(): return

        try:
            _progress(scan_id, 85,
                f"Analyzing {len(findings)} first-pass finding(s) for adaptive refinement…")
            refined_payloads = refine_payloads(findings, crawl_result, vuln_classes)
            if refined_payloads and not cancelled():
                refined_count = sum(
                    len(p) for fields in refined_payloads.values() for p in fields.values()
                )
                _progress(scan_id, 87,
                    f"Adaptive second-pass: firing {refined_count} refined payload(s) "
                    f"across {len(refined_payloads)} vuln class(es)…")
                pre_count = len(findings)
                second_pass = asyncio.run(run_fuzzer(
                    crawl_result=crawl_result,
                    all_payloads=refined_payloads,
                    target_url=target_url,
                    concurrency=8,
                ))
                if not cancelled():
                    existing_keys = {
                        (f["parameter"], f["vuln_type"], f["url"]) for f in findings
                    }
                    for f in second_pass:
                        key = (f["parameter"], f["vuln_type"], f["url"])
                        if key not in existing_keys:
                            findings.append(f)
                            existing_keys.add(key)
                    new_findings = len(findings) - pre_count
                    _progress(scan_id, 89,
                        f"Adaptive second-pass complete — {new_findings} new finding(s) "
                        f"from {refined_count} refined payload(s).")
            elif not cancelled():
                _progress(scan_id, 89,
                    "Adaptive refinement skipped — no first-pass findings to refine.")
        except Exception as e:
            print(f"[run_scan] Second-pass refinement failed: {e}")
            if not cancelled():
                _progress(scan_id, 89,
                    f"Adaptive refinement failed: {str(e)[:80]}")

        if cancelled(): return

        db.insert_findings_bulk(scan_id, findings)

        _progress(scan_id, 90,
            f"Fuzzing complete — {len(findings)} verified finding(s).")
        time.sleep(0.3)
        if cancelled(): return

        _progress(scan_id, 95,
            "Compiling findings and generating report...")
        time.sleep(0.3)
        if cancelled(): return

        db.complete_scan(
            scan_id=scan_id,
            completed_at=datetime.utcnow().isoformat() + "Z",
            forms_crawled=len(crawl_result["forms"]),
            get_params_found=len(crawl_result["get_params"]),
            total_payloads=total_payloads,
            page_title=crawl_result.get("page_title", ""),
        )
        _emit_scan_event(scan_id)

    except Exception as e:
        import traceback
        print(f"CRITICAL: Scan thread crashed: {e}")
        traceback.print_exc()
        db.fail_scan(scan_id, f"Scan failed: {str(e)}")
        _emit_scan_event(scan_id)
    finally:
        _cleanup_cancel_event(scan_id)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "SmartFuzz backend is running"}), 200


@app.route("/api/scan/new", methods=["POST"])
def new_scan():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    target_url = data.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "target_url is required"}), 400
    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "target_url must start with http:// or https://"}), 400

    is_safe, reason = _validate_target_url(target_url)
    if not is_safe:
        return jsonify({"error": f"Target URL rejected: {reason}"}), 400

    scan_type = data.get("scan_type", "GET").upper()
    if scan_type not in ("GET", "POST"):
        return jsonify({"error": "scan_type must be GET or POST"}), 400

    supported = {"SQLi", "XSS", "RCE", "SSRF", "Command Injection", "Auth Bypass", "IDOR",
                 "NoSQL", "XXE", "SSTI", "Open Redirect"}
    vuln_classes = data.get("vuln_classes", list(supported))
    invalid = set(vuln_classes) - supported
    if invalid:
        return jsonify({"error": f"Unsupported vulnerability classes: {invalid}"}), 400

    auth = data.get("auth")
    if auth is not None and not isinstance(auth, dict):
        return jsonify({"error": "auth must be an object"}), 400

    scan_id    = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + "Z"

    db.create_scan(scan_id, target_url, scan_type, vuln_classes, created_at)
    threading.Thread(
        target=run_scan, args=(scan_id, vuln_classes, target_url, auth), daemon=True
    ).start()

    return jsonify({
        "scan_id":     scan_id,
        "message":     "Scan started successfully",
        "status_url":  f"/api/scan/{scan_id}/status",
        "results_url": f"/api/scan/{scan_id}/results",
    }), 202


@app.route("/api/scan/<scan_id>/status", methods=["GET"])
def scan_status(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404
    return jsonify({
        "id":              scan["id"],
        "target_url":      scan["target_url"],
        "scan_type":       scan["scan_type"],
        "vuln_classes":    scan["vuln_classes"],
        "status":          scan["status"],
        "progress":        scan["progress"],
        "current_step":    scan["current_step"],
        "findings_so_far": db.count_findings(scan_id),
        "created_at":      scan["created_at"],
        "completed_at":    scan["completed_at"],
    }), 200


@app.route("/api/scan/<scan_id>/results", methods=["GET"])
def scan_results(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404
    findings = db.get_findings(scan_id)
    stats    = db.get_findings_stats(scan_id)
    return jsonify({
        "id":           scan["id"],
        "target_url":   scan["target_url"],
        "status":       scan["status"],
        "progress":     scan["progress"],
        "created_at":   scan["created_at"],
        "completed_at": scan["completed_at"],
        "findings":     findings,
        "stats":        stats,
        "crawl_summary": {
            "forms":      scan.get("forms_crawled", 0),
            "get_params": scan.get("get_params_found", 0),
        },
    }), 200


@app.route("/api/scan/<scan_id>/cancel", methods=["POST"])
def cancel_scan(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404
    if scan["status"] in ("completed", "failed", "cancelled"):
        return jsonify({
            "message": f"Scan already in terminal state: {scan['status']}",
            "status":  scan["status"],
        }), 200
    # Signal the running thread to stop at its next checkpoint
    _get_cancel_event(scan_id).set()
    # Write cancelled status to DB immediately
    db.cancel_scan_db(scan_id, datetime.utcnow().isoformat() + "Z")
    _emit_scan_event(scan_id)
    return jsonify({"id": scan_id, "status": "cancelled", "message": "Scan cancellation requested."}), 200


@app.route("/api/scans", methods=["GET"])
def list_scans():
    try:
        scans = db.get_all_scans()
        return jsonify({"scans": scans, "total": len(scans)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    return jsonify(db.get_dashboard_stats()), 200


@app.route("/api/reports", methods=["GET"])
def list_reports():
    reports = db.get_all_reports()
    return jsonify({"reports": reports, "total": len(reports)}), 200


@app.route("/api/report/<scan_id>/pdf", methods=["GET"])
def download_report(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404
    if scan["status"] != "completed":
        return jsonify({"error": "Report only available for completed scans.", "status": scan["status"]}), 400
    try:
        findings = db.get_findings(scan_id)
        stats    = db.get_findings_stats(scan_id)
        pdf_path = generate_pdf_report(
            {**scan, "findings": findings, "stats": stats},
            output_dir="reports",
        )
        db.save_report(scan_id, pdf_path)
        return send_file(pdf_path, mimetype="application/pdf", as_attachment=True,
                         download_name=f"smartfuzz_report_{scan_id[:8]}.pdf")
    except Exception as e:
        return jsonify({"error": f"Failed to generate report: {str(e)}"}), 500


@app.route("/api/benchmark", methods=["GET"])
def benchmark_stats():
    return jsonify(db.get_benchmark_stats()), 200


if __name__ == "__main__":
    import os
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"

    print(f"Database: {db.DB_PATH}")

    if debug:
        # ── Dev: Flask + SocketIO via Werkzeug, with auto-reload ──
        print(f"[dev] SmartFuzz backend (Flask dev server) on http://localhost:{port}")
        socketio.run(app, host="0.0.0.0", port=port,
                     debug=True, allow_unsafe_werkzeug=True)
    else:
        # ── Prod: SocketIO's production server ──
        # NOTE: Waitress can't serve WebSocket traffic, so we cannot use
        # `waitress.serve(app, ...)` here. flask-socketio in threading mode
        # uses Werkzeug's threaded server underneath when production-grade
        # async libs aren't installed — for true production, install eventlet
        # (already in requirements.txt) so SocketIO picks it up automatically.
        print(f"[prod] SmartFuzz backend (SocketIO production server) on http://0.0.0.0:{port}")
        socketio.run(app, host="0.0.0.0", port=port,
                     debug=False, allow_unsafe_werkzeug=True)