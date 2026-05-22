"""
crawler.py — SmartFuzz Playwright-based Crawler (with requests fallback)
========================================================================

Primary path
------------
Uses Playwright (headless Chromium) to:
  - Execute JavaScript so SPAs (React / Angular / Vue) render their real DOM.
  - Capture forms from the live DOM, not raw HTML.
  - Observe XHR / fetch URLs the page issues — these are extra GET param sets
    the old requests-based crawler couldn't see.
  - Optionally log in via injected cookies, extra HTTP headers, or by
    filling and submitting a login form before BFS.

Fallback path
-------------
If `playwright` is not importable, or chromium isn't usable at runtime,
falls back transparently to the legacy `requests` + `BeautifulSoup` logic.
Fallback works on static HTML only.

Setup
-----
After `pip install -r requirements.txt`, run ONCE:

    playwright install chromium

(Downloads ~150MB. One-time per environment.)
"""

import logging
import time
from collections import deque
from urllib.parse import urlparse, urljoin, parse_qs

import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("smartfuzz.crawler")

# ── Playwright availability check ─────────────────────────────────────────────

try:
    from playwright.sync_api import sync_playwright
    from playwright.sync_api import TimeoutError as PWTimeoutError
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False
    PWTimeoutError = Exception  # type: ignore
    logger.warning(
        "[Crawler] Playwright not installed — JavaScript rendering and login "
        "support are disabled. Falling back to requests-based crawling."
    )


# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}
TIMEOUT = 10                  # seconds per requests-fallback request
PAGE_TIMEOUT_MS = 15_000      # Playwright per-page nav timeout
NETWORKIDLE_MS = 2_500        # cap waiting for networkidle. Kept short on purpose:
                              # the DOM (forms + links) is already present after
                              # domcontentloaded, so this is just a brief window to
                              # catch late XHR param sets. Heavy sites never reach
                              # true idle, so a long cap only wasted time.
TOTAL_BUDGET_S = 180          # 3-minute hard cap on the whole crawl


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def crawl(
    target_url: str,
    max_pages: int = 6,
    *,
    auth_cookies: list[dict] | None = None,
    auth_headers: dict[str, str] | None = None,
    login_url: str | None = None,
    login_username: str | None = None,
    login_password: str | None = None,
    login_username_field: str = "username",
    login_password_field: str = "password",
) -> dict:
    """
    BFS-crawl `target_url`, returning forms / GET param sets / metadata.

    Auth precedence (only one is needed):
      1. `auth_cookies`  → injected into browser context before navigating
      2. `auth_headers`  → applied as extra HTTP headers
      3. `login_url` + creds → form-fill login submitted before BFS

    Falls back to a static `requests`-based crawler if Playwright is
    unavailable. Fallback does NOT honour auth_cookies / login form; in
    that case auth_headers is still applied via requests.
    """
    auth_provided = bool(auth_cookies or auth_headers or login_url)

    if _PLAYWRIGHT_AVAILABLE:
        try:
            return _crawl_with_playwright(
                target_url,
                max_pages,
                auth_cookies=auth_cookies,
                auth_headers=auth_headers,
                login_url=login_url,
                login_username=login_username,
                login_password=login_password,
                login_username_field=login_username_field,
                login_password_field=login_password_field,
            )
        except Exception as e:
            logger.warning(
                f"[Crawler] Playwright crawl failed ({type(e).__name__}: {e}). "
                f"Falling back to requests-based crawler."
            )
            if auth_provided:
                logger.warning(
                    "[Crawler] Auth was provided but Playwright failed — "
                    "fallback will only honour auth_headers, not cookies/login."
                )
    else:
        if auth_provided:
            logger.warning(
                "[Crawler] Auth was provided but Playwright is unavailable — "
                "fallback will only honour auth_headers, not cookies/login."
            )

    return _crawl_with_requests(target_url, max_pages, auth_headers=auth_headers)


# ─────────────────────────────────────────────────────────────────────────────
# Playwright implementation
# ─────────────────────────────────────────────────────────────────────────────

def _crawl_with_playwright(
    target_url: str,
    max_pages: int,
    *,
    auth_cookies: list[dict] | None,
    auth_headers: dict[str, str] | None,
    login_url: str | None,
    login_username: str | None,
    login_password: str | None,
    login_username_field: str,
    login_password_field: str,
) -> dict:
    result = _empty_result(target_url)

    visited: set[str] = set()
    queue: deque[str] = deque([target_url])
    seen_form_keys: set[str] = set()
    seen_param_keys: set[str] = set()

    start_ts = time.monotonic()

    def _budget_exceeded() -> bool:
        return (time.monotonic() - start_ts) > TOTAL_BUDGET_S

    def _block_static_resources(route):
        try:
            if route.request.resource_type in ("image", "font", "media", "stylesheet"):
                route.abort()
            else:
                route.continue_()
        except Exception:
            try:
                route.continue_()
            except Exception:
                pass

    def _record_param_url(rec_url: str):
        """Add a same-domain URL-with-query to result['get_params'] if new."""
        try:
            parsed = urlparse(rec_url)
            if not parsed.query:
                return
            if not _is_same_domain(rec_url, target_url):
                return
            base_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base_path in seen_param_keys:
                return
            seen_param_keys.add(base_path)
            params = parse_qs(parsed.query, keep_blank_values=True)
            flat = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
            result["get_params"].append({
                "url": rec_url,
                "base_url": base_path,
                "params": flat,
            })
        except Exception:
            pass

    with sync_playwright() as pw:
        browser = None
        context = None
        try:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=DEFAULT_HEADERS["User-Agent"],
                ignore_https_errors=True,
            )

            # Auth: cookies
            if auth_cookies:
                try:
                    context.add_cookies(auth_cookies)
                    logger.info(f"[Crawler] Injected {len(auth_cookies)} auth cookie(s).")
                except Exception as e:
                    logger.warning(f"[Crawler] Failed to inject auth cookies: {e}")

            # Auth: extra headers
            if auth_headers:
                try:
                    context.set_extra_http_headers(auth_headers)
                    logger.info(f"[Crawler] Set {len(auth_headers)} auth header(s).")
                except Exception as e:
                    logger.warning(f"[Crawler] Failed to set auth headers: {e}")

            # Skip heavy static assets to speed crawl up
            context.route("**/*", _block_static_resources)

            page = context.new_page()
            page.set_default_timeout(PAGE_TIMEOUT_MS)

            # Capture XHR/fetch URLs that include query strings as
            # extra GET param sets — the big win over the static crawler.
            def _on_request(request):
                try:
                    if request.resource_type in ("xhr", "fetch"):
                        _record_param_url(request.url)
                except Exception:
                    pass
            page.on("request", _on_request)

            # ── Optional form-fill login ─────────────────────────────────────
            if login_url and login_username and login_password:
                try:
                    logger.info(f"[Crawler] Performing form-fill login via {login_url}")
                    page.goto(login_url, wait_until="domcontentloaded",
                              timeout=PAGE_TIMEOUT_MS)
                    page.fill(f"[name='{login_username_field}']", login_username)
                    page.fill(f"[name='{login_password_field}']", login_password)
                    page.press(f"[name='{login_password_field}']", "Enter")
                    try:
                        page.wait_for_load_state("networkidle",
                                                 timeout=NETWORKIDLE_MS)
                    except PWTimeoutError:
                        pass
                    logger.info("[Crawler] Login submitted.")
                except Exception as e:
                    logger.warning(f"[Crawler] Login attempt failed: {e}")

            # ── BFS ──────────────────────────────────────────────────────────
            while queue and len(visited) < max_pages:
                if _budget_exceeded():
                    logger.warning("[Crawler] Total scan budget exceeded; stopping.")
                    break

                url = queue.popleft()
                if url in visited:
                    continue
                visited.add(url)

                logger.info(f"[Crawler] Visiting ({len(visited)}/{max_pages}): {url}")
                response = None
                try:
                    response = page.goto(url, wait_until="domcontentloaded",
                                         timeout=PAGE_TIMEOUT_MS)
                    try:
                        page.wait_for_load_state("networkidle",
                                                 timeout=NETWORKIDLE_MS)
                    except PWTimeoutError:
                        pass  # networkidle never reached — proceed anyway
                except PWTimeoutError:
                    if len(visited) == 1:
                        result["error"] = (
                            f"Initial page navigation timed out after "
                            f"{PAGE_TIMEOUT_MS}ms."
                        )
                        return result
                    continue
                except Exception as e:
                    if len(visited) == 1:
                        result["error"] = f"Failed to load {url}: {e}"
                        return result
                    continue

                # First page → set global metadata
                if len(visited) == 1:
                    result["reachable"] = True
                    if response is not None:
                        try:
                            result["status_code"] = response.status
                        except Exception:
                            pass
                        try:
                            result["headers_observed"] = dict(response.headers)
                        except Exception:
                            pass
                    try:
                        cookies = context.cookies()
                        result["cookies_observed"] = {
                            c.get("name", ""): c.get("value", "") for c in cookies
                        }
                    except Exception:
                        pass

                if not result["page_title"]:
                    try:
                        result["page_title"] = (page.title() or "").strip()
                    except Exception:
                        pass

                # ── Extract forms from live DOM ─────────────────────────────
                try:
                    for form_el in page.query_selector_all("form"):
                        form_data = _extract_form_from_handle(form_el, url)
                        dedup_key = f"{form_data['method']}:{form_data['action']}"
                        if dedup_key not in seen_form_keys:
                            seen_form_keys.add(dedup_key)
                            result["forms"].append(form_data)
                except Exception as e:
                    logger.warning(f"[Crawler] Form extraction failed at {url}: {e}")

                # ── Extract anchor links → BFS expansion + GET param sets ──
                try:
                    anchors = page.query_selector_all("a[href]")
                    result["links_found"] += len(anchors)
                    for a in anchors:
                        try:
                            href = a.get_attribute("href")
                        except Exception:
                            continue
                        if not href:
                            continue
                        full_url = urljoin(url, href).split("#")[0]
                        if not full_url:
                            continue
                        if not _is_same_domain(full_url, target_url):
                            continue
                        _record_param_url(full_url)
                        if full_url not in visited and (len(visited) + len(queue)) < max_pages:
                            queue.append(full_url)
                except Exception as e:
                    logger.warning(f"[Crawler] Link extraction failed at {url}: {e}")

                result["pages_crawled"] = len(visited)

        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass

    logger.info(
        f"[Crawler] Playwright done. Pages: {result['pages_crawled']}, "
        f"Forms: {len(result['forms'])}, "
        f"GET param sets: {len(result['get_params'])}"
    )
    return result


def _extract_form_from_handle(form_el, base_url: str) -> dict:
    """Extract action/method/enctype/inputs from a Playwright ElementHandle."""
    try:
        action = form_el.get_attribute("action") or ""
    except Exception:
        action = ""
    try:
        method = (form_el.get_attribute("method") or "GET").upper()
    except Exception:
        method = "GET"
    try:
        enctype = (form_el.get_attribute("enctype")
                   or "application/x-www-form-urlencoded").lower()
    except Exception:
        enctype = "application/x-www-form-urlencoded"

    action = urljoin(base_url, action) if action else base_url

    inputs: list[dict] = []

    try:
        for inp in form_el.query_selector_all("input"):
            try:
                itype = (inp.get_attribute("type") or "text").lower()
                if itype in ("submit", "button", "image", "reset"):
                    continue
                inputs.append({
                    "tag":         "input",
                    "type":        itype,
                    "name":        inp.get_attribute("name") or "",
                    "value":       inp.get_attribute("value") or "",
                    "placeholder": inp.get_attribute("placeholder") or "",
                })
            except Exception:
                pass
    except Exception:
        pass

    try:
        for ta in form_el.query_selector_all("textarea"):
            try:
                inputs.append({
                    "tag":         "textarea",
                    "type":        "text",
                    "name":        ta.get_attribute("name") or "",
                    "value":       (ta.inner_text() or "").strip(),
                    "placeholder": ta.get_attribute("placeholder") or "",
                })
            except Exception:
                pass
    except Exception:
        pass

    try:
        for sel in form_el.query_selector_all("select"):
            try:
                opt_values: list[str] = []
                for o in sel.query_selector_all("option"):
                    try:
                        v = o.get_attribute("value")
                        if v is None:
                            v = (o.inner_text() or "").strip()
                        opt_values.append(v)
                    except Exception:
                        pass
                inputs.append({
                    "tag":     "select",
                    "type":    "select",
                    "name":    sel.get_attribute("name") or "",
                    "value":   opt_values[0] if opt_values else "",
                    "options": opt_values,
                })
            except Exception:
                pass
    except Exception:
        pass

    return {
        "action":            action,
        "method":            method,
        "enctype":           enctype,
        "inputs":            inputs,
        "injectable_fields": [i["name"] for i in inputs if i["name"]],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Legacy requests-based fallback
# ─────────────────────────────────────────────────────────────────────────────

def _crawl_with_requests(
    target_url: str,
    max_pages: int = 10,
    *,
    auth_headers: dict[str, str] | None = None,
) -> dict:
    result = _empty_result(target_url)

    visited:         set[str] = set()
    queue:           deque    = deque([target_url])
    seen_form_keys:  set[str] = set()
    seen_param_keys: set[str] = set()

    headers = dict(DEFAULT_HEADERS)
    if auth_headers:
        headers.update(auth_headers)

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            logger.info(f"[Crawler/fallback] Fetching ({len(visited)}/{max_pages}): {url}")
            response = requests.get(
                url, headers=headers,
                timeout=TIMEOUT, allow_redirects=True,
            )
        except requests.exceptions.ConnectionError:
            if not visited - {url}:
                result["error"] = "Connection refused — target is unreachable or offline."
                return result
            continue
        except requests.exceptions.Timeout:
            if not visited - {url}:
                result["error"] = f"Request timed out after {TIMEOUT}s."
                return result
            continue
        except Exception as e:
            if not visited - {url}:
                result["error"] = str(e)
                return result
            continue

        if len(visited) == 1:
            result["reachable"]        = True
            result["status_code"]      = response.status_code
            result["headers_observed"] = dict(response.headers)
            result["cookies_observed"] = dict(response.cookies)

        if response.status_code not in (200, 301, 302):
            continue

        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            continue

        if not result["page_title"]:
            title_tag = soup.find("title")
            if title_tag:
                result["page_title"] = title_tag.get_text(strip=True)

        for form_tag in soup.find_all("form"):
            form_data = _extract_form_from_soup(form_tag, url)
            dedup_key = f"{form_data['method']}:{form_data['action']}"
            if dedup_key not in seen_form_keys:
                seen_form_keys.add(dedup_key)
                result["forms"].append(form_data)

        links = soup.find_all("a", href=True)
        result["links_found"] += len(links)

        for link in links:
            href     = link["href"]
            full_url = urljoin(url, href)
            if not _is_same_domain(full_url, target_url):
                continue
            full_url = full_url.split("#")[0]
            if not full_url:
                continue

            parsed = urlparse(full_url)
            if parsed.query:
                base_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if base_path not in seen_param_keys:
                    seen_param_keys.add(base_path)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    flat   = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
                    result["get_params"].append({
                        "url":      full_url,
                        "base_url": base_path,
                        "params":   flat,
                    })

            if full_url not in visited and len(visited) + len(queue) < max_pages:
                queue.append(full_url)

        result["pages_crawled"] = len(visited)

    logger.info(
        f"[Crawler/fallback] Done. Pages: {result['pages_crawled']}, "
        f"Forms: {len(result['forms'])}, "
        f"GET param sets: {len(result['get_params'])}"
    )
    return result


def _extract_form_from_soup(form_tag, base_url: str) -> dict:
    """Static-HTML form extraction via BeautifulSoup (legacy fallback)."""
    action  = form_tag.get("action", "")
    method  = form_tag.get("method", "get").upper()
    enctype = form_tag.get("enctype", "application/x-www-form-urlencoded").lower()
    action  = urljoin(base_url, action) if action else base_url

    inputs = []

    for inp in form_tag.find_all("input"):
        input_type = inp.get("type", "text").lower()
        if input_type in ("submit", "button", "image", "reset"):
            continue
        inputs.append({
            "tag":         "input",
            "type":        input_type,
            "name":        inp.get("name", ""),
            "value":       inp.get("value", ""),
            "placeholder": inp.get("placeholder", ""),
        })

    for ta in form_tag.find_all("textarea"):
        inputs.append({
            "tag":         "textarea",
            "type":        "text",
            "name":        ta.get("name", ""),
            "value":       ta.get_text(strip=True),
            "placeholder": ta.get("placeholder", ""),
        })

    for sel in form_tag.find_all("select"):
        options = [o.get("value", o.get_text()) for o in sel.find_all("option")]
        inputs.append({
            "tag":     "select",
            "type":    "select",
            "name":    sel.get("name", ""),
            "value":   options[0] if options else "",
            "options": options,
        })

    return {
        "action":            action,
        "method":            method,
        "enctype":           enctype,
        "inputs":            inputs,
        "injectable_fields": [i["name"] for i in inputs if i["name"]],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _empty_result(target_url: str) -> dict:
    return {
        "target_url":       target_url,
        "base_domain":      _get_base_domain(target_url),
        "reachable":        False,
        "status_code":      None,
        "page_title":       "",
        "forms":            [],
        "get_params":       [],
        "pages_crawled":    0,
        "headers_observed": {},
        "cookies_observed": {},
        "links_found":      0,
        "error":            None,
    }


def _get_base_domain(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _is_same_domain(url: str, base_url: str) -> bool:
    return urlparse(url).netloc == urlparse(base_url).netloc


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    test_url = "http://testphp.vulnweb.com"
    print(f"\n[Crawler] Smoke test against {test_url}\n")
    data = crawl(test_url, max_pages=5)
    print(f"Reachable:     {data['reachable']}")
    print(f"Pages crawled: {data['pages_crawled']}")
    print(f"Page title:    {data['page_title']}")
    print(f"Forms found:   {len(data['forms'])}")
    print(f"GET params:    {len(data['get_params'])}")
    print(f"Links found:   {data['links_found']}")
    print(f"Error:         {data['error']}")
    print(f"\nFull dump:\n{json.dumps(data, indent=2)[:2000]}")
