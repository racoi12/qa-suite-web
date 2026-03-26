"""Site scanner — runs all test categories using Playwright with full commercial features."""

import asyncio
import json
import os
import re
import time
import traceback
import hashlib
import secrets
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from playwright.async_api import async_playwright, Page, Browser
import undetected_playwright as uc

from database import get_db, save_artifact

ARTIFACTS_DIR = Path(os.getenv("ARTIFACTS_DIR", "/data/artifacts"))


# ─────────── DATACLASSES ───────────

@dataclass
class TestResult:
    category: str
    test_name: str
    status: str   # pass, fail, warn, skip, info
    severity: str  # critical, major, minor, info
    message: str
    details: dict


# ─────────── DB HELPERS ───────────

def _update_scan(scan_id: int, **kwargs):
    with get_db() as db:
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        db.execute(f"UPDATE scans SET {sets} WHERE id = ?", (*kwargs.values(), scan_id))


def _save_results(scan_id: int, results: list[TestResult]):
    with get_db() as db:
        db.executemany(
            "INSERT INTO results (scan_id, category, test_name, status, severity, message, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, r.category, r.test_name, r.status, r.severity, r.message, json.dumps(r.details)) for r in results],
        )


# ─────────── SCREENSHOT UTILITY ───────────

async def _screenshot_page(page: Page, path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(path), full_page=True, type="png")
        return True
    except Exception:
        return False


# ─────────── TEST MODULES ───────────

async def test_smoke(page: Page, url: str) -> list[TestResult]:
    results = []
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        status = resp.status if resp else 0
        results.append(TestResult("smoke", "Page loads", "pass" if 200 <= status < 400 else "fail",
                                  "critical", f"HTTP {status}", {"status_code": status}))

        is_https = url.startswith("https://") or (resp and resp.url.startswith("https://"))
        results.append(TestResult("smoke", "HTTPS enabled", "pass" if is_https else "warn",
                                  "major", "Site uses HTTPS" if is_https else "Site does not use HTTPS", {}))

        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        await page.wait_for_timeout(2000)
        results.append(TestResult("smoke", "No JS errors", "pass" if not errors else "warn",
                                  "minor", f"{len(errors)} JS error(s)" if errors else "Clean console",
                                  {"errors": errors[:5]}))

        title = await page.title()
        results.append(TestResult("smoke", "Page has title", "pass" if title else "fail",
                                  "major", title or "No title found", {"title": title}))
    except Exception as e:
        results.append(TestResult("smoke", "Page loads", "fail", "critical", str(e), {}))
    return results


async def test_security(page: Page, url: str) -> list[TestResult]:
    results = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            resp = await client.get(url)
            headers = dict(resp.headers)

        checks = [
            ("strict-transport-security", "HSTS header", "major"),
            ("x-frame-options", "Clickjacking protection", "major"),
            ("x-content-type-options", "MIME sniffing protection", "minor"),
            ("content-security-policy", "Content Security Policy", "major"),
            ("referrer-policy", "Referrer Policy", "minor"),
            ("permissions-policy", "Permissions Policy", "minor"),
        ]
        for header, name, severity in checks:
            present = header in headers
            results.append(TestResult("security", name,
                                      "pass" if present else "fail", severity,
                                      f"{header}: {headers[header][:80]}" if present else f"Missing {header}",
                                      {"header": header, "value": headers.get(header, "")}))

        # X-Powered-By information disclosure
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            results.append(TestResult("security", "X-Powered-By disclosure",
                                      "fail", "major",
                                      f"Exposes: {powered_by}",
                                      {"header": "x-powered-by", "value": powered_by}))
        else:
            results.append(TestResult("security", "X-Powered-By disclosure",
                                      "pass", "major", "Not exposed", {}))

        # Server header version disclosure
        server = headers.get("server", "")
        has_version = bool(re.search(r'\d+\.\d+', server))
        if has_version:
            results.append(TestResult("security", "Server version disclosure",
                                      "warn", "minor",
                                      f"Server header exposes version: {server}",
                                      {"header": "server", "value": server}))

        parsed = urlparse(url)
        if parsed.scheme == "https":
            http_url = url.replace("https://", "http://", 1)
            try:
                r2 = await client.get(http_url, follow_redirects=False)
                redirects = 300 <= r2.status_code < 400
                results.append(TestResult("security", "HTTP→HTTPS redirect", "pass" if redirects else "warn",
                                          "major", "Redirects to HTTPS" if redirects else "No redirect",
                                          {"status": r2.status_code}))
            except Exception:
                results.append(TestResult("security", "HTTP→HTTPS redirect", "skip", "info", "Could not test", {}))
    except Exception as e:
        results.append(TestResult("security", "Security scan", "fail", "critical", str(e), {}))
    return results


async def test_seo(page: Page, url: str) -> list[TestResult]:
    results = []
    try:
        await page.goto(url, wait_until="networkidle", timeout=25000)

        desc = await page.evaluate("document.querySelector('meta[name=\"description\"]')?.content || ''")
        results.append(TestResult("seo", "Meta description",
                                  "pass" if len(desc) >= 50 else ("warn" if desc else "fail"),
                                  "major", desc[:120] if desc else "No meta description",
                                  {"length": len(desc), "content": desc[:200]}))

        og_title = await page.evaluate("document.querySelector('meta[property=\"og:title\"]')?.content || ''")
        og_img = await page.evaluate("document.querySelector('meta[property=\"og:image\"]')?.content || ''")
        twitter_card = await page.evaluate("document.querySelector('meta[name=\"twitter:card\"]')?.content || ''")
        has_og = bool(og_title and og_img)
        results.append(TestResult("seo", "Open Graph tags", "pass" if has_og else "warn",
                                  "minor", f"og:title={bool(og_title)}, og:image={bool(og_img)}",
                                  {"og_title": og_title, "og_image": og_img}))
        results.append(TestResult("seo", "Twitter Card tags", "pass" if twitter_card else "warn",
                                  "minor", twitter_card or "No Twitter Card tag",
                                  {"twitter_card": twitter_card}))

        canonical = await page.evaluate("document.querySelector('link[rel=\"canonical\"]')?.href || ''")
        results.append(TestResult("seo", "Canonical URL", "pass" if canonical else "warn",
                                  "minor", canonical or "No canonical tag",
                                  {"canonical": canonical}))

        h1 = await page.evaluate("document.querySelector('h1')?.textContent?.trim() || ''")
        results.append(TestResult("seo", "H1 heading", "pass" if h1 else "fail",
                                  "major", h1[:100] if h1 else "No H1 found", {"h1": h1[:200] if h1 else ""}))

        # Schema.org JSON-LD
        schema = await page.evaluate("""
            () => {
                const el = document.querySelector('script[type=\"application/ld+json\"]');
                if (!el) return null;
                try { return JSON.parse(el.textContent); } catch { return null; }
            }
        """)
        has_schema = schema is not None
        results.append(TestResult("seo", "Schema.org JSON-LD", "pass" if has_schema else "warn",
                                  "minor", "Found" if has_schema else "No JSON-LD schema found", {}))

        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for path in ["/sitemap.xml", "/robots.txt"]:
                try:
                    r = await client.get(urljoin(url, path))
                    ok = r.status_code == 200 and len(r.text) > 10
                    name = "sitemap.xml" if path == "/sitemap.xml" else "robots.txt"
                    results.append(TestResult("seo", name, "pass" if ok else "warn",
                                              "minor", "Found" if ok else "Not found", {}))
                except Exception:
                    results.append(TestResult("seo", name, "skip", "info", "Could not test", {}))

        missing_alt = await page.evaluate("""
            Array.from(document.querySelectorAll('img'))
                .filter(i => !i.alt && i.src && i.naturalWidth > 50)
                .map(i => i.src.substring(0, 80))
        """)
        results.append(TestResult("seo", "Image alt attributes",
                                  "pass" if not missing_alt else "warn", "minor",
                                  f"{len(missing_alt)} image(s) missing alt text" if missing_alt else "All images have alt text",
                                  {"missing": missing_alt[:10]}))
    except Exception as e:
        results.append(TestResult("seo", "SEO scan", "fail", "critical", str(e), {}))
    return results


async def test_accessibility(page: Page, url: str) -> list[TestResult]:
    results = []
    try:
        await page.goto(url, wait_until="networkidle", timeout=25000)

        axe_results = await page.evaluate("""async () => {
            await new Promise((resolve, reject) => {
                if (window.axe) return resolve();
                const s = document.createElement('script');
                s.src = 'https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.9.1/axe.min.js';
                s.onload = resolve; s.onerror = reject;
                document.head.appendChild(s);
            });
            const r = await axe.run(document, {
                runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] }
            });
            return {
                violations: r.violations.map(v => ({id: v.id, impact: v.impact, description: v.description, nodes: v.nodes.length, help: v.helpUrl})),
                passes: r.passes.length, incomplete: r.incomplete.length
            };
        }""")

        violations = axe_results.get("violations", [])
        critical = [v for v in violations if v["impact"] in ("critical", "serious")]
        moderate = [v for v in violations if v["impact"] == "moderate"]
        minor = [v for v in violations if v["impact"] == "minor"]

        if not violations:
            results.append(TestResult("accessibility", "WCAG 2.1 AA compliance", "pass", "info",
                                      f"{axe_results['passes']} checks passed, 0 violations", axe_results))
        else:
            for v in violations[:15]:
                sev = "critical" if v["impact"] in ("critical", "serious") else "minor"
                results.append(TestResult("accessibility", v["id"],
                                          "fail" if sev == "critical" else "warn", sev,
                                          f"{v['description']} ({v['nodes']} element(s))",
                                          {"help": v["help"], "impact": v["impact"]}))

        results.append(TestResult("accessibility", "Accessibility summary", "info", "info",
                                  f"Passed: {axe_results['passes']}, Violations: {len(violations)} "
                                  f"(critical/serious: {len(critical)}, moderate: {len(moderate)}, minor: {len(minor)})",
                                  axe_results))
    except Exception as e:
        results.append(TestResult("accessibility", "Accessibility scan", "fail", "critical", str(e), {}))
    return results


async def test_performance(page: Page, url: str) -> list[TestResult]:
    results = []
    try:
        start = time.time()
        await page.goto(url, wait_until="networkidle", timeout=30000)
        load_time_ms = int((time.time() - start) * 1000)

        results.append(TestResult("performance", "Page load time",
                                  "pass" if load_time_ms < 3000 else ("warn" if load_time_ms < 6000 else "fail"),
                                  "major", f"{load_time_ms}ms", {"load_time_ms": load_time_ms}))

        metrics = await page.evaluate("""() => {
            const nav = performance.getEntriesByType('navigation')[0] || {};
            const paint = performance.getEntriesByType('paint');
            const fcp = paint.find(p => p.name === 'first-contentful-paint');
            const entries = performance.getEntriesByType('largestContentfulPaint') || [];
            const lcp = entries.length ? Math.max(...entries.map(e => e.startTime)) : 0;
            const cls = (() => {
                let cls = 0;
                const obs = new PerformanceObserver(list => {
                    for (const entry of list.getEntries())
                        if (!entry.hadRecentInput) cls += entry.value;
                });
                obs.observe({ type: 'layout-shift', buffered: true });
                return cls;
            })();
            return {
                dom_interactive: Math.round(nav.domInteractive || 0),
                dom_complete: Math.round(nav.domComplete || 0),
                transfer_size: Math.round(nav.transferSize || 0),
                fcp: Math.round(fcp?.startTime || 0),
                lcp: Math.round(lcp),
                cls: Math.round(cls * 1000) / 1000,
            };
        }""")

        # Reload for LCP/CLS after networkidle settles
        await page.wait_for_timeout(2000)
        metrics2 = await page.evaluate("""() => {
            const entries = performance.getEntriesByType('largestContentfulPaint') || [];
            const lcp = entries.length ? Math.max(...entries.map(e => e.startTime)) : 0;
            let cls = 0;
            const obs = new PerformanceObserver(list => {
                for (const entry of list.getEntries())
                    if (!entry.hadRecentInput) cls += entry.value;
            });
            obs.observe({ type: 'layout-shift', buffered: true });
            setTimeout(() => obs.disconnect(), 2000);
            return { lcp: Math.round(lcp), cls: Math.round(cls * 1000) / 1000 };
        }""")

        fcp = metrics.get("fcp", 0)
        if fcp > 0:
            results.append(TestResult("performance", "First Contentful Paint",
                                      "pass" if fcp < 1800 else ("warn" if fcp < 3000 else "fail"),
                                      "major", f"{fcp}ms", {"fcp_ms": fcp}))

        lcp = metrics2.get("lcp", 0)
        if lcp > 0:
            results.append(TestResult("performance", "Largest Contentful Paint",
                                      "pass" if lcp < 2500 else ("warn" if lcp < 4000 else "fail"),
                                      "major", f"{lcp}ms", {"lcp_ms": lcp}))

        cls_val = metrics2.get("cls", 0) or metrics.get("cls", 0)
        results.append(TestResult("performance", "Cumulative Layout Shift",
                                  "pass" if cls_val < 0.1 else ("warn" if cls_val < 0.25 else "fail"),
                                  "minor", f"CLS: {cls_val}", {"cls": cls_val}))

        total_kb = metrics.get("transfer_size", 0) / 1024
        results.append(TestResult("performance", "Total resource size",
                                  "pass" if total_kb < 2000 else ("warn" if total_kb < 5000 else "fail"),
                                  "minor", f"{total_kb:.0f} KB", metrics))
    except Exception as e:
        results.append(TestResult("performance", "Performance scan", "fail", "critical", str(e), {}))
    return results


async def test_responsive(page: Page, url: str, viewports: list = None) -> list[TestResult]:
    results = []
    # Normalize: accept [{"name","width","height"}] or [("name", width, height)]
    if viewports:
        normalized = []
        for v in viewports:
            if isinstance(v, dict):
                normalized.append((v["name"], int(v["width"]), int(v["height"])))
            else:
                normalized.append((str(v[0]), int(v[1]), int(v[2])))
        viewports = normalized
    else:
        viewports = [
            ("Mobile S", 320, 568), ("Mobile L", 430, 932),
            ("Tablet", 768, 1024), ("Desktop", 1280, 800), ("Wide", 1920, 1080),
        ]
    try:
        for name, w, h in viewports:
            await page.set_viewport_size({"width": w, "height": h})
            await page.goto(url, wait_until="networkidle", timeout=15000)
            overflow = await page.evaluate("document.documentElement.scrollWidth > window.innerWidth")
            overflow_x = await page.evaluate(
                "Array.from(document.querySelectorAll('*')).some(el => {"
                "const r = el.getBoundingClientRect(); return r.right > window.innerWidth && r.left < window.innerWidth; })"
            )
            results.append(TestResult("responsive", f"No overflow at {name} ({w}px)",
                                      "pass" if not (overflow or overflow_x) else "fail", "major",
                                      "No horizontal overflow" if not (overflow or overflow_x)
                                      else f"Content overflows at {w}px",
                                      {"viewport": name, "width": w}))
    except Exception as e:
        results.append(TestResult("responsive", "Responsive scan", "fail", "critical", str(e), {}))
    return results


async def test_links(page: Page, url: str, max_pages: int = 15) -> list[TestResult]:
    results = []
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
        links = await page.evaluate("""() =>
            [...new Set(Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(h => h && !h.startsWith('javascript') && !h.startsWith('mailto') && !h.startsWith('tel')))]
        """)
        parsed_base = urlparse(url)
        internal = [l for l in links if urlparse(l).netloc == parsed_base.netloc][:max_pages]
        external = [l for l in links if urlparse(l).netloc != parsed_base.netloc and urlparse(l).scheme in ("http", "https")][:20]

        broken = []
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for link in internal + external:
                try:
                    r = await client.head(link)
                    if r.status_code >= 400:
                        r = await client.get(link)
                    if r.status_code >= 400:
                        broken.append({"url": link, "status": r.status_code})
                except Exception as e:
                    broken.append({"url": link, "status": 0, "error": str(e)[:80]})

        int_broken = [b for b in broken if urlparse(b["url"]).netloc == parsed_base.netloc]
        ext_broken = [b for b in broken if urlparse(b["url"]).netloc != parsed_base.netloc]
        results.append(TestResult("links", "Internal links",
                                  "pass" if not int_broken else "fail", "major",
                                  f"Checked {len(internal)} internal links, {len(int_broken)} broken",
                                  {"checked": len(internal), "broken": [b["url"] for b in int_broken[:10]]}))
        results.append(TestResult("links", "External links",
                                  "pass" if not ext_broken else "warn", "minor",
                                  f"Checked {len(external)} external links, {len(ext_broken)} broken",
                                  {"checked": len(external), "broken": [b["url"] for b in ext_broken[:10]]}))

        for b in broken[:10]:
            results.append(TestResult("links", f"Broken: {b['url'][:60]}", "fail", "major",
                                      f"Status {b['status']}", b))
    except Exception as e:
        results.append(TestResult("links", "Link scan", "fail", "critical", str(e), {}))
    return results


async def test_images(page: Page, url: str) -> list[TestResult]:
    results = []
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
        broken = await page.evaluate("""() =>
            Array.from(document.querySelectorAll('img'))
                .filter(i => i.src && (!i.complete || i.naturalWidth === 0))
                .map(i => ({ src: i.src.substring(0, 120), alt: i.alt || '' }))
        """)
        results.append(TestResult("images", "Broken images",
                                  "pass" if not broken else "fail", "major",
                                  f"{len(broken)} broken image(s)" if broken else "All images load",
                                  {"broken": broken[:10]}))

        large = await page.evaluate("""() =>
            Array.from(document.querySelectorAll('img'))
                .filter(i => i.naturalWidth > 2000 || i.naturalHeight > 2000)
                .map(i => ({ src: i.src.substring(0, 80), w: i.naturalWidth, h: i.naturalHeight }))
        """)
        if large:
            results.append(TestResult("images", "Oversized images", "warn", "minor",
                                      f"{len(large)} image(s) over 2000px", {"images": large[:5]}))
    except Exception as e:
        results.append(TestResult("images", "Image scan", "fail", "critical", str(e), {}))
    return results


async def test_content(page: Page, url: str) -> list[TestResult]:
    results = []
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
        text = await page.evaluate("() => document.body.innerText")
        lower_text = text.lower()

        has_contact = bool(
            re.search(r'contact', lower_text) or
            re.search(r'\d{3}[-.\s]\d{3}[-.\s]\d{4}', text) or
            re.search(r'[a-z0-9.]+@[a-z]+\.[a-z]{2,}', text)
        )
        results.append(TestResult("content", "Contact information",
                                  "pass" if has_contact else "fail", "major",
                                  "Found" if has_contact else "No phone, email, or contact section", {}))

        tos_links = await page.locator('a').filter(has_text=re.compile(r'terms|tos|conditions', re.I)).count()
        priv_links = await page.locator('a').filter(has_text=re.compile(r'privacy|policy', re.I)).count()
        results.append(TestResult("content", "Terms & Privacy Policy",
                                  "pass" if (tos_links + priv_links) else "fail", "major",
                                  f"Found {tos_links} terms, {priv_links} privacy links"
                                  if (tos_links + priv_links) else "No terms or privacy policy", {}))

        hipaa_found = 'hipaa' in lower_text
        results.append(TestResult("content", "HIPAA compliance reference",
                                  "pass" if hipaa_found else "warn", "major",
                                  "Found" if hipaa_found else "HIPAA not mentioned — critical for health sites", {}))

        disclaimer_patterns = [
            r'not a substitute for.*medical', r'consult.*physician', r'not medical advice',
            r'individual results may vary', r'see.*physician.*before',
        ]
        has_disclaimer = any(re.search(p, lower_text, re.I) for p in disclaimer_patterns)
        results.append(TestResult("content", "Medical disclaimer",
                                  "pass" if has_disclaimer else "warn", "major",
                                  "Found" if has_disclaimer else "No medical disclaimer found", {}))

        has_reviews = bool(
            re.search(r'review|testimonial|\d+\s*stars?|rated', lower_text) or
            await page.locator('[class*="review"], [class*="testimonial"]').count() > 0
        )
        results.append(TestResult("content", "Testimonials / Reviews",
                                  "pass" if has_reviews else "warn", "minor",
                                  "Found" if has_reviews else "No testimonials or review section", {}))

        has_clinician = bool(
            re.search(r'clinician|doctor|physician|md|provider', lower_text) or
            await page.locator('a').filter(has_text=re.compile(r'team|about.*doctor', re.I)).count() > 0
        )
        results.append(TestResult("content", "Clinician / Doctor info",
                                  "pass" if has_clinician else "warn", "major",
                                  "Found" if has_clinician else "No clinical team or doctor info", {}))

        # Third-party scripts
        scripts = []
        def on_request(req):
            h = urlparse(req.url).hostname
            if req.resource_type == "script" and h and h != parsed.netloc:
                scripts.append(h)
        page.on("request", on_request)
        await page.reload(wait_until="networkidle", timeout=15000)

        third_party = list({s: s for s in scripts if s and s not in ['googletagmanager.com', 'google-analytics.com', 'gtag', 'analytics']}.values())
        if third_party:
            results.append(TestResult("content", "Third-party scripts",
                                      "warn", "minor",
                                      f"{len(third_party)} third-party script(s): {', '.join(third_party[:5])}",
                                      {"scripts": third_party[:10]}))

        if any('hotjar' in s for s in scripts):
            results.append(TestResult("content", "HOTJAR DETECTED — HIPAA RISK",
                                      "fail", "critical",
                                      "Hotjar on a health site may violate HIPAA. Ensure PII exclusion rules are configured.", {}))

        if re.search(r'glp-1|ozempic|semaglutide|wegovy', lower_text):
            has_disclosure = any(re.search(p, lower_text) for p in [r'off.label', r'fda.approved', r'consult.*physician', r'prescription'])
            results.append(TestResult("content", "GLP-1 / Off-label disclosure",
                                      "pass" if has_disclosure else "fail", "critical",
                                      "Disclosure found" if has_disclosure else "GLP-1 mentioned without FDA/off-label disclosure", {}))
    except Exception as e:
        results.append(TestResult("content", "Content scan", "fail", "critical", str(e), {}))
    return results


async def test_faces(page: Page, url: str, api_url: str, api_token: str = "") -> list[TestResult]:
    results = []
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
        await page.wait_for_timeout(2000)

        # Scroll to trigger lazy loading
        await page.evaluate("""() => {
            return new Promise(resolve => {
                let scrolled = 0;
                const step = window.innerHeight * 0.6;
                const iv = setInterval(() => {
                    window.scrollBy(0, step);
                    scrolled += step;
                    if (scrolled >= document.body.scrollHeight) { window.scrollTo(0, 0); clearInterval(iv); resolve(); }
                }, 200);
            });
        }""")

        images = await page.evaluate("""() => {
            const prioritySel = [
                '[class*="team"] img', '[class*="profile"] img', '[class*="hero"] img',
                '[class*="doctor"] img', '[class*="staff"] img', '[class*="person"] img',
                '[data-testid*="face"] img', 'article img',
            ];
            const priority = [];
            const seen = new Set();
            for (const sel of prioritySel) {
                for (const el of document.querySelectorAll(sel)) {
                    const img = el.tagName === 'IMG' ? el : el.querySelector('img');
                    if (img && img.src && !seen.has(img.src)) {
                        seen.add(img.src);
                        priority.push({ src: img.src, alt: img.alt || img.getAttribute('aria-label') || '', priority: true });
                    }
                }
            }
            for (const img of document.querySelectorAll('img')) {
                if (img.src && !seen.has(img.src) && (img.naturalWidth > 120 || img.naturalHeight > 120)) {
                    seen.add(img.src);
                    priority.push({ src: img.src, alt: img.alt || '', priority: false });
                }
            }
            return priority.slice(0, 40);
        }""")

        faces_found = 0
        face_scores = []
        skipped_auth = 0
        skipped_no_face = 0
        headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}

        for img in images:
            try:
                img_buffer = await page.evaluate("""async (src) => {
                    try {
                        const resp = await fetch(src);
                        if (!resp.ok) return null;
                        return await resp.blob().then(b => b.arrayBuffer());
                    } catch { return null; }
                }""", img["src"])

                if img_buffer is None:
                    continue
                img_bytes = bytes(img_buffer)
                if len(img_bytes) < 5000:
                    continue
                ct = "image/jpeg"
                if img["src"].endswith(".png"):
                    ct = "image/png"
                elif img["src"].endswith(".webp"):
                    ct = "image/webp"
                elif img["src"].endswith(".svg"):
                    continue

                async with httpx.AsyncClient(timeout=20) as client:
                    files = {"file": ("face.jpg", img_bytes, ct)}
                    api_resp = await client.post(f"{api_url}/validate-face", files=files, headers=headers)

                if api_resp.status_code == 401:
                    skipped_auth += 1
                    continue
                if api_resp.status_code != 200:
                    skipped_no_face += 1
                    continue

                data = api_resp.json()
                if data.get("error"):
                    skipped_no_face += 1
                    continue

                faces_found += 1
                score = data["score"]
                face_scores.append(score)
                status = data["status"].lower()
                label = img["alt"][:50] if img["alt"] else img["src"].split("/")[-1][:40]

                issues = []
                m = data.get("metrics", {})
                if m.get("is_cut_top"): issues.append("cut at top")
                if m.get("is_cut_bottom"): issues.append("cut at bottom")
                if not m.get("is_centered"): issues.append("off-center")

                results.append(TestResult("faces", f"Face: {label}", status,
                                          "minor" if status == "warn" else ("major" if status == "fail" else "info"),
                                          f"Score {score} — {', '.join(issues) if issues else 'Good framing'}",
                                          {**data, "image_url": img["src"][:200], "alt": img["alt"]}))
            except Exception:
                continue

        avg = sum(face_scores) / len(face_scores) if face_scores else 0
        summary_note = f" ({skipped_auth} skipped — auth required)" if skipped_auth > 0 else ""

        results.append(TestResult("faces", "Face validation summary",
                                  "pass" if avg >= 0.85 else ("warn" if avg >= 0.65 else ("fail" if faces_found else "info")),
                                  "info",
                                  f"{faces_found} faces found, avg score {avg:.2f}{summary_note}",
                                  {
                                      "faces_found": faces_found,
                                      "avg_score": round(avg, 2),
                                      "images_scanned": len(images),
                                      "skipped_no_face": skipped_no_face,
                                      "skipped_auth": skipped_auth,
                                  }))
    except Exception as e:
        results.append(TestResult("faces", "Face scan", "fail", "critical", str(e), {}))
    return results


# ─────────── EXPOSURE / OPEN ADMIN PANEL DETECTION ───────────

# Common admin and sensitive paths to probe
_ADMIN_PATHS = [
    "admin", "admin.php", "admin/", "administrator", "administrator/",
    "panel", "panel.php", "dashboard", "dashboard.php",
    "backend", "backend.php", "manage", "manage.php",
    "control", "control.php", "cpanel",
    "login", "login.php", "signin", "acceso", "acceso.php",
    "wp-admin", "wp-login.php",
    "gestionar", "gestionar.php", "administrar", "administrar.php",
]

_SENSITIVE_FILES = [
    ".env", ".git/HEAD", ".git/config",
    "config.php", "config.yml", "config.json",
    ".htpasswd", "wp-config.php", "database.yml",
    "composer.json", "package.json",
    ".DS_Store", "Thumbs.db",
    "phpinfo.php", "info.php", "test.php",
    "debug", "server-status", "server-info",
    "elmah.axd", "trace.axd",
    "backup.sql", "dump.sql", "db.sql",
]


async def test_exposure(page: Page, url: str) -> list[TestResult]:
    """Detect exposed admin panels, sensitive files, and unauthenticated endpoints."""
    results = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=8,
            headers={"User-Agent": "Mozilla/5.0 QA-Scanner/1.0"}
        ) as client:

            # ── 1. Admin panel discovery ──
            open_panels = []
            login_pages = []
            for path in _ADMIN_PATHS:
                try:
                    r = await client.get(f"{base}/{path}")
                    if r.status_code == 200:
                        body = r.text[:5000].lower()
                        content_type = r.headers.get("content-type", "")
                        if "text/html" not in content_type:
                            continue

                        # Determine if it's a login page or an open panel
                        has_login_form = any(kw in body for kw in [
                            "password", "contraseña", "login", "iniciar sesión",
                            "sign in", "log in", "autenticar",
                            'type="password"', "type='password'",
                        ])
                        has_admin_content = any(kw in body for kw in [
                            "dashboard", "panel", "admin", "usuarios",
                            "listado", "registros", "expediente", "gestión",
                            "bienvenido", "welcome", "logout", "cerrar sesión",
                            "<table", "<tr", "data-id",
                        ])

                        if has_admin_content and not has_login_form:
                            open_panels.append(path)
                        elif has_login_form:
                            login_pages.append(path)
                except Exception:
                    continue

            if open_panels:
                results.append(TestResult(
                    "exposure", "Open admin panel (NO AUTH)",
                    "fail", "critical",
                    f"Admin panel accessible without authentication: /{', /'.join(open_panels)}",
                    {"open_panels": open_panels, "count": len(open_panels)}
                ))
            else:
                results.append(TestResult(
                    "exposure", "Admin panel authentication",
                    "pass", "critical",
                    "No open admin panels found",
                    {"paths_checked": len(_ADMIN_PATHS)}
                ))

            if login_pages:
                results.append(TestResult(
                    "exposure", "Admin login pages found",
                    "info", "info",
                    f"Login pages: /{', /'.join(login_pages)}",
                    {"login_pages": login_pages}
                ))

            # ── 2. Sensitive file exposure ──
            exposed_files = []
            for path in _SENSITIVE_FILES:
                try:
                    r = await client.get(f"{base}/{path}")
                    if r.status_code == 200 and len(r.content) > 0:
                        ct = r.headers.get("content-type", "")
                        # Skip HTML error pages masquerading as 200
                        if "text/html" in ct and "<title>404" in r.text[:500].lower():
                            continue
                        exposed_files.append({
                            "path": path,
                            "size": len(r.content),
                            "content_type": ct[:60],
                        })
                except Exception:
                    continue

            if exposed_files:
                paths_str = ", ".join(f"/{f['path']}" for f in exposed_files)
                severity = "critical" if any(
                    f["path"] in (".env", ".git/HEAD", ".git/config", ".htpasswd",
                                  "wp-config.php", "backup.sql", "dump.sql", "db.sql")
                    for f in exposed_files
                ) else "major"
                results.append(TestResult(
                    "exposure", "Sensitive files exposed",
                    "fail", severity,
                    f"Publicly accessible: {paths_str}",
                    {"files": exposed_files}
                ))
            else:
                results.append(TestResult(
                    "exposure", "Sensitive files protected",
                    "pass", "major",
                    "No sensitive files exposed",
                    {"paths_checked": len(_SENSITIVE_FILES)}
                ))

            # ── 3. IDOR check on open panels ──
            if open_panels:
                for panel_path in open_panels:
                    try:
                        r = await client.get(f"{base}/{panel_path}")
                        body = r.text
                        # Look for links with sequential IDs
                        id_links = re.findall(r'(?:href|action)=["\'][^"\']*[?&]id=(\d+)', body)
                        if id_links:
                            # Try accessing a record directly
                            # Extract the URL pattern
                            id_urls = re.findall(r'(?:href|action)=["\']([^"\']*[?&]id=\d+)', body)
                            if id_urls:
                                sample_url = id_urls[0]
                                if not sample_url.startswith("http"):
                                    sample_url = f"{base}/{sample_url.lstrip('/')}"
                                r2 = await client.get(sample_url)
                                if r2.status_code == 200 and len(r2.text) > 100:
                                    results.append(TestResult(
                                        "exposure", "IDOR vulnerability (sequential IDs)",
                                        "fail", "critical",
                                        f"Records accessible via sequential IDs: {len(id_links)} records found with enumerable IDs",
                                        {"panel": panel_path, "id_count": len(id_links),
                                         "sample_pattern": re.sub(r'id=\d+', 'id=N', id_urls[0])}
                                    ))
                    except Exception:
                        continue

            # ── 4. CSRF token check on forms ──
            try:
                r = await client.get(url, follow_redirects=True)
                body = r.text.lower()
                has_form = "<form" in body and "method" in body
                if has_form:
                    has_csrf = any(kw in body for kw in [
                        "csrf", "_token", "authenticity_token",
                        "csrfmiddlewaretoken", "__requestverificationtoken",
                        "antiforgery",
                    ])
                    results.append(TestResult(
                        "exposure", "CSRF protection on forms",
                        "pass" if has_csrf else "fail",
                        "major",
                        "CSRF token found in forms" if has_csrf else "No CSRF token found — forms vulnerable to cross-site request forgery",
                        {"has_form": True, "has_csrf": has_csrf}
                    ))
            except Exception:
                pass

            # ── 5. Technology fingerprint & EOL check ──
            try:
                r = await client.get(url, follow_redirects=True)
                headers = dict(r.headers)
                powered_by = headers.get("x-powered-by", "")
                server = headers.get("server", "")

                eol_tech = []
                # Check for known EOL versions
                php_match = re.search(r'PHP/([\d.]+)', powered_by)
                if php_match:
                    major_minor = tuple(int(x) for x in php_match.group(1).split(".")[:2])
                    # PHP EOL: 5.x, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1 are all EOL
                    eol_versions = [(5,), (7, 0), (7, 1), (7, 2), (7, 3), (7, 4), (8, 0), (8, 1)]
                    if any(major_minor[:len(v)] == v for v in eol_versions):
                        eol_tech.append(f"PHP {php_match.group(1)}")

                apache_match = re.search(r'Apache/([\d.]+)', server)
                if apache_match:
                    ver = tuple(int(x) for x in apache_match.group(1).split(".")[:2])
                    if ver < (2, 4):
                        eol_tech.append(f"Apache {apache_match.group(1)}")

                if eol_tech:
                    results.append(TestResult(
                        "exposure", "End-of-life technology detected",
                        "fail", "critical",
                        f"EOL software with known vulnerabilities: {', '.join(eol_tech)}",
                        {"eol_technologies": eol_tech}
                    ))
                elif powered_by or re.search(r'\d+\.\d+', server):
                    results.append(TestResult(
                        "exposure", "Technology version exposure",
                        "warn", "minor",
                        f"Server exposes version info (potential fingerprinting target)",
                        {"powered_by": powered_by, "server": server}
                    ))
            except Exception:
                pass

            # ── 6. Form validation check ──
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                validation_info = await page.evaluate("""() => {
                    const forms = document.querySelectorAll('form');
                    const results = [];
                    forms.forEach((form, i) => {
                        const inputs = form.querySelectorAll('input, select, textarea');
                        const labeled_required = [];
                        const actual_required = [];
                        inputs.forEach(inp => {
                            const name = inp.name || inp.id || inp.type;
                            // Check if visually marked as required (text contains *)
                            const label = inp.closest('div,fieldset')?.querySelector('label');
                            if (label && label.textContent.includes('*')) {
                                labeled_required.push(name);
                            }
                            if (inp.required || inp.getAttribute('aria-required') === 'true') {
                                actual_required.push(name);
                            }
                        });
                        results.push({
                            action: form.action || '',
                            method: form.method || 'get',
                            total_inputs: inputs.length,
                            labeled_required: labeled_required,
                            actual_required: actual_required,
                            missing_required: labeled_required.filter(n => !actual_required.includes(n)),
                        });
                    });
                    return results;
                }""")

                for fi, form in enumerate(validation_info):
                    missing = form.get("missing_required", [])
                    if missing:
                        results.append(TestResult(
                            "exposure", f"Form {fi+1}: required fields not enforced",
                            "fail", "major",
                            f"{len(missing)} field(s) marked '*' but missing required attribute: {', '.join(missing[:5])}",
                            {"form_action": form["action"], "missing": missing}
                        ))
            except Exception:
                pass

    except Exception as e:
        results.append(TestResult("exposure", "Exposure scan", "fail", "critical", str(e), {}))

    if not results:
        results.append(TestResult("exposure", "Exposure scan", "pass", "info", "No issues detected", {}))
    return results


# ─────────── MODULE REGISTRY ───────────

def _get_modules(page: Page, url: str, config: dict):
    """Return list of (name, coroutine) for all enabled modules."""
    max_pages = config.get("max_pages", 15)
    modules = [
        ("smoke", test_smoke(page, url)),
        ("security", test_security(page, url)),
        ("seo", test_seo(page, url)),
        ("accessibility", test_accessibility(page, url)),
        ("performance", test_performance(page, url)),
        ("responsive", test_responsive(page, url, config.get("viewports"))),
        ("links", test_links(page, url, max_pages)),
        ("images", test_images(page, url)),
        ("content", test_content(page, url)),
        ("faces", test_faces(
            page, url,
            config.get("face_api_url", "https://faces.uat.argitic.com"),
            config.get("face_api_token", ""),
        )),
        ("exposure", test_exposure(page, url)),
    ]
    return [(name, fn) for name, fn in modules if config.get(f"{name}_enabled", True)]


# ─────────── BROWSER LAUNCHER ───────────

BROWSER_MAP = {
    "chromium": "chromium",
    "firefox": "firefox",
    "webkit": "webkit",
}


async def _launch_browser(pw, browser_name: str, headless: bool = True):
    """Launch the specified browser with anti-detection args."""
    name = BROWSER_MAP.get(browser_name, "chromium")
    stealth_args = [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-setuid-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-hang-monitor",
        "--disable-ipc-flooding-protection",
        "--disable-renderer-backgrounding",
        "--enable-features=NetworkService,NetworkServiceInProcess",
        "--force-color-profile=srgb",
        "--metrics-recording-only",
        "--no-first-run",
    ]
    browser = getattr(pw, name)
    return await browser.launch(headless=headless, args=stealth_args)


# ─────────── NETWORK BLOCKING ───────────

async def _apply_blocking(page: Page, config: dict):
    """Apply network blocking rules from config."""
    blockers = config.get("blockers", {})
    if not blockers:
        return

    patterns = []
    if blockers.get("ads"):
        patterns.extend([
            "**/*doubleclick.net/**", "**/*googlesyndication.com/**",
            "**/*googleadservices.com/**", "**/*adservice.google.com/**",
            "**/*ads/**", "**/*ad.**", "**/*banner*",
        ])
    if blockers.get("analytics"):
        patterns.extend([
            "**/*google-analytics.com/**", "**/*googletagmanager.com/**",
            "**/*gtag/**", "**/*analytics/**", "**/*segment.io/**",
            "**/*segment.com/**", "**/*mixpanel.com/**",
        ])
    if blockers.get("social"):
        patterns.extend([
            "**/*facebook.net/**", "**/*connect.facebook.net/**",
            "**/*twitter.com/widgets/**", "**/*platform.twitter.com/**",
            "**/*linkedin.com/**/insight/**", "**/*snap.licdn.com/**",
        ])
    if blockers.get("chat"):
        patterns.extend([
            "**/*intercom.io/**", "**/*intercomcdn.com/**",
            "**/*drift.com/**", "**/*tawk.to/**",
        ])

    for pattern in patterns:
        try:
            await page.route(pattern, lambda route: route.abort())
        except Exception:
            pass


# ─────────── MAIN SCAN ORCHESTRATOR ───────────

async def run_scan(scan_id: int, url: str, config: dict):
    """Run full audit suite with optional multi-browser, trace, and HAR."""
    scan_dir = ARTIFACTS_DIR / str(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)

    _update_scan(scan_id, status="running", started_at=datetime.now(timezone.utc).isoformat())
    all_results: list[TestResult] = []
    console_logs: list[dict] = []

    browsers_to_run = config.get("browsers", ["chromium"])
    enable_trace = config.get("trace_enabled", True)
    enable_har = config.get("har_enabled", True)

    try:
        async with async_playwright() as pw:
            for browser_name in browsers_to_run:
                browser = await _launch_browser(pw, browser_name)

                # Build context creation options
                har_path = str(scan_dir / f"{browser_name}_network.har") if enable_har else None

                context_options = {
                    "viewport": {"width": 1280, "height": 720},
                    "ignore_https_errors": True,
                    "locale": "en-US",
                    "timezone_id": "America/New_York",
                    "permissions": ["geolocation"],
                    "extra_http_headers": {
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    },
                }
                if enable_trace:
                    context_options["record_video_dir"] = str(scan_dir / f"{browser_name}_video")
                    context_options["record_video_size"] = {"width": 1280, "height": 720}

                context = await browser.new_context(
                    **context_options,
                    record_har_path=har_path,
                )

                # Apply stealth patches to avoid bot detection
                if browser_name == "chromium":
                    try:
                        await uc.stealth_async(context)
                    except Exception:
                        pass

                # Start tracing if enabled
                if enable_trace:
                    await context.tracing.start(
                        screenshots=True,
                        snapshots=True,
                        sources=True,
                    )

                page = await context.new_page()

                # Stealth: comprehensive anti-bot detection script
                await page.add_init_script("""
                    // Hide webdriver
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    try { delete navigator.__proto__.webdriver; } catch(e) {}

                    // Fake Chrome runtime to avoid detection
                    window.chrome = {
                        runtime: {
                            PlatformOs: {}, PlatformArch: {},
                            onInstalled: {}, onUpdateAvailable: {},
                            connect: function() {}, sendMessage: function() {},
                            id: '', getManifest: () => ({version: '120.0'}),
                            getURL: (u) => u
                        },
                        loadTimes: () => ({}),
                        csi: () => ({}),
                        app: {}
                    };

                    // Permissions API - return granted for common permissions
                    const origQuery = window.navigator.permissions ? window.navigator.permissions.query : null;
                    if (origQuery) {
                        window.navigator.permissions.query = (params) => {
                            const perm = params.name === 'notifications' ? 'default' : 'granted';
                            return Promise.resolve({state: perm, onchange: null});
                        };
                    }

                    // Make plugins look real
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [
                            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format', mimeTypes: [{type: 'application/pdf', suffixes: 'pdf'}] },
                            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '', mimeTypes: [] },
                            { name: 'Native Client', filename: 'internal-nacl-plugin', description: '', mimeTypes: [] }
                        ]
                    });

                    // Languages
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en', 'es']
                    });

                    // Hardware concurrency
                    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });

                    // Device memory
                    Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });

                    // Platform
                    Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });

                    // UA with real Chrome string
                    const ua = navigator.userAgent.replace('HeadlessChrome', 'Chrome').replace(/Headless/, '');
                    Object.defineProperty(navigator, 'userAgent', { get: () => ua });

                    // Remove automation attributes from document
                    const scr = document.createElement('script');
                    scr.textContent = `
                        if (window.cdc_adoQpoasnfa76pfcZLmcfl_Array) {
                            delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
                            delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
                            delete window.cdc_adoQpoasnfa76pfcZLmcfl_Proxy;
                        }
                    `;
                    document.documentElement.appendChild(scr);
                    document.documentElement.removeChild(scr);
                """)

                def on_console(msg):
                    if msg.type in ("error", "warning", "log"):
                        console_logs.append({
                            "type": msg.type,
                            "text": msg.text,
                            "location": dict(msg.location) if hasattr(msg, 'location') else {},
                        })

                page.on("console", on_console)

                # Apply network blocking
                await _apply_blocking(page, config)

                modules = _get_modules(page, url, config)

                # Take initial page screenshot before any tests
                try:
                    await page.goto(url, wait_until="networkidle", timeout=20000)
                except Exception:
                    pass
                initial_path = scan_dir / f"{browser_name}_initial.png"
                await _screenshot_page(page, initial_path)
                if initial_path.exists():
                    save_artifact(scan_id, f"{browser_name}_scan", "screenshot_before",
                                  initial_path.name, "image/png", initial_path.stat().st_size)

                for name, fn_coro in modules:
                    _update_scan(scan_id, progress=f"[{browser_name}] Running {name}...")

                    try:
                        module_results = await asyncio.wait_for(fn_coro, timeout=120)
                        all_results.extend(module_results)
                        _save_results(scan_id, module_results)
                    except asyncio.TimeoutError:
                        r = TestResult(name, f"{name} scan", "fail", "critical", "Timed out (120s)", {})
                        all_results.append(r)
                        _save_results(scan_id, [r])
                    except Exception as e:
                        r = TestResult(name, f"{name} scan", "fail", "critical", str(e), {})
                        all_results.append(r)
                        _save_results(scan_id, [r])

                    after_path = scan_dir / f"{browser_name}_{name}_after.png"
                    await _screenshot_page(page, after_path)

                    if after_path.exists():
                        save_artifact(scan_id, f"{browser_name}_{name}", f"screenshot_after",
                                      after_path.name, "image/png", after_path.stat().st_size)

                # Save trace
                trace_path = None
                if enable_trace:
                    trace_file = scan_dir / f"{browser_name}_trace.zip"
                    await context.tracing.stop(path=str(trace_file))
                    if trace_file.exists():
                        trace_path = str(trace_file)
                        save_artifact(scan_id, f"{browser_name}_scan", "trace",
                                     trace_file.name, "application/zip", trace_file.stat().st_size)
                        _update_scan(scan_id, trace_path=trace_path)

                page_video = page.video
                await page.close()
                await context.close()
                await browser.close()

                # HAR is finalized after context.close()
                har_file = scan_dir / f"{browser_name}_network.har"
                if har_file.exists():
                    save_artifact(scan_id, f"{browser_name}_scan", "har",
                                 har_file.name, "application/json", har_file.stat().st_size)

                video_saved = False
                if page_video:
                    try:
                        vp = await asyncio.wait_for(page_video.path(), timeout=10)
                        vid_path = Path(vp)
                        if vid_path.exists() and vid_path.stat().st_size > 0:
                            save_artifact(scan_id, f"{browser_name}_scan", "video",
                                         vid_path.name, "video/webm", vid_path.stat().st_size)
                            video_saved = True
                    except Exception:
                        pass

                # Fallback: look for video file in record_video_dir (if primary didn't save)
                if not video_saved:
                    video_record_dir = Path(scan_dir) / f"{browser_name}_video"
                    if video_record_dir.exists():
                        try:
                            video_files = sorted(video_record_dir.glob("*.webm"), key=lambda f: f.stat().st_mtime)
                            if video_files:
                                vid_path = video_files[-1]
                                if vid_path.stat().st_size > 0:
                                    save_artifact(scan_id, f"{browser_name}_scan", "video",
                                                 vid_path.name, "video/webm", vid_path.stat().st_size)
                        except Exception:
                            pass

        # Save console logs
        if console_logs:
            console_path = scan_dir / "console.json"
            console_path.write_text(json.dumps(console_logs, indent=2))
            save_artifact(scan_id, "scan", "console", console_path.name,
                          "application/json", console_path.stat().st_size)

        # Score
        weights = {"critical": 10, "major": 5, "minor": 2, "info": 0}
        total_weight = lost_weight = 0
        for r in all_results:
            w = weights.get(r.severity, 0)
            if w == 0:
                continue
            total_weight += w
            if r.status in ("fail", "warn"):
                lost_weight += w * (1.0 if r.status == "fail" else 0.5)

        score = max(0, round(100 * (1 - lost_weight / total_weight), 1)) if total_weight > 0 else 100
        passed = sum(1 for r in all_results if r.status == "pass")
        failed = sum(1 for r in all_results if r.status == "fail")
        warned = sum(1 for r in all_results if r.status == "warn")

        _update_scan(
            scan_id, status="done", score=score, progress="Complete",
            summary=json.dumps({"passed": passed, "failed": failed, "warned": warned,
                               "total": len(all_results), "browsers": browsers_to_run}),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as e:
        _update_scan(scan_id, status="failed", progress=f"Error: {str(e)[:200]}",
                     finished_at=datetime.now(timezone.utc).isoformat())
        traceback.print_exc()


# ─────────── LEGACY API (single scan) ───────────

async def run_single_scan(scan_id: int, url: str, config: dict):
    """Legacy single-scan entry point for backward compat."""
    await run_scan(scan_id, url, config)
