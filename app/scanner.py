"""Site scanner — runs all test categories using Playwright."""

import asyncio
import json
import time
import traceback
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from playwright.async_api import async_playwright, Page, Browser

from database import get_db


@dataclass
class TestResult:
    category: str
    test_name: str
    status: str  # pass, fail, warn, skip, info
    severity: str  # critical, major, minor, info
    message: str
    details: dict


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


# ──────────────────────── TEST MODULES ────────────────────────


async def test_smoke(page: Page, url: str) -> list[TestResult]:
    results = []
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=20000)
        status = resp.status if resp else 0
        results.append(TestResult("smoke", "Page loads", "pass" if 200 <= status < 400 else "fail",
                                  "critical", f"HTTP {status}", {"status_code": status}))

        # HTTPS check
        is_https = url.startswith("https://") or (resp and resp.url.startswith("https://"))
        results.append(TestResult("smoke", "HTTPS enabled", "pass" if is_https else "warn",
                                  "major", "Site uses HTTPS" if is_https else "Site does not use HTTPS", {}))

        # No console errors
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        await page.wait_for_timeout(2000)
        results.append(TestResult("smoke", "No JS errors", "pass" if not errors else "warn",
                                  "minor", f"{len(errors)} JS error(s)" if errors else "Clean console",
                                  {"errors": errors[:5]}))

        # Title exists
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

        # HTTPS redirect
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
        await page.goto(url, wait_until="networkidle", timeout=20000)

        # Meta description
        desc = await page.evaluate("document.querySelector('meta[name=\"description\"]')?.content || ''")
        results.append(TestResult("seo", "Meta description",
                                  "pass" if len(desc) >= 50 else ("warn" if desc else "fail"),
                                  "major", desc[:120] if desc else "No meta description",
                                  {"length": len(desc), "content": desc[:200]}))

        # OG tags
        og_title = await page.evaluate("document.querySelector('meta[property=\"og:title\"]')?.content || ''")
        og_img = await page.evaluate("document.querySelector('meta[property=\"og:image\"]')?.content || ''")
        has_og = bool(og_title and og_img)
        results.append(TestResult("seo", "Open Graph tags", "pass" if has_og else "warn",
                                  "minor", f"og:title={bool(og_title)}, og:image={bool(og_img)}",
                                  {"og_title": og_title, "og_image": og_img}))

        # Canonical URL
        canonical = await page.evaluate("document.querySelector('link[rel=\"canonical\"]')?.href || ''")
        results.append(TestResult("seo", "Canonical URL", "pass" if canonical else "warn",
                                  "minor", canonical or "No canonical tag",
                                  {"canonical": canonical}))

        # H1 tag
        h1 = await page.evaluate("document.querySelector('h1')?.textContent?.trim() || ''")
        results.append(TestResult("seo", "H1 heading", "pass" if h1 else "fail",
                                  "major", h1[:100] if h1 else "No H1 found", {"h1": h1[:200] if h1 else ""}))

        # Sitemap
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            try:
                r = await client.get(urljoin(url, "/sitemap.xml"))
                has_sitemap = r.status_code == 200 and "xml" in r.headers.get("content-type", "")
            except Exception:
                has_sitemap = False
        results.append(TestResult("seo", "Sitemap.xml", "pass" if has_sitemap else "warn",
                                  "minor", "Found" if has_sitemap else "Not found", {}))

        # Robots.txt
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            try:
                r = await client.get(urljoin(url, "/robots.txt"))
                has_robots = r.status_code == 200 and len(r.text) > 10
            except Exception:
                has_robots = False
        results.append(TestResult("seo", "Robots.txt", "pass" if has_robots else "warn",
                                  "minor", "Found" if has_robots else "Not found", {}))

        # Image alt tags
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
        await page.goto(url, wait_until="networkidle", timeout=20000)

        # Inject axe-core and run
        axe_results = await page.evaluate("""async () => {
            await new Promise((resolve, reject) => {
                if (window.axe) return resolve();
                const s = document.createElement('script');
                s.src = 'https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.9.1/axe.min.js';
                s.onload = resolve;
                s.onerror = reject;
                document.head.appendChild(s);
            });
            const r = await axe.run(document, {
                runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] }
            });
            return {
                violations: r.violations.map(v => ({
                    id: v.id,
                    impact: v.impact,
                    description: v.description,
                    nodes: v.nodes.length,
                    help: v.helpUrl
                })),
                passes: r.passes.length,
                incomplete: r.incomplete.length
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
                                  "major", f"{load_time_ms}ms",
                                  {"load_time_ms": load_time_ms}))

        # Performance metrics
        metrics = await page.evaluate("""() => {
            const nav = performance.getEntriesByType('navigation')[0] || {};
            const paint = performance.getEntriesByType('paint');
            const fcp = paint.find(p => p.name === 'first-contentful-paint');
            return {
                dom_interactive: Math.round(nav.domInteractive || 0),
                dom_complete: Math.round(nav.domComplete || 0),
                transfer_size: Math.round(nav.transferSize || 0),
                fcp: Math.round(fcp?.startTime || 0),
            };
        }""")

        fcp = metrics.get("fcp", 0)
        if fcp > 0:
            results.append(TestResult("performance", "First Contentful Paint",
                                      "pass" if fcp < 1800 else ("warn" if fcp < 3000 else "fail"),
                                      "major", f"{fcp}ms", {"fcp_ms": fcp}))

        # Total resources
        resources = await page.evaluate("""() => {
            const entries = performance.getEntriesByType('resource');
            let total = 0;
            entries.forEach(e => total += e.transferSize || 0);
            return { count: entries.length, total_bytes: total };
        }""")
        total_kb = resources["total_bytes"] / 1024
        results.append(TestResult("performance", "Total resource size",
                                  "pass" if total_kb < 2000 else ("warn" if total_kb < 5000 else "fail"),
                                  "minor", f"{total_kb:.0f} KB ({resources['count']} resources)",
                                  resources))

        # CLS (Cumulative Layout Shift)
        cls_val = await page.evaluate("""() => new Promise(resolve => {
            let cls = 0;
            const observer = new PerformanceObserver(list => {
                for (const entry of list.getEntries()) {
                    if (!entry.hadRecentInput) cls += entry.value;
                }
            });
            observer.observe({ type: 'layout-shift', buffered: true });
            setTimeout(() => { observer.disconnect(); resolve(Math.round(cls * 1000) / 1000); }, 2000);
        })""")
        results.append(TestResult("performance", "Cumulative Layout Shift",
                                  "pass" if cls_val < 0.1 else ("warn" if cls_val < 0.25 else "fail"),
                                  "minor", f"CLS: {cls_val}", {"cls": cls_val}))

    except Exception as e:
        results.append(TestResult("performance", "Performance scan", "fail", "critical", str(e), {}))
    return results


async def test_responsive(page: Page, url: str) -> list[TestResult]:
    results = []
    viewports = [
        ("Mobile S", 320, 568),
        ("Mobile L", 430, 932),
        ("Tablet", 768, 1024),
        ("Desktop", 1280, 800),
        ("Wide", 1920, 1080),
    ]
    try:
        for name, w, h in viewports:
            await page.set_viewport_size({"width": w, "height": h})
            await page.goto(url, wait_until="networkidle", timeout=15000)
            overflow = await page.evaluate("document.documentElement.scrollWidth > window.innerWidth")
            results.append(TestResult("responsive", f"No overflow at {name} ({w}px)",
                                      "pass" if not overflow else "fail", "major",
                                      "No horizontal overflow" if not overflow else f"Content overflows at {w}px",
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
                .filter(h => h && !h.startsWith('javascript') && !h.startsWith('mailto') && !h.startsWith('tel'))
            )]
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

        results.append(TestResult("links", "Internal links",
                                  "pass" if not [b for b in broken if urlparse(b["url"]).netloc == parsed_base.netloc] else "fail",
                                  "major", f"Checked {len(internal)} internal links",
                                  {"checked": len(internal)}))

        ext_broken = [b for b in broken if urlparse(b["url"]).netloc != parsed_base.netloc]
        results.append(TestResult("links", "External links",
                                  "pass" if not ext_broken else "warn",
                                  "minor", f"Checked {len(external)} external links, {len(ext_broken)} broken",
                                  {"checked": len(external), "broken": ext_broken[:10]}))

        if broken:
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

        # Large images
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


async def test_faces(page: Page, url: str, api_url: str, api_token: str = "") -> list[TestResult]:
    """Validate face images via the Face Validation API."""
    results = []
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
        images = await page.evaluate("""() =>
            Array.from(document.querySelectorAll('img'))
                .filter(i => i.src && i.complete && i.naturalWidth > 80)
                .map(i => ({ src: i.src, alt: i.alt || '' }))
        """)

        unique = list({img["src"]: img for img in images}.values())
        faces_found = 0
        face_scores = []

        async with httpx.AsyncClient(timeout=15) as client:
            for img in unique[:30]:
                try:
                    img_resp = await client.get(img["src"])
                    ct = img_resp.headers.get("content-type", "")
                    if not ct.startswith("image/") or "svg" in ct or len(img_resp.content) < 5000:
                        continue

                    headers = {}
                    if api_token:
                        headers["Authorization"] = f"Bearer {api_token}"

                    files = {"file": ("image.jpg", img_resp.content, ct)}
                    api_resp = await client.post(f"{api_url}/validate-face", files=files, headers=headers)
                    if api_resp.status_code != 200:
                        continue

                    data = api_resp.json()
                    if data.get("error"):
                        continue  # No face — skip

                    faces_found += 1
                    score = data["score"]
                    face_scores.append(score)
                    status = "pass" if data["status"] == "PASS" else ("warn" if data["status"] == "WARN" else "fail")
                    label = img["alt"][:50] if img["alt"] else img["src"].split("/")[-1][:50]

                    issues = []
                    m = data.get("metrics", {})
                    if m.get("is_cut_top"):
                        issues.append("cut at top")
                    if m.get("is_cut_bottom"):
                        issues.append("cut at bottom")
                    if not m.get("is_centered"):
                        issues.append("off-center")

                    results.append(TestResult("faces", f"Face: {label}", status,
                                              "minor" if status == "warn" else ("major" if status == "fail" else "info"),
                                              f"Score {score} — {', '.join(issues) if issues else 'Good framing'}",
                                              {**data, "image_url": img["src"][:200], "alt": img["alt"]}))
                except Exception:
                    continue

        avg = sum(face_scores) / len(face_scores) if face_scores else 0
        results.append(TestResult("faces", "Face validation summary",
                                  "pass" if avg >= 0.85 else ("warn" if avg >= 0.65 else ("fail" if faces_found else "info")),
                                  "info", f"{faces_found} faces found, avg score {avg:.2f}",
                                  {"faces_found": faces_found, "avg_score": round(avg, 2), "images_scanned": len(unique)}))
    except Exception as e:
        results.append(TestResult("faces", "Face scan", "fail", "critical", str(e), {}))
    return results


# ──────────────────────── ORCHESTRATOR ────────────────────────


async def run_scan(scan_id: int, url: str, config: dict):
    """Main scan orchestrator. Runs all enabled test modules."""
    _update_scan(scan_id, status="running", started_at=datetime.now(timezone.utc).isoformat())
    all_results: list[TestResult] = []

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            page = await browser.new_page()

            modules = [
                ("smoke", lambda: test_smoke(page, url)),
                ("security", lambda: test_security(page, url)),
                ("seo", lambda: test_seo(page, url)),
                ("accessibility", lambda: test_accessibility(page, url)),
                ("performance", lambda: test_performance(page, url)),
                ("responsive", lambda: test_responsive(page, url)),
                ("links", lambda: test_links(page, url, config.get("max_pages", 15))),
                ("images", lambda: test_images(page, url)),
                ("faces", lambda: test_faces(
                    page, url,
                    config.get("face_api_url", "https://faces.uat.argitic.com"),
                    config.get("face_api_token", ""),
                )),
            ]

            for name, fn in modules:
                if not config.get(f"{name}_enabled", True):
                    _update_scan(scan_id, progress=f"Skipped {name}")
                    continue

                _update_scan(scan_id, progress=f"Running {name}...")
                try:
                    module_results = await asyncio.wait_for(fn(), timeout=120)
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

            await browser.close()

        # Calculate overall score
        weights = {"critical": 10, "major": 5, "minor": 2, "info": 0}
        total_weight = 0
        lost_weight = 0
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
            summary=json.dumps({"passed": passed, "failed": failed, "warned": warned, "total": len(all_results)}),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as e:
        _update_scan(scan_id, status="failed", progress=f"Error: {str(e)[:200]}",
                     finished_at=datetime.now(timezone.utc).isoformat())
        traceback.print_exc()
