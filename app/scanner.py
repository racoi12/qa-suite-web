"""Site scanner — runs all test categories using Playwright."""

import asyncio
import base64
import json
import os
import re
import time
import traceback
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from playwright.async_api import async_playwright, Page, Browser

from database import get_db, save_artifact


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
    """Validate face images via the Face Validation API.

    Uses Playwright to screenshot image elements directly from the browser context,
    handling lazy loading, authentication, and next/image srcsets correctly.
    """
    results = []
    try:
        # Navigate and wait for images to settle
        await page.goto(url, wait_until="networkidle", timeout=20000)
        await page.wait_for_timeout(2000)

        # Scroll to trigger lazy loading
        await page.evaluate("""() => {
            return new Promise(resolve => {
                let scrolled = 0;
                const step = window.innerHeight * 0.6;
                const interval = setInterval(() => {
                    window.scrollBy(0, step);
                    scrolled += step;
                    if (scrolled >= document.body.scrollHeight) {
                        window.scrollTo(0, 0);
                        clearInterval(interval);
                        resolve();
                    }
                }, 200);
            });
        }""")

        # Collect images — prioritize team/profile/hero images, skip icons and tiny images
        images = await page.evaluate("""() => {
            const prioritySel = [
                '[class*="team"] img', '[class*="profile"] img',
                '[class*="hero"] img', '[class*="doctor"] img',
                '[class*="staff"] img', '[class*="person"] img',
                '[data-testid*="face"] img', 'article img',
            ];
            const priority = [];
            const seen = new Set();

            // First: priority images (people/team)
            for (const sel of prioritySel) {
                for (const el of document.querySelectorAll(sel)) {
                    const img = el.tagName === 'IMG' ? el : el.querySelector('img');
                    if (img && img.src && !seen.has(img.src)) {
                        seen.add(img.src);
                        priority.push({ src: img.src, alt: img.alt || img.getAttribute('aria-label') || '', priority: true });
                    }
                }
            }

            // Then: all other images that are large enough
            for (const img of document.querySelectorAll('img')) {
                if (img.src && !seen.has(img.src) &&
                    (img.naturalWidth > 120 || img.naturalHeight > 120)) {
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

        headers = {}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"

        for img in images:
            try:
                # Use Playwright to screenshot the image element directly from browser context
                # This handles next/image URLs, lazy loading, auth cookies, etc.
                img_buffer = await page.evaluate("""async (src) => {
                    try {
                        const resp = await fetch(src);
                        if (!resp.ok) return null;
                        const blob = await resp.blob();
                        return await blob.arrayBuffer();
                    } catch { return null; }
                }""", img["src"])

                if img_buffer is None:
                    continue

                import io
                img_bytes = bytes(img_buffer)

                if len(img_bytes) < 5000:
                    continue

                # Determine content type
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

        # Summary with auth warning if needed
        summary_note = ""
        if skipped_auth > 0:
            summary_note = f" ({skipped_auth} skipped — auth required, set FACE_API_TOKEN)"

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


# ──────────────────────── CONTENT / COMPLIANCE ────────────────────────


async def test_content(page: Page, url: str) -> list[TestResult]:
    """Content completeness and compliance checks."""
    results = []

    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
        text = await page.evaluate("() => document.body.innerText")
        lower_text = text.lower()
        parsed = urlparse(url)

        # Medical/contact info
        has_contact = bool(
            re.search(r'contact', lower_text) or
            re.search(r'\d{3}[-.\s]\d{3}[-.\s]\d{4}', text) or
            re.search(r'[a-z0-9.]+@[a-z]+\.[a-z]{2,}', text)
        )
        results.append(TestResult("content", "Contact information",
                                  "pass" if has_contact else "fail", "major",
                                  "Found" if has_contact else "No phone, email, or contact section",
                                  {}))

        # Terms / Privacy
        tos_links = await page.locator('a').filter(has_text=re.compile(r'terms|tos|conditions', re.I)).count()
        priv_links = await page.locator('a').filter(has_text=re.compile(r'privacy|policy', re.I)).count()
        has_legal = bool(tos_links + priv_links)
        results.append(TestResult("content", "Terms & Privacy Policy",
                                  "pass" if has_legal else "fail", "major",
                                  f"Found {tos_links} terms, {priv_links} privacy links" if has_legal else "No terms or privacy policy",
                                  {"terms_links": tos_links, "privacy_links": priv_links}))

        # HIPAA (medical platforms)
        hipaa_found = 'hipaa' in lower_text
        results.append(TestResult("content", "HIPAA compliance reference",
                                  "pass" if hipaa_found else "warn", "major",
                                  "Found" if hipaa_found else "HIPAA not mentioned — critical for health sites",
                                  {}))

        # Medical disclaimer
        disclaimer_patterns = [
            r'not a substitute for.*medical',
            r'consult.*physician',
            r'not medical advice',
            r'individual results may vary',
            r'see.*physician.*before',
        ]
        has_disclaimer = any(re.search(p, lower_text, re.I) for p in disclaimer_patterns)
        results.append(TestResult("content", "Medical disclaimer",
                                  "pass" if has_disclaimer else "warn", "major",
                                  "Found" if has_disclaimer else "No medical disclaimer found",
                                  {}))

        # Testimonials / social proof
        has_reviews = bool(
            re.search(r'review|testimonial|\d+\s*stars?|rated', lower_text) or
            await page.locator('[class*="review"], [class*="testimonial"]').count() > 0
        )
        results.append(TestResult("content", "Testimonials / Reviews",
                                  "pass" if has_reviews else "warn", "minor",
                                  "Found" if has_reviews else "No testimonials or review section",
                                  {}))

        # Doctor / clinician info
        has_clinician = bool(
            re.search(r'clinician|doctor|physician|md|provider', lower_text) or
            await page.locator('a').filter(has_text=re.compile(r'team|about.*doctor', re.I)).count() > 0
        )
        results.append(TestResult("content", "Clinician / Doctor info",
                                  "pass" if has_clinician else "warn", "major",
                                  "Found" if has_clinician else "No clinical team or doctor info",
                                  {}))

        # Privacy policy page depth
        privacy_text = ""
        try:
            priv_link = page.locator('a').filter(has_text=re.compile(r'privacy|policy', re.I)).first
            if await priv_link.is_visible():
                href = await priv_link.get_attribute('href')
                if href:
                    priv_resp = await page.request.get(urljoin(url, href), timeout=10000)
                    privacy_text = (await priv_resp.text()).lower()
        except Exception:
            pass

        if privacy_text:
            has_privacy_content = len(privacy_text) > 200 and any(
                k in privacy_text for k in ['collect', 'personal', 'data', 'information']
            )
            results.append(TestResult("content", "Privacy policy content",
                                      "pass" if has_privacy_content else "fail", "major",
                                      f"{len(privacy_text)} chars, covers data handling" if has_privacy_content else "Privacy policy empty or missing data handling info",
                                      {"privacy_chars": len(privacy_text)}))

        # Third-party scripts audit
        scripts = []
        page.on("request", lambda req: (
            scripts.append(urlparse(req.url).hostname)
            if req.resource_type == "script" and urlparse(req.url).hostname
            and not urlparse(req.url).hostname.endswith(parsed.netloc)
            else None
        ))
        await page.reload(wait_until="networkidle", timeout=15000)
        unique_scripts = list({s: s for s in scripts if s and s not in ['googletagmanager.com', 'google-analytics.com', 'gtag', 'analytics']})
        if unique_scripts:
            results.append(TestResult("content", "Third-party scripts",
                                      "warn", "minor",
                                      f"{len(unique_scripts)} third-party script(s): {', '.join(unique_scripts[:5])}",
                                      {"scripts": unique_scripts[:10]}))

        # Hotjar warning
        if any('hotjar' in s for s in scripts):
            results.append(TestResult("content", "HOTJAR DETECTED — HIPAA RISK",
                                      "fail", "critical",
                                      "Hotjar session recording on a health site may violate HIPAA. Ensure PII exclusion rules are configured.",
                                      {}))

        # GLP-1 / off-label disclosure
        if re.search(r'glp-1|ozempic|semaglutide|wegovy', lower_text):
            has_disclosure = any(
                re.search(p, lower_text)
                for p in [r'off.label', r'fda.approved', r'consult.*physician', r'prescription']
            )
            results.append(TestResult("content", "GLP-1 / Off-label disclosure",
                                      "pass" if has_disclosure else "fail", "critical",
                                      "Disclosure found" if has_disclosure else "GLP-1 mentioned without FDA/off-label disclosure",
                                      {}))

    except Exception as e:
        results.append(TestResult("content", "Content scan", "fail", "critical", str(e), {}))

    return results


# ──────────────────────── ORCHESTRATOR ────────────────────────

ARTIFACTS_DIR = Path(os.getenv("ARTIFACTS_DIR", "/data/artifacts"))


async def _screenshot_page(page: Page, path: Path) -> bool:
    """Capture a full-page screenshot and return True if successful."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path= str(path), full_page=True, type="png")
        return True
    except Exception:
        return False


async def run_scan(scan_id: int, url: str, config: dict):
    """Main scan orchestrator. Runs all enabled test modules."""
    scan_dir = ARTIFACTS_DIR / str(scan_id)
    video_path = scan_dir / "video.webm"
    scan_dir.mkdir(parents=True, exist_ok=True)

    _update_scan(scan_id, status="running", started_at=datetime.now(timezone.utc).isoformat())
    all_results: list[TestResult] = []
    console_logs: list[dict] = []

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )

            # Context with video recording enabled
            context = await browser.new_context(
                record_video_dir=str(scan_dir),
                record_video_size={"width": 1280, "height": 720},
            )

            # Capture all console messages
            def on_console(msg):
                if msg.type in ("error", "warning", "log"):
                    console_logs.append({
                        "type": msg.type,
                        "text": msg.text,
                        "location": dict(msg.location) if hasattr(msg, 'location') else {},
                    })

            page = await context.new_page()
            page.on("console", on_console)

            modules = [
                ("smoke", lambda: test_smoke(page, url)),
                ("security", lambda: test_security(page, url)),
                ("seo", lambda: test_seo(page, url)),
                ("accessibility", lambda: test_accessibility(page, url)),
                ("performance", lambda: test_performance(page, url)),
                ("responsive", lambda: test_responsive(page, url)),
                ("links", lambda: test_links(page, url, config.get("max_pages", 15))),
                ("images", lambda: test_images(page, url)),
                ("content", lambda: test_content(page, url)),
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

                # Screenshot BEFORE module runs (baseline)
                before_path = scan_dir / f"{name}_before.png"
                await _screenshot_page(page, before_path)

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

                # Screenshot AFTER module runs (result state)
                after_path = scan_dir / f"{name}_after.png"
                await _screenshot_page(page, after_path)

                # Save both screenshots as artifacts
                for label, path in [("before", before_path), ("after", after_path)]:
                    if path.exists():
                        size = path.stat().st_size
                        save_artifact(scan_id, name, f"screenshot_{label}", path.name, "image/png", size)

            # Get video from the page before closing
            page_video = page.video
            # Close page first, then context — video is finalized after context.close()
            await page.close()
            await context.close()
            await browser.close()
            try:
                if page_video:
                    video_path_str = str(await asyncio.wait_for(page_video.path(), timeout=10))
                    _update_scan(scan_id, video_path=video_path_str)
                else:
                    # Fallback: find any .webm file created in scan_dir
                    webm_files = list(scan_dir.glob("*.webm"))
                    if webm_files:
                        _update_scan(scan_id, video_path=str(webm_files[0]))
            except Exception:
                # Fallback: find any .webm file created in scan_dir
                webm_files = list(scan_dir.glob("*.webm"))
                if webm_files:
                    _update_scan(scan_id, video_path=str(webm_files[0]))

        # Save console logs as artifact
        if console_logs:
            console_path = scan_dir / "console.json"
            console_path.write_text(json.dumps(console_logs, indent=2))
            save_artifact(scan_id, "scan", "console", console_path.name, "application/json", console_path.stat().st_size)


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
