import streamlit as st
import os
import subprocess
import requests
import json
import re
import urllib.parse
from openai import OpenAI
from bs4 import BeautifulSoup

st.set_page_config(
    page_title="XSS & HTML Injection Analyzer",
    page_icon="🔍",
    layout="wide"
)

# ── Constants ────────────────────────────────────────────────────────────────
MAX_TURNS = 3
MAX_TOKENS = 1200
MAX_CODE_CHARS = 8000
MODEL = "deepseek/deepseek-r1"
BASE_URL = "https://openrouter.ai/api/v1"

SYSTEM_PROMPT = """You are an expert white-hat security code auditor specializing in XSS (Cross-Site Scripting) and HTML Injection vulnerabilities.

Your job:
1. Analyze source code or HTML for sanitization flaws.
2. Check how the code handles special characters: < > " ' / & ` = { }
3. Detect missing encoding (e.g., htmlspecialchars, escapeHTML, DOMPurify, Content Security Policy).
4. Identify Stored XSS, Reflected XSS, DOM-based XSS, and HTML Injection sinks.
5. Flag dangerous patterns: innerHTML, document.write, eval, dangerouslySetInnerHTML, unescaped template literals, unsanitized DB output rendered into HTML.
6. Produce a structured security report:
   - VULNERABILITY SUMMARY (severity: Critical/High/Medium/Low)
   - AFFECTED CODE LINES with exact location
   - ATTACK SCENARIO (how an attacker would exploit it)
   - SECURE REMEDIATION with corrected code snippet
7. Be concise. No boilerplate. Skip safe code. Focus only on flaws.

If the user specifies a target URL and focus area, prioritize findings relevant to that context."""

# ── Session state ─────────────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []
if "poc_results" not in st.session_state:
    st.session_state.poc_results = []
if "cmd_output" not in st.session_state:
    st.session_state.cmd_output = ""
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = ""

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client() -> OpenAI:
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        st.error("OPENROUTER_API_KEY is not set. Add it in Replit Secrets.")
        st.stop()
    return OpenAI(api_key=api_key, base_url=BASE_URL)


def extract_relevant_blocks(code: str, max_chars: int = MAX_CODE_CHARS) -> str:
    """Extract only high-risk code blocks to save tokens."""
    if len(code) <= max_chars:
        return code

    risk_patterns = [
        r'innerHTML', r'outerHTML', r'document\.write', r'eval\s*\(',
        r'dangerouslySetInnerHTML', r'\.html\s*\(', r'v-html',
        r'<\s*script', r'on\w+\s*=', r'htmlspecialchars', r'escape',
        r'sanitize', r'DOMPurify', r'\$_GET', r'\$_POST', r'\$_REQUEST',
        r'request\.(args|form|json|data)', r'req\.(body|query|params)',
        r'getParameter', r'getAttribute', r'render\s*\(',
        r'template\s*\(', r'format\s*\(.*input', r'f["\'].*\{',
        r'printf.*input', r'echo\s+\$', r'print\s+\$',
    ]

    lines = code.splitlines(keepends=True)
    flagged_lines = set()
    for i, line in enumerate(lines):
        for pat in risk_patterns:
            if re.search(pat, line, re.IGNORECASE):
                for j in range(max(0, i - 5), min(len(lines), i + 10)):
                    flagged_lines.add(j)
                break

    if not flagged_lines:
        return code[:max_chars] + "\n\n[... truncated for token budget ...]"

    chunks = []
    total = 0
    for idx in sorted(flagged_lines):
        chunk = lines[idx]
        if total + len(chunk) > max_chars:
            break
        chunks.append(chunk)
        total += len(chunk)

    result = "".join(chunks)
    if len(result) < len(code):
        result += "\n\n[... non-risky sections omitted for token budget ...]"
    return result


def trim_history(history: list) -> list:
    """Keep only last MAX_TURNS exchanges to cap context size."""
    if len(history) > MAX_TURNS * 2:
        return history[-(MAX_TURNS * 2):]
    return history


def analyze_code(code: str, target_url: str, focus: str) -> str:
    client = get_client()
    trimmed_code = extract_relevant_blocks(code)

    user_msg = ""
    if target_url:
        user_msg += f"Target URL: {target_url}\n"
    if focus:
        user_msg += f"Focus area: {focus}\n"
    user_msg += f"\n--- SOURCE CODE ---\n{trimmed_code}\n--- END ---"

    st.session_state.history.append({"role": "user", "content": user_msg})
    st.session_state.history = trim_history(st.session_state.history)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + st.session_state.history

    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=MAX_TOKENS,
        temperature=0.2,
    )
    reply = response.choices[0].message.content
    st.session_state.history.append({"role": "assistant", "content": reply})
    st.session_state.history = trim_history(st.session_state.history)
    return reply


def ask_followup(question: str) -> str:
    client = get_client()
    st.session_state.history.append({"role": "user", "content": question})
    st.session_state.history = trim_history(st.session_state.history)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + st.session_state.history

    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=MAX_TOKENS,
        temperature=0.2,
    )
    reply = response.choices[0].message.content
    st.session_state.history.append({"role": "assistant", "content": reply})
    st.session_state.history = trim_history(st.session_state.history)
    return reply


def run_command(cmd: str) -> str:
    """Execute a shell command and return combined stdout+stderr."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        out = result.stdout or ""
        err = result.stderr or ""
        return (out + err).strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 30 seconds."
    except Exception as e:
        return f"[ERROR] {e}"


# ── PoC XSS payloads ──────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    ('<script>alert("XSS")</script>', "Basic script tag"),
    ('"><script>alert(1)</script>', "Attribute breakout + script"),
    ("'><img src=x onerror=alert(1)>", "Single-quote breakout + img onerror"),
    ('<svg onload=alert(1)>', "SVG onload"),
    ('javascript:alert(1)', "javascript: URI"),
    ('<iframe src="javascript:alert(1)">', "iframe javascript URI"),
    ('"><body onload=alert(1)>', "Body onload injection"),
    ('{{7*7}}', "Template injection probe"),
]


def probe_url_for_xss(target_url: str, param: str) -> list:
    """
    Send harmless PoC payloads to a target URL parameter and check if
    they are reflected unescaped in the response body.
    This is a reflection check only — no actual code execution.
    """
    results = []
    session = requests.Session()
    session.headers.update({
        "User-Agent": "WhiteHat-XSS-Analyzer/1.0 (authorized security test)"
    })

    for payload, label in XSS_PAYLOADS:
        try:
            # Try GET param injection
            parsed = urllib.parse.urlparse(target_url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            if param:
                params[param] = payload
            else:
                params["q"] = payload

            test_url = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
            resp = session.get(test_url, timeout=10, allow_redirects=True)
            body = resp.text

            reflected = payload in body
            escaped = (
                payload.replace("<", "&lt;").replace(">", "&gt;") in body
                or payload.replace('"', "&quot;") in body
            )

            if reflected and not escaped:
                status = "⚠️ REFLECTED UNESCAPED"
            elif reflected and escaped:
                status = "✅ Reflected but escaped"
            else:
                status = "➖ Not reflected"

            results.append({
                "payload": payload,
                "label": label,
                "status": status,
                "url": test_url,
                "http_status": resp.status_code,
            })
        except Exception as e:
            results.append({
                "payload": payload,
                "label": label,
                "status": f"❌ Error: {e}",
                "url": target_url,
                "http_status": "N/A",
            })

    return results


# ── UI ────────────────────────────────────────────────────────────────────────

st.title("🔍 XSS & HTML Injection Analyzer")
st.caption("White-hat security tool — for use only on sites you own or are authorized to test.")

tabs = st.tabs(["📋 Code Analyzer", "🎯 PoC Injection Tester", "💻 Linux Terminal", "💬 Follow-up Chat"])

# ── Tab 1: Code Analyzer ──────────────────────────────────────────────────────
with tabs[0]:
    st.subheader("Analyze Source Code for XSS / HTML Injection")

    col1, col2 = st.columns(2)
    with col1:
        target_url = st.text_input(
            "Target URL (optional)",
            placeholder="https://example.com/search?q=",
            help="Provide context for the analysis"
        )
    with col2:
        focus = st.text_input(
            "Focus area",
            placeholder="e.g. search results rendering, comment output, user profile display",
            help="Tell the AI what part of the app to focus on"
        )

    input_method = st.radio("Input method", ["Paste code", "Upload file"], horizontal=True)

    code_input = ""
    if input_method == "Paste code":
        code_input = st.text_area(
            "Paste HTML / source code",
            height=280,
            placeholder="Paste the relevant HTML, PHP, JS, Python template, etc. here..."
        )
    else:
        uploaded = st.file_uploader(
            "Upload source file",
            type=["html", "php", "js", "ts", "py", "erb", "twig", "jinja", "txt", "jsx", "tsx"]
        )
        if uploaded:
            code_input = uploaded.read().decode("utf-8", errors="replace")
            st.code(code_input[:2000] + ("..." if len(code_input) > 2000 else ""), language="html")

    col_a, col_b = st.columns([1, 4])
    with col_a:
        run_analysis = st.button("🔎 Analyze", type="primary", use_container_width=True)
    with col_b:
        if st.button("🗑️ Clear history", use_container_width=False):
            st.session_state.history = []
            st.session_state.analysis_result = ""
            st.success("Conversation history cleared.")

    turns_used = len(st.session_state.history) // 2
    st.caption(f"Conversation turns used: {turns_used} / {MAX_TURNS} (older turns auto-discarded)")

    if run_analysis:
        if not code_input.strip():
            st.warning("Please paste or upload some source code first.")
        else:
            with st.spinner("Analyzing with DeepSeek R1 — this may take 20–40 seconds..."):
                try:
                    result = analyze_code(code_input, target_url, focus)
                    st.session_state.analysis_result = result
                except Exception as e:
                    st.error(f"API error: {e}")

    if st.session_state.analysis_result:
        st.divider()
        st.subheader("📊 Security Report")
        st.markdown(st.session_state.analysis_result)

# ── Tab 2: PoC Injection Tester ───────────────────────────────────────────────
with tabs[1]:
    st.subheader("🎯 Proof-of-Concept Reflection Tester")
    st.warning(
        "⚠️ **Authorized use only.** Only test sites you own or have explicit written permission to test. "
        "This tool sends real HTTP requests with XSS payloads to check for unescaped reflection. "
        "No payloads execute client-side — this is a server-response analysis only."
    )

    poc_col1, poc_col2 = st.columns(2)
    with poc_col1:
        poc_url = st.text_input(
            "Target URL",
            placeholder="https://mysite.com/search?q=test",
            key="poc_url"
        )
    with poc_col2:
        poc_param = st.text_input(
            "Parameter to inject into",
            placeholder="q  (leave blank to use 'q')",
            key="poc_param"
        )

    if st.button("🚀 Run PoC Probe", type="primary"):
        if not poc_url.strip():
            st.warning("Enter a target URL.")
        else:
            with st.spinner("Sending probes..."):
                try:
                    results = probe_url_for_xss(poc_url.strip(), poc_param.strip())
                    st.session_state.poc_results = results
                except Exception as e:
                    st.error(f"Probe error: {e}")

    if st.session_state.poc_results:
        st.divider()
        st.subheader("Probe Results")
        for r in st.session_state.poc_results:
            with st.expander(f"{r['status']} — {r['label']}", expanded="UNESCAPED" in r["status"]):
                st.code(r["payload"], language="html")
                st.markdown(f"**HTTP Status:** `{r['http_status']}`")
                st.markdown(f"**Test URL:** `{r['url']}`")

        unescaped = [r for r in st.session_state.poc_results if "UNESCAPED" in r["status"]]
        if unescaped:
            st.error(f"🚨 {len(unescaped)} payload(s) reflected **unescaped** — potential XSS confirmed.")
            if st.button("📋 Send findings to AI for analysis"):
                summary = "The following XSS payloads were reflected unescaped in the HTTP response:\n"
                for r in unescaped:
                    summary += f"- Payload: {r['payload']} | URL: {r['url']}\n"
                summary += "\nAnalyze the risk and recommend server-side fixes."
                with st.spinner("Consulting AI..."):
                    reply = ask_followup(summary)
                    st.markdown(reply)
        else:
            st.success("No unescaped reflections detected with these payloads.")

# ── Tab 3: Linux Terminal ─────────────────────────────────────────────────────
with tabs[2]:
    st.subheader("💻 Linux Command Runner")
    st.info(
        "Run reconnaissance and diagnostic commands against your target. "
        "Useful tools: `curl`, `wget`, `nmap`, `nikto`, `whatweb`, `nslookup`, `dig`, `whois`, `openssl`."
    )

    preset_col, _ = st.columns([2, 3])
    with preset_col:
        preset = st.selectbox("Quick presets", [
            "— select —",
            "curl headers",
            "curl page source",
            "nmap quick scan",
            "whatweb",
            "nslookup",
            "check CSP header",
            "check X-XSS-Protection",
        ])

    cmd_input = st.text_input(
        "Command",
        placeholder="curl -I https://example.com",
        key="cmd_input"
    )

    # Auto-fill preset
    preset_url = st.text_input("URL for preset (optional)", placeholder="https://example.com", key="preset_url")
    if preset != "— select —" and preset_url:
        url = preset_url.strip()
        preset_map = {
            "curl headers": f"curl -s -I --max-time 10 '{url}'",
            "curl page source": f"curl -s --max-time 15 '{url}' | head -200",
            "nmap quick scan": f"nmap -F --open {urllib.parse.urlparse(url).hostname or url}",
            "whatweb": f"whatweb '{url}'",
            "nslookup": f"nslookup {urllib.parse.urlparse(url).hostname or url}",
            "check CSP header": f"curl -s -I --max-time 10 '{url}' | grep -i 'content-security-policy'",
            "check X-XSS-Protection": f"curl -s -I --max-time 10 '{url}' | grep -i 'x-xss'",
        }
        if preset in preset_map:
            st.code(preset_map[preset])
            if st.button("▶ Run preset", type="primary"):
                with st.spinner("Running..."):
                    st.session_state.cmd_output = run_command(preset_map[preset])

    if st.button("▶ Run command", type="secondary") and cmd_input.strip():
        with st.spinner("Running..."):
            st.session_state.cmd_output = run_command(cmd_input.strip())

    if st.session_state.cmd_output:
        st.divider()
        st.subheader("Output")
        st.code(st.session_state.cmd_output, language="bash")

        if st.button("🤖 Send output to AI for analysis"):
            with st.spinner("Analyzing output..."):
                q = f"I ran a security recon command and got this output. Analyze it for security issues relevant to XSS or HTML injection:\n\n```\n{st.session_state.cmd_output[:3000]}\n```"
                reply = ask_followup(q)
                st.markdown(reply)

# ── Tab 4: Follow-up Chat ─────────────────────────────────────────────────────
with tabs[3]:
    st.subheader("💬 Follow-up with the AI Auditor")
    st.caption(
        f"Ask follow-up questions based on the current analysis context. "
        f"History is capped at {MAX_TURNS} turns to protect your API budget."
    )

    if not st.session_state.history:
        st.info("Run a code analysis first to establish context, then ask follow-up questions here.")

    for msg in st.session_state.history:
        role = msg["role"]
        with st.chat_message(role):
            st.markdown(msg["content"])

    followup = st.chat_input("Ask a follow-up question...")
    if followup:
        with st.chat_message("user"):
            st.markdown(followup)
        with st.spinner("Thinking..."):
            try:
                reply = ask_followup(followup)
                with st.chat_message("assistant"):
                    st.markdown(reply)
                st.rerun()
            except Exception as e:
                st.error(f"API error: {e}")
