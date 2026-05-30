# XSS & HTML Injection Analyzer

A white-hat security tool that analyzes HTML and web application source code for XSS and HTML Injection vulnerabilities, backed by DeepSeek R1 via OpenRouter.

## Run & Operate

- `python3 -m streamlit run artifacts/xss-analyzer/app.py --server.port 5000` — run the Streamlit app
- Required secret: `OPENROUTER_API_KEY` — OpenRouter API key for DeepSeek R1

## Stack

- Python 3.11, Streamlit
- OpenAI SDK (pointed at OpenRouter, model: `deepseek/deepseek-r1`)
- requests, BeautifulSoup4, lxml

## Where things live

- `artifacts/xss-analyzer/app.py` — entire application (analyzer, PoC prober, terminal, chat)
- `artifacts/xss-analyzer/.streamlit/config.toml` — Streamlit server config (port 5000)

## Product

Four tabs:
1. **Code Analyzer** — paste or upload source code, optionally set a target URL and focus area, get a structured AI security report
2. **PoC Injection Tester** — send real XSS payloads to a target URL parameter and check if they reflect unescaped
3. **Linux Terminal** — run shell commands (curl, nmap, whatweb, etc.) against targets; presets for common recon
4. **Follow-up Chat** — conversational follow-up with the AI auditor within the current analysis context

## Architecture decisions

- Token budget enforced: 3-turn conversation history cap, code truncated to 8000 chars (high-risk blocks prioritized), max_tokens=1200 per API call
- Code extraction targets dangerous patterns (innerHTML, eval, echo $, req.body, etc.) and expands ±5 lines of context around each
- PoC prober uses HTTP GET reflection checks only — no client-side execution, no JS injection
- Shell commands run via `subprocess` with a 30-second timeout

## User preferences

_Populate as you build._

## Gotchas

- Only test sites you own or have written authorization to test
- DeepSeek R1 via OpenRouter can take 20–40s per response; this is normal
