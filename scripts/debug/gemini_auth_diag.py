"""
Diagnose how the Gemini API key is transmitted and what Google returns.

- Captures litellm's outgoing request (URL auth method, headers, status, body).
  The key value is never printed; only the auth mechanism is shown.
- Replays the minimal Generative Language request with each auth variant:
  (1) x-goog-api-key header, (2) ?key= query param, (3) Authorization Bearer.

Usage: python scripts/debug/gemini_auth_diag.py [model-name]  (default: gemini-2.0-flash)
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import httpx
from vulnguard.config import cfg

KEY = cfg.llm.api_key
API_HOST = "https://generativelanguage.googleapis.com"
MODEL = sys.argv[1] if len(sys.argv) > 1 else "gemini-2.0-flash"


def redact(text: str) -> str:
    return text.replace(KEY, "***REDACTED***")


def show(msg: str, sender: str) -> None:
    print(f"\n=== {sender}: {msg} ===")


# ── Part 1: capture litellm's actual request ─────────────────────────────
_orig_send = httpx.Client.send


def patched_send(self, request, **kwargs):
    url = str(request.url)
    auth_shape = []
    if "x-goog-api-key" in request.headers:
        auth_shape.append("header x-goog-api-key")
    if "Authorization" in request.headers:
        auth_shape.append("header Authorization (Bearer/token)")
    if "key=" in url:
        auth_shape.append("URL ?key= query param")
    show(f"endpoint={url.split('/models/')[0]}/…", "litellm outgoing request")
    print(f"  auth mechanism: {auth_shape or 'none'}")
    resp = _orig_send(self, request, **kwargs)
    print(f"  HTTP status: {resp.status_code}")
    body = getattr(resp, "text", "") or ""
    if body.strip():
        print(f"  response body: {redact(body)[:400]}")
    return resp


httpx.Client.send = patched_send

from litellm import completion  # noqa: E402

try:
    r = completion(model=f"gemini/{MODEL}", messages=[{"role": "user", "content": "Reply with OK."}], max_tokens=8)
    show(f"SUCCESS -> {r.choices[0].message.content!r}", "litellm result")
except Exception as exc:
    body = getattr(getattr(exc, "response", None), "text", "") or str(exc)
    show(f"FAILED — HTTP status: {getattr(getattr(exc, 'response', None), 'status_code', 'n/a')} | {type(exc).__name__}", "litellm result")
    print(redact(body[:800]))
finally:
    httpx.Client.send = _orig_send

# ── Part 2: replay with each auth variant ────────────────────────────────
payload = {"contents": [{"parts": [{"text": "Reply with OK."}]}]}
client = httpx.Client(timeout=60)

variants = {
    "x-goog-api-key header": {"url": f"{API_HOST}/v1beta/models/{MODEL}:generateContent", "headers": {"x-goog-api-key": KEY}},
    "?key= query param": {"url": f"{API_HOST}/v1beta/models/{MODEL}:generateContent?key={KEY}", "headers": {}},
    "Authorization Bearer": {"url": f"{API_HOST}/v1beta/models/{MODEL}:generateContent", "headers": {"Authorization": f"Bearer {KEY}"}},
}

for name, v in variants.items():
    try:
        resp = client.post(v["url"], json=payload, headers=v["headers"])
        print(f"\n=== direct replay ({name}) ===")
        print(f"  HTTP status: {resp.status_code}")
        print(f"  body: {redact(resp.text)[:400]}")
    except Exception as exc:
        print(f"\n=== direct replay ({name}) ===")
        print(f"  request error: {type(exc).__name__}: {redact(str(exc))[:300]}")

# cheap auth-only variant: list models
for name, headers in {"x-goog-api-key header": {"x-goog-api-key": KEY}, "Authorization Bearer": {"Authorization": f"Bearer {KEY}"}}.items():
    try:
        resp = client.get(f"{API_HOST}/v1beta/models?pageSize=1", headers=headers)
        print(f"\n=== GET /v1beta/models ({name}) ===")
        print(f"  HTTP status: {resp.status_code}")
        print(f"  body: {redact(resp.text)[:300]}")
    except Exception as exc:
        print(f"\n=== GET /v1beta/models ({name}) ===")
        print(f"  request error: {type(exc).__name__}: {redact(str(exc))[:300]}")

client.close()
