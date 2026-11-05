"""LLM access layer (P0b).

Centralises three things that used to be tangled into phase 3:

* **A correct client/timeout.** The old code set ``client._client_timeout`` --
  an attribute the SDK never reads -- so the "20 minute" timeout was a no-op.
  Here the timeout is passed where the SDK actually uses it.
* **Robust, validated parsing.** Instead of ``json.loads(raw_text)`` (which
  died on any prose or markdown fence), we extract the JSON structurally and
  validate it into typed :class:`Finding` models.
* **A cache-friendly layout.** The large static system prompt is always the
  first message, unchanged between runs, so providers that do prompt caching
  (DeepSeek, OpenAI, Anthropic-compatible) can reuse it cheaply.

The structured-output contract is an object ``{"findings": [...]}`` so it is
compatible with JSON-object response modes, while the parser still accepts a
bare array for backward compatibility with older analysis logs.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from core.models import Finding, parse_findings

DEFAULT_TIMEOUT = 1200.0  # seconds; reasoning models on long flows are slow.

_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def build_client(api_key: str, base_url: str, timeout: float = DEFAULT_TIMEOUT):
    """Construct an OpenAI-compatible client with a timeout that is honoured."""
    from openai import OpenAI

    return OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)


def _balanced_slice(text: str, open_ch: str, close_ch: str) -> Optional[str]:
    """Return the first balanced ``open_ch..close_ch`` span in ``text``."""
    start = text.find(open_ch)
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def extract_findings_payload(text: str) -> Optional[List[Dict[str, Any]]]:
    """Pull a list of finding dicts out of a raw model response.

    Accepts: a bare JSON array, an object with a ``findings``/``results``/
    ``vulnerabilities`` key, or any of those wrapped in a markdown fence or
    surrounded by prose. Returns ``None`` only if nothing parseable is found.
    """
    if not text or not text.strip():
        return None

    candidates: List[str] = []
    m = _FENCE.search(text)
    if m:
        candidates.append(m.group(1))
    candidates.append(text)

    for chunk in candidates:
        chunk = chunk.strip()
        # Try an object first (structured-output contract).
        obj_span = _balanced_slice(chunk, "{", "}")
        arr_span = _balanced_slice(chunk, "[", "]")
        for span in (obj_span, arr_span):
            if not span:
                continue
            try:
                data = json.loads(span)
            except json.JSONDecodeError:
                continue
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("findings", "results", "vulnerabilities", "items"):
                    if isinstance(data.get(key), list):
                        return data[key]
    return None


def extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Pull a single JSON object out of a raw model response (prose/fence safe)."""
    if not text or not text.strip():
        return None
    candidates: List[str] = []
    m = _FENCE.search(text)
    if m:
        candidates.append(m.group(1))
    candidates.append(text)
    for chunk in candidates:
        span = _balanced_slice(chunk.strip(), "{", "}")
        if not span:
            continue
        try:
            data = json.loads(span)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
    return None


def parse_response(text: str) -> Tuple[Optional[List[Dict[str, Any]]], List[Finding]]:
    """Return (raw_payload, validated_findings).

    ``raw_payload`` is the extracted list of dicts (or ``None`` if extraction
    failed); ``findings`` is the subset that validated against the schema.
    """
    payload = extract_findings_payload(text)
    if payload is None:
        return None, []
    return payload, parse_findings(payload)


def messages_for(system_prompt: str, user_prompt: str) -> List[Dict[str, str]]:
    """Build a cache-friendly message list (stable system prefix first)."""
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
