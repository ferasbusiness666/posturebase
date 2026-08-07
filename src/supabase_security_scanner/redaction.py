from __future__ import annotations

import re


_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)(sb_secret_)[A-Za-z0-9_-]+"),
    re.compile(r"(?i)(postgres(?:ql)?://)([^\s'\"]+)"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._-]+"),
)


def redact_text(value: object) -> str:
    """Remove likely credential values from errors before they reach a report or MCP host."""

    text = str(value)
    for pattern in _SENSITIVE_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", text)
    return text
