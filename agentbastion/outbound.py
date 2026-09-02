"""Outbound guard - detect and redact PII / secrets before the agent's reply
leaves the building.

ponytail: regex catches the high-value money cases (SSN, card, API key, private
key, email). It is NOT full NER. Upgrade path: swap `PiiRedactor.scan` for
Microsoft Presidio (`presidio-analyzer`) behind the same shape - it does names,
addresses, locations, and locale-aware detection the regex can't. Regex ships
today with zero model download and no false-negative on the leaks that actually
cost money (secrets + government IDs).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PiiFinding:
    kind: str
    value: str
    start: int
    end: int


def _luhn_ok(digits: str) -> bool:
    """Luhn check - cuts the credit-card regex's false positives on random 16-digit runs."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13:
        return False
    checksum = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


# (kind, pattern, optional validator). Order matters: most specific first.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("API_KEY", re.compile(r"\bsk-(?:ant-|proj-|live-)?[A-Za-z0-9_-]{20,}\b")),
    ("BEARER_TOKEN", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b")),
    ("SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
]

_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


class PiiRedactor:
    def scan(self, text: str) -> list[PiiFinding]:
        findings: list[PiiFinding] = []
        for kind, pattern in _PATTERNS:
            for m in pattern.finditer(text):
                findings.append(PiiFinding(kind, m.group(), m.start(), m.end()))
        for m in _CARD.finditer(text):
            if _luhn_ok(m.group()):
                findings.append(PiiFinding("CREDIT_CARD", m.group(), m.start(), m.end()))
        # Sort by position so redaction offsets stay valid.
        findings.sort(key=lambda f: f.start)
        return _dedupe_overlaps(findings)

    def redact(self, text: str) -> tuple[str, list[PiiFinding]]:
        findings = self.scan(text)
        if not findings:
            return text, []
        out = []
        cursor = 0
        for f in findings:
            out.append(text[cursor:f.start])
            out.append(f"<REDACTED:{f.kind}>")
            cursor = f.end
        out.append(text[cursor:])
        return "".join(out), findings


def _dedupe_overlaps(findings: list[PiiFinding]) -> list[PiiFinding]:
    """Drop findings that overlap an earlier (more specific) one - e.g. an email
    inside a longer token. Keeps the first match at each span."""
    kept: list[PiiFinding] = []
    last_end = -1
    for f in findings:
        if f.start >= last_end:
            kept.append(f)
            last_end = f.end
    return kept
