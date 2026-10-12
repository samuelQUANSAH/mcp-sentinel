"""High-performance PII and API secret detection and redaction engine for MCP payloads."""

import re
from typing import Any, Dict, List, Set, Tuple


def _luhn_checksum_valid(number_str: str) -> bool:
    """Validate credit card numbers using Luhn checksum algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


class PIIRedactor:
    """Scans and scrubs sensitive personal data and credentials from tool inputs and outputs."""

    # High-precision regular expressions
    PATTERNS: Dict[str, Tuple[re.Pattern, str]] = {
        "SSN": (
            re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
            "[REDACTED_SSN]",
        ),
        "EMAIL": (
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "[REDACTED_EMAIL]",
        ),
        "PHONE": (
            re.compile(r"\b(?:\+?1[-. ]?)?\(?([2-9]\d{2})\)?[-. ]?([2-9]\d{2})[-. ]?(\d{4})\b"),
            "[REDACTED_PHONE]",
        ),
        "AWS_KEY": (
            re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
            "[REDACTED_AWS_KEY]",
        ),
        "OPENAI_KEY": (
            re.compile(r"\bsk-(?:live-|proj-)?[A-Za-z0-9-_]{20,}\b"),
            "[REDACTED_OPENAI_KEY]",
        ),
        "ANTHROPIC_KEY": (
            re.compile(r"\bsk-ant-[A-Za-z0-9-_]{20,}\b"),
            "[REDACTED_ANTHROPIC_KEY]",
        ),
        "GITHUB_TOKEN": (
            re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
            "[REDACTED_GITHUB_TOKEN]",
        ),
        "JWT": (
            re.compile(r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b"),
            "[REDACTED_JWT]",
        ),
    }

    # Credit card regex pre-filter before Luhn verification
    CREDIT_CARD_REGEX = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"
    )

    def __init__(self, enable_pii: bool = True, enable_secrets: bool = True):
        self.enable_pii = enable_pii
        self.enable_secrets = enable_secrets

    def redact_text(self, text: str) -> Tuple[str, List[str]]:
        """Redact sensitive substrings in a string.

        Returns:
            Tuple of (redacted_string, list_of_detected_entity_types)
        """
        if not text or not isinstance(text, str):
            return text, []

        detected_entities: Set[str] = set()
        result = text

        # 1. Check Credit Cards with Luhn validation
        if self.enable_pii:
            for match in self.CREDIT_CARD_REGEX.finditer(result):
                raw_match = match.group(0)
                clean_digits = re.sub(r"\D", "", raw_match)
                if _luhn_checksum_valid(clean_digits):
                    result = result.replace(raw_match, "[REDACTED_CREDIT_CARD]")
                    detected_entities.add("CREDIT_CARD")

        # 2. Check Standard Patterns
        for name, (pattern, placeholder) in self.PATTERNS.items():
            is_secret = "KEY" in name or "TOKEN" in name or "JWT" in name
            if is_secret and not self.enable_secrets:
                continue
            if not is_secret and not self.enable_pii:
                continue

            if pattern.search(result):
                result, count = pattern.subn(placeholder, result)
                if count > 0:
                    detected_entities.add(name)

        return result, sorted(list(detected_entities))

    def redact_value(self, value: Any) -> Tuple[Any, List[str]]:
        """Recursively redact nested data structures (dicts, lists, primitives).

        Returns:
            Tuple of (redacted_data_structure, list_of_detected_entity_types)
        """
        all_detected: Set[str] = set()

        if isinstance(value, str):
            redacted_str, detected = self.redact_text(value)
            all_detected.update(detected)
            return redacted_str, sorted(list(all_detected))

        if isinstance(value, dict):
            new_dict = {}
            for k, v in value.items():
                redacted_v, detected = self.redact_value(v)
                all_detected.update(detected)
                new_dict[k] = redacted_v
            return new_dict, sorted(list(all_detected))

        if isinstance(value, list):
            new_list = []
            for item in value:
                redacted_item, detected = self.redact_value(item)
                all_detected.update(detected)
                new_list.append(redacted_item)
            return new_list, sorted(list(all_detected))

        return value, []
