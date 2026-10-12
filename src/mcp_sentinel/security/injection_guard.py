"""Prompt Injection & Adversarial Jailbreak Guard for MCP Tool Arguments and Inputs.

Detects instruction hijacking, delimiter injection, adversarial roleplay jailbreaks,
data exfiltration triggers, and zero-width steganography in tool payloads.
"""

from enum import Enum
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field


class InjectionCategory(str, Enum):
    """Classification of prompt injection and jailbreak attack patterns."""

    SYSTEM_OVERRIDE = "system_override"
    DELIMITER_HIJACKING = "delimiter_hijacking"
    JAILBREAK_ROLEPLAY = "jailbreak_roleplay"
    DATA_EXFILTRATION = "data_exfiltration"
    STEGANOGRAPHY = "steganography"


class InjectionRiskLevel(str, Enum):
    """Categorized risk severity of detected adversarial content."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InjectionScanResult(BaseModel):
    """Comprehensive result of an adversarial injection scan."""

    is_flagged: bool = Field(default=False, description="True if risk exceeds configured threshold")
    risk_score: float = Field(default=0.0, description="Normalized composite risk score between 0.0 and 1.0")
    risk_level: InjectionRiskLevel = Field(default=InjectionRiskLevel.LOW)
    matched_categories: List[InjectionCategory] = Field(default_factory=list)
    detected_patterns: List[str] = Field(default_factory=list)
    explanation: Optional[str] = None
    sanitized_text: Optional[str] = None


class PromptInjectionGuard:
    """Enterprise-grade semantic and heuristic scanner for adversarial prompt injections."""

    # Unicode zero-width characters used for adversarial steganography
    ZERO_WIDTH_CHARS = re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060\u200E\u200F]")

    # Compiled attack pattern definitions with associated severity weights
    PATTERNS: List[Tuple[InjectionCategory, re.Pattern, float, str]] = [
        # 1. System instruction override & rule wiping
        (
            InjectionCategory.SYSTEM_OVERRIDE,
            re.compile(
                r"(?i)\b(ignore|disregard|forget|override|bypass|neglect)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|commands|directives|guidelines)\b"
            ),
            0.88,
            "Direct instruction override attempt",
        ),
        (
            InjectionCategory.SYSTEM_OVERRIDE,
            re.compile(
                r"(?i)\b(new\s+system\s+instruction|system\s+override|priority\s+override):\s*"
            ),
            0.82,
            "Explicit system directive header injection",
        ),
        (
            InjectionCategory.SYSTEM_OVERRIDE,
            re.compile(
                r"(?i)\b(you\s+must\s+now|from\s+now\s+on\s+you\s+will|you\s+are\s+now\s+required\s+to)\s+(forget|ignore|disregard)\b"
            ),
            0.80,
            "Directive wiping instruction memory",
        ),

        # 2. Delimiter hijacking & token smuggling
        (
            InjectionCategory.DELIMITER_HIJACKING,
            re.compile(
                r"(?i)(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|<<SYS>>|<\/s>|\[INST\]|\[\/INST\])"
            ),
            0.92,
            "Special chat model delimiter / token smuggling",
        ),
        (
            InjectionCategory.DELIMITER_HIJACKING,
            re.compile(
                r"(?i)(---+\s*BEGIN\s+(SYSTEM|PROMPT|INSTRUCTIONS|RULES)|===+\s*NEW\s+(ROLE|SYSTEM|CONTEXT))"
            ),
            0.85,
            "Structured block boundary spoofing",
        ),
        (
            InjectionCategory.DELIMITER_HIJACKING,
            re.compile(
                r"(?i)(```(?:markdown|system)?\s*(?:system|developer|admin)\s*:)"
            ),
            0.78,
            "Markdown fenced codeblock system spoofing",
        ),

        # 3. Jailbreak roleplay & persona bypass
        (
            InjectionCategory.JAILBREAK_ROLEPLAY,
            re.compile(
                r"(?i)\b(DAN\s+mode|Do\s+Anything\s+Now|AIM\s+mode|developer\s+mode\s+enabled|jailbroken\s+mode)\b"
            ),
            0.90,
            "Known jailbreak persona activation (DAN/AIM)",
        ),
        (
            InjectionCategory.JAILBREAK_ROLEPLAY,
            re.compile(
                r"(?i)\b(pretend\s+you\s+have\s+no\s+(rules|limits|safety|ethics)|act\s+as\s+an\s+unfiltered|without\s+any\s+moral\s+guidelines)\b"
            ),
            0.82,
            "Ethical and safety constraint removal request",
        ),
        (
            InjectionCategory.JAILBREAK_ROLEPLAY,
            re.compile(
                r"(?i)\b(hypothetical\s+scenario\s+where\s+you\s+are\s+allowed\s+to\s+bypass)\b"
            ),
            0.72,
            "Hypothetical jailbreak framing bypass",
        ),

        # 4. Out-of-band data exfiltration triggers
        (
            InjectionCategory.DATA_EXFILTRATION,
            re.compile(
                r"(?i)!\[.*?\]\(https?:\/\/[^\s\)]+(?:\?|&)(?:leak|data|token|key|secret|pass|exfil|dump)="
            ),
            0.88,
            "Markdown image beacon data exfiltration vector",
        ),
        (
            InjectionCategory.DATA_EXFILTRATION,
            re.compile(
                r"(?i)\b(curl|wget|fetch|axios\.post)\s+['\"]?https?:\/\/[^\s'\"]+(?:\?|&)(?:exfil|token|key|data|auth)="
            ),
            0.85,
            "Scripted HTTP egress exfiltration vector",
        ),
    ]

    def __init__(self, risk_threshold: float = 0.60):
        """Initialize the PromptInjectionGuard with a sensitivity threshold.

        Args:
            risk_threshold: Minimum risk score (0.0 - 1.0) to flag as a violation.
        """
        self.risk_threshold = risk_threshold

    def scan_text(self, text: str) -> InjectionScanResult:
        """Scan a single string for prompt injection, jailbreaks, and steganography.

        Args:
            text: Input string to inspect.

        Returns:
            InjectionScanResult with risk score, matched categories, and explanations.
        """
        if not text or not isinstance(text, str):
            return InjectionScanResult(is_flagged=False, risk_score=0.0)

        matched_categories: Set[InjectionCategory] = set()
        detected_patterns: List[str] = []
        pattern_weights: List[float] = []

        # 1. Check for zero-width steganography characters
        zw_matches = self.ZERO_WIDTH_CHARS.findall(text)
        sanitized = text
        if zw_matches:
            matched_categories.add(InjectionCategory.STEGANOGRAPHY)
            detected_patterns.append(f"Steganography: {len(zw_matches)} invisible zero-width unicode characters detected")
            pattern_weights.append(min(0.50, 0.15 + (len(zw_matches) * 0.05)))
            sanitized = self.ZERO_WIDTH_CHARS.sub("", text)

        # 2. Heuristic regex pattern scanning against raw and steganography-cleaned text
        for category, regex, weight, description in self.PATTERNS:
            if regex.search(text) or (sanitized != text and regex.search(sanitized)):
                matched_categories.add(category)
                detected_patterns.append(f"{category.value}: {description}")
                pattern_weights.append(weight)

        # 3. Calculate composite non-linear risk score
        # Using probability union formula: P(A or B) = 1 - (1 - P(A)) * (1 - P(B))
        if not pattern_weights:
            risk_score = 0.0
        else:
            product = 1.0
            for w in pattern_weights:
                product *= (1.0 - w)
            risk_score = min(1.0, 1.0 - product)

        # Determine qualitative risk level
        if risk_score >= 0.80:
            level = InjectionRiskLevel.CRITICAL
        elif risk_score >= 0.60:
            level = InjectionRiskLevel.HIGH
        elif risk_score >= 0.30:
            level = InjectionRiskLevel.MEDIUM
        else:
            level = InjectionRiskLevel.LOW

        is_flagged = risk_score >= self.risk_threshold

        explanation = "; ".join(detected_patterns) if detected_patterns else None

        return InjectionScanResult(
            is_flagged=is_flagged,
            risk_score=round(risk_score, 3),
            risk_level=level,
            matched_categories=sorted(list(matched_categories), key=lambda x: x.value),
            detected_patterns=detected_patterns,
            explanation=explanation,
            sanitized_text=sanitized if zw_matches else None,
        )

    def scan_value(self, value: Any) -> InjectionScanResult:
        """Recursively scan arbitrary nested Python structures (dicts, lists, strings).

        Aggregates results and returns the highest severity violation found.
        """
        if isinstance(value, str):
            return self.scan_text(value)

        if isinstance(value, dict):
            highest_result = InjectionScanResult(is_flagged=False, risk_score=0.0)
            for k, v in value.items():
                # Scan dict key
                k_res = self.scan_value(k)
                if k_res.risk_score > highest_result.risk_score:
                    highest_result = k_res

                # Scan dict value
                v_res = self.scan_value(v)
                if v_res.risk_score > highest_result.risk_score:
                    highest_result = v_res

            return highest_result

        if isinstance(value, (list, tuple, set)):
            highest_result = InjectionScanResult(is_flagged=False, risk_score=0.0)
            for item in value:
                item_res = self.scan_value(item)
                if item_res.risk_score > highest_result.risk_score:
                    highest_result = item_res
            return highest_result

        return InjectionScanResult(is_flagged=False, risk_score=0.0)
