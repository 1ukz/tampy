"""Typed data models shared across TAMPY phases.

Centralising these as Pydantic models (P0) removes the fragile dict access and
hand-rolled JSON parsing that used to live in phases 3 and 4, and gives us a
single schema we can hand to the LLM for structured output and validate the
response against.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ParameterLocation(str, Enum):
    URL_PATH = "url_path"
    QUERY = "query"
    HEADERS = "headers"
    BODY = "body"


class Verdict(str, Enum):
    """Result of the deterministic oracle after a tamper+replay."""

    CONFIRMED = "confirmed"   # the response clearly shows the tamper took effect
    LIKELY = "likely"         # strong but not conclusive signal
    REJECTED = "rejected"     # server rejected or ignored the tamper
    INCONCLUSIVE = "inconclusive"  # not enough signal; may warrant an LLM judge
    ERROR = "error"           # replay/transport failure


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModifiedRequest(BaseModel):
    """The example request the LLM proposes, with a single tampered value."""

    model_config = {"extra": "ignore"}

    url: str
    method: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body_data: Optional[str] = None


class Finding(BaseModel):
    """One potential business-logic weakness proposed by the analyzer.

    Field names match the legacy JSON contract so existing analysis logs keep
    loading, but everything is now validated and typed.
    """

    model_config = {"extra": "ignore"}

    control_id: str
    packet_index: int
    parameter_name: str
    parameter_location: ParameterLocation
    vulnerability_description: str
    exploitation_hypothesis: str
    test_payload: str
    modified_request_example: ModifiedRequest

    # Optional enrichment (new in the 2026 rework). Defaulted so old logs load.
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    cwe: Optional[str] = None

    @field_validator("packet_index", mode="before")
    @classmethod
    def _coerce_index(cls, v: Any) -> Any:
        # Models occasionally emit the index as a string; accept it.
        if isinstance(v, str) and v.strip().lstrip("-").isdigit():
            return int(v.strip())
        return v

    @field_validator("test_payload", "parameter_name", mode="before")
    @classmethod
    def _coerce_str(cls, v: Any) -> Any:
        # Numeric payloads/segment indices may arrive as int/float.
        if isinstance(v, (int, float)):
            return str(v)
        return v


class OracleResult(BaseModel):
    """Deterministic assessment of whether a tamper took effect."""

    model_config = {"extra": "ignore"}

    verdict: Verdict
    reason: str
    baseline_status: Optional[int] = None
    tampered_status: Optional[int] = None
    signals: Dict[str, Any] = Field(default_factory=dict)


class FindingResult(BaseModel):
    """A finding paired with the outcome of verifying it."""

    model_config = {"extra": "ignore"}

    finding: Finding
    oracle: Optional[OracleResult] = None


def parse_findings(raw: List[Dict[str, Any]]) -> List[Finding]:
    """Validate a list of raw finding dicts into Finding models.

    Invalid entries are skipped rather than aborting the whole run; the caller
    gets back whatever was well-formed.
    """
    findings: List[Finding] = []
    for item in raw:
        try:
            findings.append(Finding.model_validate(item))
        except Exception:
            continue
    return findings
