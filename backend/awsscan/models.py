"""Finding schema. Keep stable: the API and dashboard depend on it."""

from dataclasses import asdict, dataclass, field
from typing import Any

# exposure labels, ordered most to least exposed
EXPOSURES = ("internet", "cross_account", "internal")


@dataclass
class Finding:
    rule_id: str
    cis_id: str
    category: str  # iam | s3 | network | logging | encryption
    title: str
    description: str
    resource_arn: str
    resource_type: str
    region: str
    base_severity: float  # 1-10, from CIS/AWS guidance
    exploitability: float  # 0.5-1.0, how easy to abuse (set per rule)
    exposure: str  # one of EXPOSURES
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    # filled by scoring.score_finding
    risk_score: float = 0.0
    risk_bucket: str = ""
    breakdown: dict[str, float] = field(default_factory=dict)
    environment: str = ""
    status: str = "open"  # open | acknowledged | fixed | accepted-risk

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def severity_label(base: float) -> str:
    """Flat label from base severity alone (what a context-blind tool shows)."""
    if base >= 9:
        return "CRITICAL"
    if base >= 7:
        return "HIGH"
    if base >= 4:
        return "MEDIUM"
    return "LOW"
