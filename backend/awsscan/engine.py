"""Run all rules over an inventory snapshot and score the results."""

from typing import Any, Optional

from .models import Finding
from .rules import load_all
from .scoring import load_weights, score_finding


def scan_inventory(
    inventory: dict[str, Any],
    *,
    weights: Optional[dict[str, Any]] = None,
    rule_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Return {findings, not_assessed, summary}. Findings sorted by risk, highest first."""
    w = weights or load_weights()
    findings: list[Finding] = []
    crashed: list[dict[str, str]] = []
    for rid, r in load_all().items():
        if rule_ids and rid not in rule_ids:
            continue
        try:
            findings.extend(r.fn(inventory, r))
        except Exception as e:  # noqa: BLE001  a broken rule must not hide the others
            crashed.append({"service": rid, "message": f"rule crashed: {type(e).__name__}: {e}"})
    for f in findings:
        score_finding(f, w)
    findings.sort(key=lambda f: f.risk_score, reverse=True)

    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        buckets[f.risk_bucket] += 1
    return {
        "account_id": inventory.get("account_id", ""),
        "findings": [f.to_dict() for f in findings],
        # AccessDenied etc. surface here; they are never a silent pass
        "not_assessed": list(inventory.get("errors", [])) + crashed,
        "summary": {"total": len(findings), **buckets},
    }
