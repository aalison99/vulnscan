"""Context-aware risk model. Pure functions: no AWS calls, no I/O besides loading weights."""

from pathlib import Path
from typing import Any, Optional

import yaml

from .models import EXPOSURES, Finding

_DEFAULT_PATH = Path(__file__).with_name("weights.yaml")
_ENV_KEYS = ("environment", "env", "stage")
_SENSITIVITY_KEYS = ("data-classification", "dataclassification", "classification", "sensitivity")
_PROD_WORDS = ("prod", "production", "prd", "live")
_STAGING_WORDS = ("staging", "stage", "preprod", "uat")
_TEST_WORDS = ("dev", "test", "qa", "sandbox", "demo", "tmp")


def load_weights(path: Optional[str] = None) -> dict[str, Any]:
    with open(path or _DEFAULT_PATH, encoding="utf-8") as fh:
        w = yaml.safe_load(fh)
    for label in EXPOSURES:
        if label not in w["exposure"]:
            raise ValueError(f"weights: missing exposure '{label}'")
    return w


def _tag(tags: dict[str, str], keys: tuple[str, ...]) -> Optional[str]:
    lowered = {k.lower(): v for k, v in (tags or {}).items()}
    for k in keys:
        if k in lowered:
            return str(lowered[k]).lower()
    return None


def _classify_env(text: str) -> Optional[str]:
    text = text.lower()
    words = [w for w in text.replace("_", "-").replace(".", "-").replace("/", "-").split("-") if w]
    for group, name in ((_PROD_WORDS, "prod"), (_STAGING_WORDS, "staging"), (_TEST_WORDS, "test")):
        if any(w in group for w in words):
            return name
    return None


def environment_of(tags: dict[str, str], resource_name: str = "") -> tuple[str, bool]:
    """Return (env, from_heuristic). Tag wins; name heuristic is the flagged fallback."""
    tagged = _tag(tags, _ENV_KEYS)
    if tagged:
        return (_classify_env(tagged) or "untagged", False)
    guess = _classify_env(resource_name) if resource_name else None
    if guess:
        return guess, True
    return "untagged", False


def score_finding(
    f: Finding, weights: Optional[dict[str, Any]] = None, *, context: bool = True
) -> Finding:
    """Fill risk fields in place. context=False gives the flat (severity-only) baseline."""
    w = weights or load_weights()
    name = f.resource_arn.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
    env, heuristic = environment_of(f.tags, name)
    f.environment = env + (" (heuristic)" if heuristic else "")

    base = f.base_severity / 10
    exposure = w["exposure"][f.exposure] if context else 1.0
    ctx = w["environment"][env] if context else 1.0
    sensitivity = _tag(f.tags, _SENSITIVITY_KEYS)
    if context and sensitivity in w["sensitive_values"]:
        ctx = min(1.0, ctx + w["sensitivity_bonus"])
    expl = f.exploitability if context else 1.0

    final = max(0.0, min(1.0, base * expl * exposure * ctx))
    f.breakdown = {
        "base": round(base, 3),
        "exploitability": round(expl, 3),
        "exposure": round(exposure, 3),
        "context": round(ctx, 3),
        "final": round(final, 3),
    }
    f.risk_score = round(final * 100, 1)
    b = w["buckets"]
    f.risk_bucket = (
        "critical" if f.risk_score >= b["critical"]
        else "high" if f.risk_score >= b["high"]
        else "medium" if f.risk_score >= b["medium"]
        else "low"
    )
    return f
