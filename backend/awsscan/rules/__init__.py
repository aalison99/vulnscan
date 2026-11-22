"""Rule registry. A rule is a pure function: inventory dict in, list of Finding out."""

from dataclasses import dataclass
from typing import Callable

from ..models import Finding

REGISTRY: dict[str, "Rule"] = {}


@dataclass
class Rule:
    id: str
    title: str
    cis_id: str  # CIS AWS Foundations v3.0; numbering NOT yet verified against the PDF
    category: str
    base_severity: float
    exploitability: float
    remediation: str
    fn: Callable[[dict, "Rule"], list[Finding]]

    def finding(self, *, arn: str, rtype: str, region: str, description: str,
                evidence: dict, tags: dict, exposure: str) -> Finding:
        return Finding(
            rule_id=self.id, cis_id=self.cis_id, category=self.category, title=self.title,
            description=description, resource_arn=arn, resource_type=rtype, region=region,
            base_severity=self.base_severity, exploitability=self.exploitability,
            exposure=exposure, remediation=self.remediation, evidence=evidence, tags=tags or {},
        )


def rule(*, id, title, cis_id, category, base_severity, exploitability, remediation):
    def deco(fn):
        if id in REGISTRY:
            raise ValueError(f"duplicate rule id {id}")
        REGISTRY[id] = Rule(id, title, cis_id, category, base_severity, exploitability, remediation, fn)
        return fn
    return deco


def load_all() -> dict[str, Rule]:
    from . import encryption, iam, network, s3, trail  # noqa: F401  (registers rules)
    return REGISTRY
