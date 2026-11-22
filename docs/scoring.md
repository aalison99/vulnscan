# Context-aware risk scoring

Implemented in `backend/awsscan/scoring.py`; weights in `backend/awsscan/weights.yaml`.

## Formula

```
risk = 100 x clamp( base/10 x exploitability x exposure x context )
```

| Factor | Range | Source |
|---|---|---|
| base | 0-1 | Rule's `base_severity` (1-10) divided by 10. Chosen per rule from CIS/AWS guidance. |
| exploitability | 0.3-1.0 | Constant per rule: how easy the issue is to abuse (world-readable bucket 1.0, missing log validation 0.5). |
| exposure | 0.6-1.0 | `internet` 1.0, `cross_account` 0.8, `internal` 0.6. Set by the rule for each finding. |
| context | 0.4-1.0 | Environment tag: `prod` 1.0, `staging` 0.7, `test` 0.4, untagged 0.8. Adds 0.2 (capped at 1.0) when a data-classification tag marks the data sensitive. |

Buckets: critical >= 70, high >= 50, medium >= 30, otherwise low.

Every finding returns its breakdown (`base`, `exploitability`, `exposure`, `context`, `final`), shown in the dashboard drawer.

## Environment detection

1. Tag `Environment`, `env` or `stage` (case-insensitive). Values containing prod/production/prd/live map to `prod`; staging/stage/preprod/uat to `staging`; dev/test/qa/sandbox/demo/tmp to `test`.
2. If there is no tag, the resource name is checked for the same words. The result is labelled `(heuristic)` in the output.
3. Otherwise `untagged`.

## Flat baseline

`score_finding(f, context=False)` ignores every factor except base severity. The API's `sort=severity` and the dashboard's "Flat severity" toggle show this ordering, so the effect of context is visible on the same findings.

## Tested properties (`backend/tests/test_scoring.py`)

- A prod finding never scores below its test-tagged twin.
- An internet-exposed finding scores above the same internal one.
- Flat mode gives prod and test twins the same score.
- Factors multiply to the final value; scores stay within 0-100.
- Weights are not mutated by scoring.

## Limitations

- The multipliers are chosen by judgement, not fitted to data. Their values and the bucket thresholds are not yet justified by a sensitivity analysis.
- Exposure is set per rule from the resource's own configuration (for example a 0.0.0.0/0 rule). It does not trace routes, NACLs or an internet gateway.
- Context depends on tags. Untagged accounts degrade towards the 0.8 default.
- Evaluation against a seeded sandbox account and against Prowler has not been done.
