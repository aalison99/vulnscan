import copy

from awsscan.models import Finding
from awsscan.scoring import environment_of, load_weights, score_finding


def mk(env=None, exposure="internet", base=9.0, expl=0.9, tags=None, arn="arn:aws:s3:::thing"):
    t = dict(tags or {})
    if env:
        t["Environment"] = env
    return Finding("r", "1.1", "s3", "t", "d", arn, "x", "g", base, expl, exposure, "fix", tags=t)


def test_prod_never_below_test_twin():
    w = load_weights()
    for exp in ("internet", "cross_account", "internal"):
        for base in (3, 6, 9):
            assert score_finding(mk("prod", exp, base), w).risk_score >= score_finding(mk("test", exp, base), w).risk_score
    assert score_finding(mk("prod"), w).risk_score > score_finding(mk("test"), w).risk_score


def test_internet_never_below_internal():
    w = load_weights()
    assert score_finding(mk("prod", "internet"), w).risk_score > score_finding(mk("prod", "internal"), w).risk_score


def test_flat_mode_ignores_context():
    w = load_weights()
    a = score_finding(mk("prod"), w, context=False).risk_score
    b = score_finding(mk("test"), w, context=False).risk_score
    assert a == b


def test_breakdown_multiplies_to_final():
    f = score_finding(mk("prod"))
    b = f.breakdown
    assert abs(b["base"] * b["exploitability"] * b["exposure"] * b["context"] - b["final"]) < 0.01
    assert 0 <= f.risk_score <= 100


def test_sensitivity_raises_context_but_caps_at_one():
    w = load_weights()
    plain = score_finding(mk("test"), w)
    sens = score_finding(mk("test", tags={"data-classification": "confidential"}), w)
    assert sens.risk_score > plain.risk_score
    assert score_finding(mk("prod", tags={"data-classification": "pii"}), w).breakdown["context"] == 1.0


def test_untagged_and_name_heuristic():
    assert environment_of({}, "") == ("untagged", False)
    assert environment_of({}, "orders-prod") == ("prod", True)
    assert environment_of({"Environment": "Production"}, "x-test") == ("prod", False)
    assert environment_of({"env": "dev"}, "")[0] == "test"


def test_weights_not_mutated():
    w = load_weights()
    before = copy.deepcopy(w)
    score_finding(mk("prod"), w)
    assert w == before
