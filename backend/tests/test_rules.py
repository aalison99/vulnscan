from awsscan import scan_inventory
from awsscan.rules import load_all
from awsscan.sample import sample_inventory


def ids(res):
    return {f["rule_id"] for f in res["findings"]}


def test_every_rule_has_unique_id_and_cis():
    reg = load_all()
    assert len(reg) >= 20
    assert all(r.cis_id and r.remediation for r in reg.values())


def test_sample_detects_expected_rules():
    got = ids(scan_inventory(sample_inventory()))
    expected = {"iam-root-access-key", "iam-root-no-mfa", "iam-password-policy-weak", "iam-user-no-mfa",
                "iam-key-not-rotated", "iam-unused-credentials", "iam-admin-policy", "iam-user-direct-policy",
                "s3-public-access", "s3-no-block-public-access", "s3-no-encryption", "s3-no-tls-enforced",
                "net-sg-open-admin", "net-sg-open-db", "net-rds-public", "enc-rds-unencrypted",
                "enc-ebs-default-off", "enc-kms-no-rotation", "log-no-multiregion-trail", "log-no-validation"}
    assert expected <= got


def test_clean_resources_yield_no_findings():
    res = scan_inventory(sample_inventory())
    arns = {f["resource_arn"] for f in res["findings"]}
    assert "arn:aws:s3:::logs-clean" not in arns
    assert not any("carol-clean" in a for a in arns)


def test_prod_twin_outranks_test_twin_in_sample():
    res = scan_inventory(sample_inventory())
    score = {(f["rule_id"], f["resource_arn"]): f["risk_score"] for f in res["findings"]}
    pairs = [("s3-public-access", "arn:aws:s3:::customer-data-prod", "arn:aws:s3:::customer-data-test"),
             ("net-sg-open-admin", "arn:aws:ec2:ap-south-1:111122223333:security-group/sg-0prod0001",
              "arn:aws:ec2:ap-south-1:111122223333:security-group/sg-0test0001"),
             ("net-rds-public", "arn:aws:rds:ap-south-1:111122223333:db:orders-prod",
              "arn:aws:rds:ap-south-1:111122223333:db:orders-test")]
    for rid, p, t in pairs:
        assert score[(rid, p)] > score[(rid, t)]


def test_findings_sorted_and_not_assessed_surfaced():
    res = scan_inventory(sample_inventory())
    scores = [f["risk_score"] for f in res["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert res["not_assessed"]  # AccessDenied is visible, never a silent pass
    assert res["summary"]["total"] == len(res["findings"])


def test_crashing_rule_reported_not_fatal():
    inv = sample_inventory()
    del inv["iam"]  # rules touching iam will KeyError
    res = scan_inventory(inv)
    assert any("rule crashed" in e["message"] for e in res["not_assessed"])
    assert res["findings"]  # other rules still ran
