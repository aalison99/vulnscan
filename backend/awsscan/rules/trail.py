from . import rule


def _acct(inv):
    return f"arn:aws:cloudtrail::{inv['account_id']}:account"


@rule(id="log-no-multiregion-trail", title="No multi-region CloudTrail is logging", cis_id="3.1",
      category="logging", base_severity=7, exploitability=0.6,
      remediation="aws cloudtrail create-trail --name <n> --s3-bucket-name <b> --is-multi-region-trail "
                  "&& aws cloudtrail start-logging --name <n>")
def no_trail(inv, r):
    trails = inv.get("cloudtrail", {}).get("trails", [])
    if not any(t.get("multi_region") and t.get("is_logging") for t in trails):
        return [r.finding(arn=_acct(inv), rtype="cloudtrail", region="global",
                          description="No active multi-region CloudTrail trail exists.",
                          evidence={"trails": [t["name"] for t in trails]}, tags={}, exposure="internal")]
    return []


@rule(id="log-no-validation", title="CloudTrail log file validation disabled", cis_id="3.2",
      category="logging", base_severity=5, exploitability=0.5,
      remediation="aws cloudtrail update-trail --name <n> --enable-log-file-validation")
def no_validation(inv, r):
    return [
        r.finding(arn=t["arn"], rtype="cloudtrail", region=t.get("region", "global"),
                  description=f"Trail {t['name']} has no log file validation.",
                  evidence={"log_validation": False}, tags=t.get("tags", {}), exposure="internal")
        for t in inv.get("cloudtrail", {}).get("trails", []) if not t.get("log_validation")
    ]
