from . import rule



@rule(id="iam-root-access-key", title="Root account has an access key", cis_id="1.4", category="iam",
      base_severity=10, exploitability=1.0,
      remediation="Delete root access keys: aws iam delete-access-key --user-name <root> (use the console for root).")
def root_access_key(inv, r):
    root = inv["iam"].get("root", {})
    if root.get("access_keys", 0) > 0:
        return [r.finding(arn=f"arn:aws:iam::{inv['account_id']}:root", rtype="iam-root", region="global",
                          description="The root user has active access keys.",
                          evidence={"access_keys": root["access_keys"]}, tags={}, exposure="internet")]
    return []


@rule(id="iam-root-no-mfa", title="Root account has no MFA", cis_id="1.5", category="iam",
      base_severity=9, exploitability=0.8,
      remediation="Enable a hardware or virtual MFA device for the root user in the IAM console.")
def root_no_mfa(inv, r):
    root = inv["iam"].get("root", {})
    if root and not root.get("mfa", False):
        return [r.finding(arn=f"arn:aws:iam::{inv['account_id']}:root", rtype="iam-root", region="global",
                          description="Root user MFA is not enabled.", evidence={"mfa": False},
                          tags={}, exposure="internet")]
    return []


@rule(id="iam-password-policy-weak", title="Password policy minimum length below 14", cis_id="1.8",
      category="iam", base_severity=5, exploitability=0.6,
      remediation="aws iam update-account-password-policy --minimum-password-length 14")
def password_policy(inv, r):
    pp = inv["iam"].get("password_policy")
    if pp is None or pp.get("minimum_length", 0) < 14:
        return [r.finding(arn=f"arn:aws:iam::{inv['account_id']}:account-password-policy",
                          rtype="iam-password-policy", region="global",
                          description="Account password policy is missing or shorter than 14 characters.",
                          evidence={"policy": pp}, tags={}, exposure="internet")]
    return []


@rule(id="iam-user-no-mfa", title="Console user without MFA", cis_id="1.10", category="iam",
      base_severity=8, exploitability=0.8,
      remediation="Enrol an MFA device: aws iam enable-mfa-device ... or via the console.")
def user_no_mfa(inv, r):
    return [
        r.finding(arn=u["arn"], rtype="iam-user", region="global",
                  description=f"User {u['name']} has console access but no MFA.",
                  evidence={"console_access": True, "mfa": False}, tags=u.get("tags", {}),
                  exposure="internet")
        for u in inv["iam"].get("users", []) if u.get("console_access") and not u.get("mfa_enabled")
    ]


@rule(id="iam-unused-credentials", title="Credentials unused for more than 45 days", cis_id="1.12",
      category="iam", base_severity=5, exploitability=0.6,
      remediation="Disable or delete unused credentials: aws iam update-access-key --status Inactive ...")
def unused_credentials(inv, r):
    out = []
    for u in inv["iam"].get("users", []):
        stale = [k["id"] for k in u.get("access_keys", [])
                 if k.get("active") and (k.get("last_used_days") is None or k["last_used_days"] > 45)]
        if stale:
            out.append(r.finding(arn=u["arn"], rtype="iam-user", region="global",
                                 description=f"User {u['name']} has active keys unused for over 45 days.",
                                 evidence={"stale_keys": stale}, tags=u.get("tags", {}), exposure="internet"))
    return out


@rule(id="iam-key-not-rotated", title="Access key older than 90 days", cis_id="1.14", category="iam",
      base_severity=6, exploitability=0.7,
      remediation="Rotate the key: create a new key, update consumers, then delete the old one.")
def key_not_rotated(inv, r):
    out = []
    for u in inv["iam"].get("users", []):
        old = [k["id"] for k in u.get("access_keys", []) if k.get("active") and k.get("age_days", 0) > 90]
        if old:
            out.append(r.finding(arn=u["arn"], rtype="iam-user", region="global",
                                 description=f"User {u['name']} has access keys older than 90 days.",
                                 evidence={"old_keys": old}, tags=u.get("tags", {}), exposure="internet"))
    return out


@rule(id="iam-user-direct-policy", title="Policy attached directly to a user", cis_id="1.15",
      category="iam", base_severity=3, exploitability=0.5,
      remediation="Attach policies to groups or roles instead of users.")
def direct_policy(inv, r):
    return [
        r.finding(arn=u["arn"], rtype="iam-user", region="global",
                  description=f"User {u['name']} has policies attached directly.",
                  evidence={"policies": [p["name"] for p in u["attached_policies"]]},
                  tags=u.get("tags", {}), exposure="internal")
        for u in inv["iam"].get("users", []) if u.get("attached_policies")
    ]


@rule(id="iam-admin-policy", title="Policy grants full *:* administrative access", cis_id="1.16",
      category="iam", base_severity=9, exploitability=0.9,
      remediation="Replace the *:* policy with least-privilege permissions.")
def admin_policy(inv, r):
    out = []
    for u in inv["iam"].get("users", []):
        admin = [p["name"] for p in u.get("attached_policies", []) if p.get("admin")]
        if admin:
            out.append(r.finding(arn=u["arn"], rtype="iam-user", region="global",
                                 description=f"User {u['name']} holds a full-admin policy.",
                                 evidence={"policies": admin}, tags=u.get("tags", {}), exposure="internal"))
    return out
