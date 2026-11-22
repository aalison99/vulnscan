"""Built-in demo inventory: the same misconfiguration classes in prod- and test-tagged copies.

Lets the dashboard and CLI run without an AWS account (demo/viva fallback).
Contains no real account data.
"""

ACCOUNT = "111122223333"


def _bucket(name, env, **kw):
    row = {"name": name, "arn": f"arn:aws:s3:::{name}", "region": "ap-south-1",
           "tags": {"Environment": env, "data-classification": "confidential" if env == "prod" else "public"},
           "public_access_block": None, "acl_public": True, "policy_public": False,
           "encryption": False, "tls_enforced": False}
    row.update(kw)
    return row


def _sg(sgid, env, port=22):
    return {"id": sgid, "name": f"{env}-app", "region": "ap-south-1", "tags": {"Environment": env},
            "arn": f"arn:aws:ec2:ap-south-1:{ACCOUNT}:security-group/{sgid}",
            "ingress": [{"from": port, "to": port, "proto": "tcp", "cidrs": ["0.0.0.0/0"]}]}


def _user(name, env, mfa):
    return {"name": name, "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "tags": {"Environment": env},
            "console_access": True, "mfa_enabled": mfa,
            "access_keys": [{"id": f"AKIA{name.upper()[:8]}", "active": True, "age_days": 200, "last_used_days": 80}],
            "attached_policies": [{"name": "AdministratorAccess", "admin": True}]}


def _rds(name, env):
    return {"id": name, "arn": f"arn:aws:rds:ap-south-1:{ACCOUNT}:db:{name}", "region": "ap-south-1",
            "tags": {"Environment": env}, "publicly_accessible": True, "storage_encrypted": False}


def sample_inventory() -> dict:
    return {
        "account_id": ACCOUNT, "collected_at": "2026-11-23T00:00:00+00:00", "regions": ["ap-south-1"],
        "iam": {
            "root": {"access_keys": 1, "mfa": False},
            "password_policy": {"minimum_length": 8},
            "users": [_user("alice-prod", "prod", False), _user("bob-test", "test", False),
                      {**_user("carol-clean", "prod", True), "access_keys": [], "attached_policies": []}],
        },
        "s3": {"buckets": [
            _bucket("customer-data-prod", "prod"), _bucket("customer-data-test", "test"),
            _bucket("logs-clean", "prod", acl_public=False, encryption=True, tls_enforced=True,
                    public_access_block={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                         "BlockPublicPolicy": True, "RestrictPublicBuckets": True}),
        ]},
        "ec2": {"security_groups": [_sg("sg-0prod0001", "prod", 22), _sg("sg-0test0001", "test", 22),
                                    _sg("sg-0prod0002", "prod", 3306)],
                "ebs_default_encryption": {"ap-south-1": False}},
        "rds": {"instances": [_rds("orders-prod", "prod"), _rds("orders-test", "test")]},
        "cloudtrail": {"trails": [{"name": "old-trail", "arn": f"arn:aws:cloudtrail:ap-south-1:{ACCOUNT}:trail/old-trail",
                                   "region": "ap-south-1", "multi_region": False, "log_validation": False,
                                   "is_logging": True}]},
        "kms": {"keys": [{"id": "key-prod-1", "arn": f"arn:aws:kms:ap-south-1:{ACCOUNT}:key/key-prod-1",
                          "region": "ap-south-1", "tags": {"Environment": "prod"}, "rotation_enabled": False}]},
        "errors": [{"service": "config:describe", "message": "AccessDenied: not assessed (sample)"}],
    }
