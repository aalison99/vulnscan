"""Collect an inventory snapshot from AWS with boto3. Read-only calls only."""

import json
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

_CFG = Config(retries={"max_attempts": 5, "mode": "standard"}, read_timeout=20, connect_timeout=10)


def _tags(raw: Any) -> dict[str, str]:
    if isinstance(raw, dict):
        return raw
    return {t["Key"]: t["Value"] for t in (raw or [])}


def _days(dt: Optional[datetime]) -> Optional[int]:
    return None if dt is None else (datetime.now(timezone.utc) - dt).days


def _guard(inv: dict, service: str, fn: Callable[[], Any], default: Any = None) -> Any:
    """Run a collector; record failures as 'not assessed' instead of passing silently."""
    try:
        return fn()
    except (ClientError, BotoCoreError) as e:
        code = e.response["Error"]["Code"] if isinstance(e, ClientError) else type(e).__name__
        inv["errors"].append({"service": service, "message": f"{code}: {e}"[:300]})
        return default


def _is_public_policy(doc: dict) -> bool:
    for st in doc.get("Statement", []):
        if st.get("Effect") != "Allow" or "Condition" in st:
            continue
        p = st.get("Principal")
        if p == "*" or (isinstance(p, dict) and "*" in (p.get("AWS"), *(p.get("AWS") or []))):
            return True
    return False


def _is_admin(doc: dict) -> bool:
    for st in doc.get("Statement", []):
        if st.get("Effect") == "Allow":
            acts, res = st.get("Action"), st.get("Resource")
            acts = [acts] if isinstance(acts, str) else acts or []
            res = [res] if isinstance(res, str) else res or []
            if "*" in acts and "*" in res:
                return True
    return False


def _has_login_profile(iam, inv, name) -> bool:
    try:
        iam.get_login_profile(UserName=name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            inv["errors"].append({"service": f"iam:login-profile:{name}", "message": str(e)[:300]})
        return False


def collect_iam(session, inv):
    iam = session.client("iam", config=_CFG)
    out = inv["iam"]
    out["password_policy"] = _guard(
        inv, "iam:password-policy",
        lambda: {"minimum_length": iam.get_account_password_policy()["PasswordPolicy"]["MinimumPasswordLength"]},
    )
    summary = _guard(inv, "iam:account-summary", lambda: iam.get_account_summary()["SummaryMap"], {})
    if summary:
        out["root"] = {"access_keys": summary.get("AccountAccessKeysPresent", 0),
                       "mfa": bool(summary.get("AccountMFAEnabled", 0))}
    users = []
    for u in _guard(inv, "iam:list-users", lambda: iam.get_paginator("list_users").paginate().build_full_result()["Users"], []):
        name = u["UserName"]
        keys = _guard(inv, f"iam:keys:{name}", lambda: iam.list_access_keys(UserName=name)["AccessKeyMetadata"], [])
        key_rows = []
        for k in keys:
            lu = _guard(inv, f"iam:key-last-used:{name}",
                        lambda: iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])["AccessKeyLastUsed"], {})
            key_rows.append({"id": k["AccessKeyId"], "active": k["Status"] == "Active",
                             "age_days": _days(k["CreateDate"]), "last_used_days": _days(lu.get("LastUsedDate"))
                             if lu.get("LastUsedDate") else None})
        mfa = _guard(inv, f"iam:mfa:{name}", lambda: iam.list_mfa_devices(UserName=name)["MFADevices"], [])
        console = _has_login_profile(iam, inv, name)
        pols = []
        for p in _guard(inv, f"iam:policies:{name}", lambda: iam.list_attached_user_policies(UserName=name)["AttachedPolicies"], []):
            doc = _guard(inv, f"iam:policy-doc:{p['PolicyName']}", lambda: iam.get_policy_version(
                PolicyArn=p["PolicyArn"],
                VersionId=iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"])["PolicyVersion"]["Document"], {})
            admin = _is_admin(doc) if doc else False
            pols.append({"name": p["PolicyName"], "admin": admin})
        tags = _guard(inv, f"iam:tags:{name}", lambda: _tags(iam.list_user_tags(UserName=name)["Tags"]), {})
        users.append({"name": name, "arn": u["Arn"], "tags": tags, "console_access": bool(console),
                      "mfa_enabled": bool(mfa), "access_keys": key_rows, "attached_policies": pols})
    out["users"] = users


def collect_s3(session, inv):
    s3 = session.client("s3", config=_CFG)
    out = []
    for b in _guard(inv, "s3:list-buckets", lambda: s3.list_buckets()["Buckets"], []):
        n = b["Name"]
        row: dict[str, Any] = {"name": n, "arn": f"arn:aws:s3:::{n}", "region": "global"}
        row["tags"] = _guard(inv, f"s3:tags:{n}", lambda: _tags(s3.get_bucket_tagging(Bucket=n)["TagSet"]), {})
        try:
            row["public_access_block"] = {
                k: v for k, v in s3.get_public_access_block(Bucket=n)["PublicAccessBlockConfiguration"].items()}
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                row["public_access_block"] = None
            else:
                inv["errors"].append({"service": f"s3:pab:{n}", "message": str(e)[:300]})
        grants = _guard(inv, f"s3:acl:{n}", lambda: s3.get_bucket_acl(Bucket=n)["Grants"], [])
        row["acl_public"] = any(g["Grantee"].get("URI", "").endswith(("AllUsers", "AuthenticatedUsers")) for g in grants)
        try:
            doc = json.loads(s3.get_bucket_policy(Bucket=n)["Policy"])
            row["policy_public"] = _is_public_policy(doc)
            row["tls_enforced"] = any(
                st.get("Effect") == "Deny" and "aws:SecureTransport" in json.dumps(st.get("Condition", {}))
                for st in doc.get("Statement", []))
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                inv["errors"].append({"service": f"s3:policy:{n}", "message": str(e)[:300]})
            row["policy_public"], row["tls_enforced"] = False, False
        try:
            s3.get_bucket_encryption(Bucket=n)
            row["encryption"] = True
        except ClientError as e:
            if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                inv["errors"].append({"service": f"s3:encryption:{n}", "message": str(e)[:300]})
            row["encryption"] = False
        out.append(row)
    inv["s3"]["buckets"] = out


def collect_region(session, region, account_id, inv):
    ec2 = session.client("ec2", region_name=region, config=_CFG)
    for sg in _guard(inv, f"ec2:sg:{region}", lambda: ec2.describe_security_groups()["SecurityGroups"], []):
        ingress = [{"from": p.get("FromPort", 0), "to": p.get("ToPort", 65535), "proto": p["IpProtocol"],
                    "cidrs": [r["CidrIp"] for r in p.get("IpRanges", [])] + [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])]}
                   for p in sg.get("IpPermissions", [])]
        inv["ec2"]["security_groups"].append({
            "id": sg["GroupId"], "name": sg["GroupName"], "region": region, "tags": _tags(sg.get("Tags")),
            "arn": f"arn:aws:ec2:{region}:{account_id}:security-group/{sg['GroupId']}", "ingress": ingress})
    enabled = _guard(inv, f"ec2:ebs-default:{region}",
                     lambda: ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"])
    if enabled is not None:
        inv["ec2"]["ebs_default_encryption"][region] = enabled
    rds = session.client("rds", region_name=region, config=_CFG)
    for db in _guard(inv, f"rds:{region}", lambda: rds.describe_db_instances()["DBInstances"], []):
        inv["rds"]["instances"].append({
            "id": db["DBInstanceIdentifier"], "arn": db["DBInstanceArn"], "region": region,
            "tags": _tags(db.get("TagList")), "publicly_accessible": db.get("PubliclyAccessible", False),
            "storage_encrypted": db.get("StorageEncrypted", False)})
    ct = session.client("cloudtrail", region_name=region, config=_CFG)
    for t in _guard(inv, f"cloudtrail:{region}", lambda: ct.describe_trails()["trailList"], []):
        if t.get("HomeRegion", region) != region:
            continue
        logging_on = _guard(inv, f"cloudtrail:status:{t['Name']}", lambda: ct.get_trail_status(Name=t["TrailARN"])["IsLogging"], False)
        inv["cloudtrail"]["trails"].append({
            "name": t["Name"], "arn": t["TrailARN"], "region": region, "multi_region": t.get("IsMultiRegionTrail", False),
            "log_validation": t.get("LogFileValidationEnabled", False), "is_logging": logging_on})
    kms = session.client("kms", region_name=region, config=_CFG)
    for k in _guard(inv, f"kms:{region}", lambda: kms.list_keys()["Keys"], []):
        meta = _guard(inv, f"kms:describe:{k['KeyId']}", lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"], None)
        if not meta or meta["KeyManager"] != "CUSTOMER" or meta["KeyState"] != "Enabled":
            continue
        rot = _guard(inv, f"kms:rotation:{k['KeyId']}", lambda: kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"], False)
        inv["kms"]["keys"].append({"id": k["KeyId"], "arn": meta["Arn"], "region": region,
                                   "tags": _tags(_guard(inv, f"kms:tags:{k['KeyId']}",
                                                        lambda: [{"Key": t["TagKey"], "Value": t["TagValue"]} for t in kms.list_resource_tags(KeyId=k["KeyId"])["Tags"]], [])),
                                   "rotation_enabled": rot})


def collect(session: Optional[boto3.Session] = None, regions: Optional[list[str]] = None) -> dict[str, Any]:
    session = session or boto3.Session()
    inv: dict[str, Any] = {
        "account_id": "", "collected_at": datetime.now(timezone.utc).isoformat(), "regions": [],
        "iam": {}, "s3": {}, "ec2": {"security_groups": [], "ebs_default_encryption": {}},
        "rds": {"instances": []}, "cloudtrail": {"trails": []}, "kms": {"keys": []}, "errors": [],
    }
    ident = _guard(inv, "sts:get-caller-identity", lambda: session.client("sts", config=_CFG).get_caller_identity(), {})
    inv["account_id"] = ident.get("Account", "")
    if not regions:
        regions = _guard(inv, "ec2:describe-regions",
                         lambda: [r["RegionName"] for r in session.client("ec2", region_name=session.region_name or "us-east-1", config=_CFG).describe_regions()["Regions"]],
                         [session.region_name or "us-east-1"])
    inv["regions"] = regions
    collect_iam(session, inv)
    collect_s3(session, inv)
    for region in regions:
        collect_region(session, region, inv["account_id"], inv)
    return inv
