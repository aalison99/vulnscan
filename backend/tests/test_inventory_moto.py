"""Exercise the real boto3 collector against moto (no AWS needed)."""

import boto3
import pytest
from moto import mock_aws

from awsscan import scan_inventory
from awsscan.inventory import collect


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_collects_and_flags_seeded_misconfigurations():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="open-prod")
    s3.put_bucket_tagging(Bucket="open-prod", Tagging={"TagSet": [{"Key": "Environment", "Value": "prod"}]})
    s3.put_bucket_acl(Bucket="open-prod", ACL="public-read")
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="web", Description="d")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    iam = boto3.client("iam")
    iam.create_user(UserName="dave")
    iam.create_login_profile(UserName="dave", Password="Passw0rd!Passw0rd!")
    key = iam.create_access_key(UserName="dave")["AccessKey"]

    inv = collect(boto3.Session(region_name="us-east-1"), regions=["us-east-1"])
    res = scan_inventory(inv)
    found = {(f["rule_id"]) for f in res["findings"]}
    assert {"s3-public-access", "net-sg-open-admin", "iam-user-no-mfa"} <= found
    s3f = next(f for f in res["findings"] if f["rule_id"] == "s3-public-access")
    assert s3f["environment"] == "prod"
    assert key["AccessKeyId"]  # keys exist but must never appear in output
    assert key["SecretAccessKey"] not in str(res)


@mock_aws
def test_access_denied_is_reported_not_passed(monkeypatch):
    from botocore.exceptions import ClientError

    from awsscan import inventory

    def boom(*a, **k):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListBuckets")

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="short-name-bucket")
    session = boto3.Session(region_name="us-east-1")
    real = session.client

    def patched(name, **kw):
        c = real(name, **kw)
        if name == "s3":
            c.list_buckets = boom
        return c

    monkeypatch.setattr(session, "client", patched)
    inv = inventory.collect(session, regions=["us-east-1"])
    assert any(e["service"] == "s3:list-buckets" and "AccessDenied" in e["message"] for e in inv["errors"])
