from . import rule


def _buckets(inv):
    return inv["s3"].get("buckets", [])


@rule(id="s3-public-access", title="S3 bucket is publicly accessible", cis_id="2.1.4", category="s3",
      base_severity=9, exploitability=1.0,
      remediation="aws s3api put-public-access-block --bucket <name> --public-access-block-configuration "
                  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
def public_access(inv, r):
    out = []
    for b in _buckets(inv):
        if b.get("acl_public") or b.get("policy_public"):
            out.append(r.finding(
                arn=b["arn"], rtype="s3-bucket", region=b.get("region", "global"),
                description=f"Bucket {b['name']} grants public access via "
                            f"{'ACL' if b.get('acl_public') else 'policy'}.",
                evidence={"acl_public": b.get("acl_public", False),
                          "policy_public": b.get("policy_public", False)},
                tags=b.get("tags", {}), exposure="internet"))
    return out


@rule(id="s3-no-block-public-access", title="S3 Block Public Access not fully enabled", cis_id="2.1.4",
      category="s3", base_severity=6, exploitability=0.7,
      remediation="Enable all four Block Public Access settings on the bucket.")
def no_bpa(inv, r):
    out = []
    for b in _buckets(inv):
        bpa = b.get("public_access_block")
        if not bpa or not all(bpa.values()):
            out.append(r.finding(arn=b["arn"], rtype="s3-bucket", region=b.get("region", "global"),
                                 description=f"Bucket {b['name']} does not block all public access.",
                                 evidence={"public_access_block": bpa}, tags=b.get("tags", {}),
                                 exposure="internal"))
    return out


@rule(id="s3-no-encryption", title="S3 bucket has no default encryption", cis_id="2.1.1", category="s3",
      base_severity=6, exploitability=0.5,
      remediation="aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration ...")
def no_encryption(inv, r):
    return [
        r.finding(arn=b["arn"], rtype="s3-bucket", region=b.get("region", "global"),
                  description=f"Bucket {b['name']} has no default encryption.",
                  evidence={"encryption": False}, tags=b.get("tags", {}), exposure="internal")
        for b in _buckets(inv) if not b.get("encryption")
    ]


@rule(id="s3-no-tls-enforced", title="S3 bucket policy does not deny non-TLS requests", cis_id="2.1.2",
      category="s3", base_severity=4, exploitability=0.5,
      remediation="Add a bucket policy statement denying requests where aws:SecureTransport is false.")
def no_tls(inv, r):
    return [
        r.finding(arn=b["arn"], rtype="s3-bucket", region=b.get("region", "global"),
                  description=f"Bucket {b['name']} allows plain-HTTP requests.",
                  evidence={"tls_enforced": False}, tags=b.get("tags", {}), exposure="internet")
        for b in _buckets(inv) if not b.get("tls_enforced")
    ]
