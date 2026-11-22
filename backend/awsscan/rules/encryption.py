from . import rule


@rule(id="enc-ebs-default-off", title="EBS encryption by default disabled", cis_id="2.2.1",
      category="encryption", base_severity=5, exploitability=0.4,
      remediation="aws ec2 enable-ebs-encryption-by-default --region <region>")
def ebs_default(inv, r):
    return [
        r.finding(arn=f"arn:aws:ec2:{region}:{inv['account_id']}:ebs-default-encryption", rtype="ebs-settings",
                  region=region, description=f"EBS default encryption is off in {region}.",
                  evidence={"enabled": False}, tags={}, exposure="internal")
        for region, on in inv["ec2"].get("ebs_default_encryption", {}).items() if not on
    ]


@rule(id="enc-rds-unencrypted", title="RDS storage not encrypted", cis_id="2.3.1", category="encryption",
      base_severity=6, exploitability=0.4,
      remediation="Snapshot, copy with encryption, and restore (RDS cannot encrypt in place).")
def rds_unencrypted(inv, r):
    return [
        r.finding(arn=db["arn"], rtype="rds-instance", region=db["region"],
                  description=f"RDS instance {db['id']} storage is unencrypted.",
                  evidence={"storage_encrypted": False}, tags=db.get("tags", {}), exposure="internal")
        for db in inv.get("rds", {}).get("instances", []) if not db.get("storage_encrypted")
    ]


@rule(id="enc-kms-no-rotation", title="KMS key rotation disabled", cis_id="3.6", category="encryption",
      base_severity=4, exploitability=0.3,
      remediation="aws kms enable-key-rotation --key-id <id>")
def kms_rotation(inv, r):
    return [
        r.finding(arn=k["arn"], rtype="kms-key", region=k["region"],
                  description=f"Customer-managed KMS key {k['id']} has rotation disabled.",
                  evidence={"rotation_enabled": False}, tags=k.get("tags", {}), exposure="internal")
        for k in inv.get("kms", {}).get("keys", []) if not k.get("rotation_enabled")
    ]
