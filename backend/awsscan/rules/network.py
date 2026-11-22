from . import rule

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB", 6379: "Redis"}


def _open_ports(sg, ports):
    hits = []
    for rule_ in sg.get("ingress", []):
        if not any(c in ("0.0.0.0/0", "::/0") for c in rule_.get("cidrs", [])):
            continue
        lo, hi = rule_.get("from", 0), rule_.get("to", 65535)
        if rule_.get("proto") in ("-1", "all"):
            lo, hi = 0, 65535
        hits += [p for p in ports if lo <= p <= hi]
    return sorted(set(hits))


@rule(id="net-sg-open-admin", title="Security group exposes SSH/RDP to the internet", cis_id="5.2",
      category="network", base_severity=9, exploitability=0.9,
      remediation="Restrict the ingress rule to a trusted CIDR or use SSM Session Manager.")
def open_admin(inv, r):
    out = []
    for sg in inv["ec2"].get("security_groups", []):
        ports = _open_ports(sg, ADMIN_PORTS)
        if ports:
            out.append(r.finding(arn=sg["arn"], rtype="security-group", region=sg["region"],
                                 description=f"{sg['id']} allows 0.0.0.0/0 on {', '.join(ADMIN_PORTS[p] for p in ports)}.",
                                 evidence={"ports": ports, "attached": sg.get("attached", True)},
                                 tags=sg.get("tags", {}), exposure="internet"))
    return out


@rule(id="net-sg-open-db", title="Security group exposes a database port to the internet", cis_id="5.2",
      category="network", base_severity=9, exploitability=0.8,
      remediation="Restrict database ingress to application security groups or private CIDRs.")
def open_db(inv, r):
    out = []
    for sg in inv["ec2"].get("security_groups", []):
        ports = _open_ports(sg, DB_PORTS)
        if ports:
            out.append(r.finding(arn=sg["arn"], rtype="security-group", region=sg["region"],
                                 description=f"{sg['id']} allows 0.0.0.0/0 on {', '.join(DB_PORTS[p] for p in ports)}.",
                                 evidence={"ports": ports}, tags=sg.get("tags", {}), exposure="internet"))
    return out


@rule(id="net-default-sg-open", title="Default security group allows traffic", cis_id="5.4",
      category="network", base_severity=4, exploitability=0.5,
      remediation="Remove all inbound and outbound rules from the default security group.")
def default_sg(inv, r):
    return [
        r.finding(arn=sg["arn"], rtype="security-group", region=sg["region"],
                  description=f"Default SG {sg['id']} has ingress rules.",
                  evidence={"rules": len(sg["ingress"])}, tags=sg.get("tags", {}), exposure="internal")
        for sg in inv["ec2"].get("security_groups", [])
        if sg.get("name") == "default" and sg.get("ingress")
    ]


@rule(id="net-rds-public", title="RDS instance is publicly accessible", cis_id="2.3.3",
      category="network", base_severity=9, exploitability=0.8,
      remediation="aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible")
def rds_public(inv, r):
    return [
        r.finding(arn=db["arn"], rtype="rds-instance", region=db["region"],
                  description=f"RDS instance {db['id']} is publicly accessible.",
                  evidence={"publicly_accessible": True}, tags=db.get("tags", {}), exposure="internet")
        for db in inv.get("rds", {}).get("instances", []) if db.get("publicly_accessible")
    ]
