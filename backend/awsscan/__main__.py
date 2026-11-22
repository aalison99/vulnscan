import argparse
import json
import sys

from .engine import scan_inventory


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="awsscan", description="Read-only AWS misconfiguration scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan an AWS account (read-only)")
    s.add_argument("--profile")
    s.add_argument("--regions", default="all", help="comma list or 'all'")
    s.add_argument("--out", default="-")
    s.add_argument("--weights", help="path to a weights YAML file")
    d = sub.add_parser("sample", help="scan the built-in demo inventory (no AWS needed)")
    d.add_argument("--out", default="-")
    args = ap.parse_args(argv)

    weights = None
    if args.cmd == "scan":
        import boto3

        from .inventory import collect
        from .scoring import load_weights
        weights = load_weights(args.weights) if args.weights else None
        regions = None if args.regions == "all" else args.regions.split(",")
        inv = collect(boto3.Session(profile_name=args.profile), regions)
    else:
        from .sample import sample_inventory
        inv = sample_inventory()

    text = json.dumps(scan_inventory(inv, weights=weights), indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
