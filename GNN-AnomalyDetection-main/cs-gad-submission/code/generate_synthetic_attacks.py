#!/usr/bin/env python3
"""
generate_synthetic_attacks.py
=============================================================================
Generates four synthetic attack scenarios and injects them into the CS-GAD
CloudTrail dataset, per the approved design document.

Attacks (2 types x visible/stealthy = 4 scenarios):
  1A  Agentic AI prompt injection  - visible  - 2023-03-28 - AssumedRole ai-agent
  1B  Agentic AI prompt injection  - stealthy - 2023-04-04 - AssumedRole ai-agent
  2A  MITM via rogue certificate   - visible  - 2023-04-11 - IAMUser cert-admin (new)
  2B  MITM via rogue certificate   - stealthy - 2023-04-14 - IAMUser Level6 (insider)

The agent (1A/1B) gets a benign InvokeModel warm-up history on 2023-03-24..27 so
it has an established baseline to deviate from (Bedrock never appears in the real
log, so without this it would be trivially "new").

Output:
  attack_expanded.json   real records + injected records (same schema)
  synthetic_labels.csv   ground-truth labels, per (identity, day, scenario)
  synthetic_only.json    just the injected records (for inspection)

Reproducible: fixed SEED. Running twice yields byte-identical output.
=============================================================================
"""

import json, csv, uuid, random, argparse, os
from datetime import datetime, timedelta

SEED = 20230328
ACCOUNT = "123456789"
REGION = "us-east-1"

# ---- source-of-truth call sequences, straight from the design-doc tables ----
# Each tuple: (eventName, eventSource_short, count, readOnly)
SCEN = {
    "1A": {
        "attack": "prompt_injection", "variant": "visible",
        "identity": {"type": "AssumedRole", "name": "ai-agent"},
        "day": "2023-03-28", "start": "14:00:02", "span_min": 4,
        "ip": "198.51.100.73",                    # TEST-NET-2, new external IP
        "ua": "Boto3/1.26.90 Python/3.10.6 Linux/5.15.0 Botocore/1.29.90",
        "errors": 4,                              # extra AccessDenied probes
        "calls": [
            ("InvokeModel", "bedrock", 2, False),
            ("ListBuckets", "s3", 1, True),
            ("ListSecrets", "secretsmanager", 1, True),
            ("DescribeInstances", "ec2", 3, True),
            ("ListUsers", "iam", 1, True),
            ("ListRoles", "iam", 1, True),
            ("GetSecretValue", "secretsmanager", 18, True),
            ("GetParameter", "ssm", 10, True),
            ("DescribeInstances", "ec2", 2, True),
            ("ListSecrets", "secretsmanager", 2, True),
            ("CreateAccessKey", "iam", 1, False),
            ("AttachUserPolicy", "iam", 1, False),
        ],
    },
    "1B": {
        "attack": "prompt_injection", "variant": "stealthy",
        "identity": {"type": "AssumedRole", "name": "ai-agent"},
        "day": "2023-04-04", "start": "09:05:00", "span_min": 480,  # spread 09:00-17:00
        "ip": "203.0.113.45",                     # the agent's normal warm-up IP
        "ua": "Boto3/1.26.90 Python/3.10.6 Linux/5.15.0 Botocore/1.29.90",
        "errors": 0,
        "calls": [
            ("InvokeModel", "bedrock", 6, False),
            ("DescribeSecret", "secretsmanager", 2, True),
            ("GetSecretValue", "secretsmanager", 4, True),
            ("GetParameter", "ssm", 2, True),
        ],
    },
    "2A": {
        "attack": "mitm", "variant": "visible",
        "identity": {"type": "IAMUser", "name": "cert-admin"},
        "day": "2023-04-11", "start": "16:30:05", "span_min": 6,
        "ip": "198.51.100.212",                   # new external IP
        "ua": "aws-cli/2.11.6 Python/3.11.2 Linux/5.15.0 exec-env/CloudShell",
        "errors": 2,
        "calls": [
            ("ImportCertificate", "acm", 1, False),
            ("ListCertificates", "acm", 1, True),
            ("DescribeLoadBalancers", "elasticloadbalancing", 4, True),
            ("DescribeListeners", "elasticloadbalancing", 4, True),
            ("DescribeTargetGroups", "elasticloadbalancing", 2, True),
            ("ModifyListener", "elasticloadbalancing", 2, False),
            ("ListHostedZones", "route53", 1, True),
            ("ChangeResourceRecordSets", "route53", 3, False),
        ],
    },
    "2B": {
        "attack": "mitm", "variant": "stealthy",
        "identity": {"type": "IAMUser", "name": "Level6"},   # trusted insider
        "day": "2023-04-14", "start": "11:00:00", "span_min": 15,
        "ip": "252.123.210.192",                  # Level6's historical IP
        "ua": "Boto3/1.4.4 Python/2.7.6 Linux/3.19.0-32-generic Botocore/1.5.7",
        "errors": 0,
        "calls": [
            ("DescribeLoadBalancers", "elasticloadbalancing", 1, True),
            ("ImportCertificate", "acm", 1, False),
            ("ModifyListener", "elasticloadbalancing", 1, False),
        ],
    },
}

# Benign warm-up for the agent: a normal baseline of model inference before 1A/1B.
WARMUP = {
    "identity": {"type": "AssumedRole", "name": "ai-agent"},
    "ip": "203.0.113.45",
    "ua": "Boto3/1.26.90 Python/3.10.6 Linux/5.15.0 Botocore/1.29.90",
    "days": ["2023-03-24", "2023-03-25", "2023-03-26", "2023-03-27"],
    # The agent legitimately reads config/secrets as part of its normal job, every
    # day, from its normal IP. This establishes Secrets Manager + SSM as routine for
    # it, so the 1B stealthy attack is a behavioural shift (more reads), not a brand-
    # new service. Without this, a naive "new service" rule would flag 1B for free.
    "per_day": [("InvokeModel", "bedrock", 4, False),
                ("GetSecretValue", "secretsmanager", 1, True),
                ("GetParameter", "ssm", 1, True)],
    "extra": [("DescribeSecret", "secretsmanager", 1, True)],  # once, on last warm-up day
}

TLS = {"tlsVersion": "TLSv1.2", "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256"}


def host_header(src):
    return f"{src}.{REGION}.amazonaws.com"


def make_identity(ident):
    """Build a userIdentity block matching the real 2023 schema."""
    name = ident["name"]
    if ident["type"] == "AssumedRole":
        role = f"{name}-role"
        return {
            "type": "AssumedRole",
            "principalId": f"AROASYNTH{name.upper().replace('-','')[:8]:<8}:{name}",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{name}",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIASYNTH" + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(11)),
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role", "principalId": f"AROASYNTH{name.upper().replace('-','')[:8]:<8}",
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}", "accountId": ACCOUNT,
                    "userName": role,
                },
                "webIdFederationData": {},
                "attributes": {"creationDate": "2023-01-01T00:00:00Z", "mfaAuthenticated": "false"},
            },
        }
    else:  # IAMUser
        if name == "Level6":  # reuse the real insider's identifiers
            return {
                "type": "IAMUser", "principalId": "AIDADO2GQD0K8TEF7KW1V",
                "arn": f"arn:aws:iam::{ACCOUNT}:user/Level6", "accountId": ACCOUNT,
                "accessKeyId": "AKIA3Z2XBVUDFQ9TU4MD", "userName": "Level6",
            }
        return {
            "type": "IAMUser",
            "principalId": "AIDASYNTH" + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(11)),
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "accountId": ACCOUNT,
            "accessKeyId": "AKIASYNTH" + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(11)),
            "userName": name,
        }


def make_record(ev_name, src_short, ro, ident_block, ip, ua, ts, error=False):
    """One CloudTrail record in the real 2023 (eventVersion 1.08) schema."""
    src = f"{src_short}.amazonaws.com"
    rec = {
        "eventVersion": "1.08",
        "userIdentity": ident_block,
        "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": src,
        "eventName": ev_name,
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": None,
        "responseElements": None,
        "requestID": str(uuid.UUID(int=random.getrandbits(128))),
        "eventID": str(uuid.UUID(int=random.getrandbits(128))),
        "readOnly": ro,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": ACCOUNT,
        "eventCategory": "Management",
        "tlsDetails": {**TLS, "clientProvidedHostHeader": host_header(src_short)},
    }
    # A couple of distinctive request parameters, so the records aren't all null.
    if ev_name == "CreateRoute" or ev_name == "ChangeResourceRecordSets":
        rec["requestParameters"] = {"hostedZoneId": "Z0SYNTH000EXAMPLE"}
    if ev_name == "ImportCertificate":
        rec["requestParameters"] = {"certificate": "HIDDEN_DUE_TO_SECURITY_REASONS"}
    if ev_name == "ModifyListener":
        rec["requestParameters"] = {"listenerArn": f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:listener/app/synth/abc/def"}
    if error:
        rec["errorCode"] = "AccessDenied"
        rec["errorMessage"] = "User is not authorized to perform this action"
        rec["readOnly"] = False
    return rec


def expand_calls(calls):
    """Flatten [(name,src,count,ro),...] into [(name,src,ro),...] one per event."""
    out = []
    for name, src, cnt, ro in calls:
        out.extend([(name, src, ro)] * cnt)
    return out


def generate():
    random.seed(SEED)
    injected = []
    labels = []

    # ---- benign warm-up for the agent (labelled benign, not attack) ----
    agent_ident = make_identity(WARMUP["identity"])
    for i, day in enumerate(WARMUP["days"]):
        base = datetime.strptime(day + "T10:00:00", "%Y-%m-%dT%H:%M:%S")
        day_calls = list(WARMUP["per_day"])
        if i == len(WARMUP["days"]) - 1:
            day_calls = day_calls + WARMUP["extra"]
        events = expand_calls(day_calls)
        for j, (name, src, ro) in enumerate(events):
            ts = base + timedelta(minutes=37 * j + random.randint(0, 9))
            injected.append(make_record(name, src, ro, agent_ident, WARMUP["ip"], WARMUP["ua"], ts))
        labels.append({"identity": "ai-agent", "day": day, "scenario": "warmup",
                       "attack_family": "benign", "variant": "benign",
                       "n_events": len(events), "label": 0})

    # ---- the four attack scenarios ----
    for sid, s in SCEN.items():
        ident = make_identity(s["identity"])
        start = datetime.strptime(s["day"] + "T" + s["start"], "%Y-%m-%dT%H:%M:%S")
        events = expand_calls(s["calls"])
        n = len(events)
        span = s["span_min"]
        for j, (name, src, ro) in enumerate(events):
            # spread events across the span (burst = tight, stealthy = wide)
            frac = j / max(n - 1, 1)
            ts = start + timedelta(seconds=int(frac * span * 60) + random.randint(0, 3))
            injected.append(make_record(name, src, ro, ident, s["ip"], s["ua"], ts))
        # add the extra AccessDenied probe events (visible variants)
        for k in range(s["errors"]):
            name, src, ro = random.choice([(c[0], c[1], c[3]) for c in s["calls"]])
            ts = start + timedelta(seconds=random.randint(0, span * 60))
            injected.append(make_record(name, src, ro, ident, s["ip"], s["ua"], ts, error=True))
        total = n + s["errors"]
        labels.append({"identity": s["identity"]["name"], "day": s["day"], "scenario": sid,
                       "attack_family": s["attack"], "variant": s["variant"],
                       "n_events": total, "label": 1})

    return injected, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="attack.json", help="path to the real dataset")
    ap.add_argument("--outdir", default=".", help="output directory")
    args = ap.parse_args()

    injected, labels = generate()

    # write synthetic-only (for inspection)
    with open(os.path.join(args.outdir, "synthetic_only.json"), "w") as f:
        json.dump({"Records": injected}, f, indent=1)

    # write labels csv
    with open(os.path.join(args.outdir, "synthetic_labels.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["identity", "day", "scenario", "attack_family",
                                          "variant", "n_events", "label"])
        w.writeheader()
        w.writerows(labels)

    # merge into the real dataset and write expanded
    if os.path.exists(args.input):
        real = json.load(open(args.input))["Records"]
        merged = real + injected
        merged.sort(key=lambda r: r["eventTime"])
        with open(os.path.join(args.outdir, "attack_expanded.json"), "w") as f:
            json.dump({"Records": merged}, f)
        print(f"Merged: {len(real)} real + {len(injected)} injected = {len(merged)} total")
    else:
        print(f"(input {args.input} not found - wrote synthetic_only + labels only)")

    print(f"Injected {len(injected)} synthetic records across {len(labels)} (identity,day) groups.")
    for L in labels:
        print(f"  {L['scenario']:7s} {L['day']}  {L['identity']:10s} "
              f"{L['attack_family']:16s} {L['variant']:8s} n={L['n_events']:3d} label={L['label']}")


if __name__ == "__main__":
    main()
