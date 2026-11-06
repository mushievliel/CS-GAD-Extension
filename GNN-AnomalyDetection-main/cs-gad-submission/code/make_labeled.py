#!/usr/bin/env python3
"""
Step 1 - Consolidate into ONE labeled file.
Keeps the original (reverse-engineered) attack labels AND adds the new
synthetic labels on top. Every record gets label = 1 (attack) or 0 (benign).

Label sources:
  - Original attacks: ATTACK_WINDOWS from cs_gad.py (user + date range)
  - Synthetic attacks: fixed (identity, day) rules below
Output:
  attack_expanded_labeled.json   same records + "label" field per record
  record_labels.csv              eventID, user, day, label, source (compact)
"""
import json, csv, argparse
import pandas as pd

# ---- original attack windows (copied from cs_gad.py, the reverse-engineered labels) ----
ORIGINAL_WINDOWS = [
    ('cloud_user', 'cryptojacking', '2023-03-14', '2023-03-22'),
    ('cloud_user', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('arn:aws:sts::123456789:assumed-role/flask-server/i-0d6d1080e1184b9b4', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('arn:aws:sts::123456789:assumed-role/backend_server/i-0e113c6c02d37490f', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('arn:aws:sts::123456789:assumed-role/final_instance/i-0a427bfae3dae42ae', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('vpc_peering', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('test', 'monitor_exploiting', '2023-04-23', '2023-04-24'),
    ('sec-check', 'targeted_services', '2023-04-23', '2023-04-24'),
]

# ---- synthetic attacks: (identity, scenario, attack_type, day) ----
SYNTHETIC_ATTACKS = [
    ('ai-agent',   '1A', 'prompt_injection_visible',  '2023-03-28'),
    ('ai-agent',   '1B', 'prompt_injection_stealthy', '2023-04-04'),
    ('cert-admin', '2A', 'mitm_visible',              '2023-04-11'),
    ('Level6',     '2B', 'mitm_stealthy',             '2023-04-14'),
]
# ai-agent warm-up days (benign, label 0) - listed only for clarity
WARMUP_DAYS = {'2023-03-24', '2023-03-25', '2023-03-26', '2023-03-27'}


def user_id(r):
    ui = r.get('userIdentity', {})
    return ui.get('userName') or ui.get('arn') or ui.get('type') or 'UNKNOWN'


def synth_ident(r):
    """Identity for synthetic matching: userName, else last arn segment
    (the assumed-role session name, e.g. 'ai-agent')."""
    ui = r.get('userIdentity', {})
    un = ui.get('userName')
    if un:
        return un
    arn = ui.get('arn', '')
    return arn.split('/')[-1] if arn else None


def label_record(r):
    """Return (label, source_tag). label 1=attack, 0=benign."""
    day = r['eventTime'][:10]
    uname = r.get('userIdentity', {}).get('userName')
    arn = r.get('userIdentity', {}).get('arn', '')
    # original attacks: match on exact user (userName or full arn) + date in window
    for win_user, atype, start, end in ORIGINAL_WINDOWS:
        if (win_user == uname) or (win_user == arn):
            if start <= day <= end:
                return 1, f'original:{atype}'
    # synthetic attacks: identity (userName OR assumed-role session name) + exact day
    sid = synth_ident(r)
    for ident, scen, atype, aday in SYNTHETIC_ATTACKS:
        if sid == ident and day == aday:
            return 1, f'synthetic:{scen}:{atype}'
    return 0, 'benign'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True)
    ap.add_argument('--out_json', default='attack_expanded_labeled.json')
    ap.add_argument('--out_csv', default='record_labels.csv')
    args = ap.parse_args()

    R = json.load(open(args.data))['Records']
    n_attack = 0
    src_counts = {}
    csv_rows = []
    for r in R:
        lab, src = label_record(r)
        r['label'] = lab
        n_attack += lab
        src_counts[src] = src_counts.get(src, 0) + 1
        csv_rows.append({
            'eventID': r.get('eventID', ''),
            'user': user_id(r),
            'day': r['eventTime'][:10],
            'label': lab,
            'source': src,
        })

    json.dump({'Records': R}, open(args.out_json, 'w'))
    with open(args.out_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['eventID', 'user', 'day', 'label', 'source'])
        w.writeheader()
        w.writerows(csv_rows)

    print(f'Total records:   {len(R)}')
    print(f'Attack (1):      {n_attack}')
    print(f'Benign (0):      {len(R) - n_attack}')
    print()
    print('Breakdown by source:')
    for src in sorted(src_counts, key=lambda s: (-src_counts[s], s)):
        if src == 'benign':
            continue
        print(f'  {src:40s} {src_counts[src]}')
    print(f'  {"benign":40s} {src_counts.get("benign",0)}')
    print()
    print(f'Wrote: {args.out_json}')
    print(f'Wrote: {args.out_csv}')


if __name__ == '__main__':
    main()
