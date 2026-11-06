#!/usr/bin/env python3
"""
Full analysis of CS-GAD results on the expanded dataset.
Produces a documentation-ready report:
  A. Per-scenario detection for the 4 synthetic attacks
  B. Visible-vs-stealthy summary
  C. Original attacks detection at their snapshots
  D. Overall ROC-AUC (synthetic + original), via the model's own labels
"""
import argparse
import numpy as np
import pandas as pd

AI_AGENT = 'arn:aws:sts::123456789:assumed-role/ai-agent-role/ai-agent'

# (label, user, detection_cutoff_day, kind)
SYNTH = [
    ('1A prompt_injection visible',  AI_AGENT,     '2023-03-29', 'visible'),
    ('1B prompt_injection stealthy', AI_AGENT,     '2023-04-05', 'stealthy'),
    ('2A mitm visible',              'cert-admin', '2023-04-12', 'visible'),
    ('2B mitm stealthy',            'Level6',      '2023-04-15', 'stealthy'),
]

# original attacks: (name, user, a representative detection cutoff day)
ORIG = [
    ('cryptojacking (cloud_user)',      'cloud_user', '2023-03-22'),
    ('lateral_movement (cloud_user)',   'cloud_user', '2023-04-21'),
    ('lateral_movement (vpc_peering)',  'vpc_peering', '2023-04-21'),
    ('monitor_exploiting (test)',       'test',       '2023-04-24'),
    ('targeted_services (sec-check)',   'sec-check',  '2023-04-24'),
]


def detection_row(daily, user, cday):
    grp = daily[daily['cutoff_day'] == cday]
    if len(grp) == 0:
        return None
    row = grp[grp['user'] == user]
    if len(row) == 0:
        return ('no-score', None, len(grp), None, None)
    s = float(row['score'].iloc[0])
    scores = grp['score'].values
    rank = int((scores > s).sum()) + 1
    t1 = scores.mean() + scores.std()
    t2 = scores.mean() + 2 * scores.std()
    return (s, rank, len(scores), bool(s > t1), bool(s > t2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', required=True)
    args = ap.parse_args()
    df = pd.read_csv(args.results)
    df['cutoff_day'] = df['cutoff'].astype(str).str[:10]
    daily = df[df['kind'] == 'daily'] if 'kind' in df.columns else df

    print('=' * 74)
    print('A. SYNTHETIC ATTACKS - per-scenario detection')
    print('=' * 74)
    print(f"{'scenario':32s} {'score':>6s} {'rank':>8s} {'>1std':>6s} {'>2std':>6s}")
    res = {}
    for name, user, cday, kind in SYNTH:
        r = detection_row(daily, user, cday)
        if r is None:
            print(f'{name:32s}   (snapshot {cday} not available yet)')
            continue
        s, rank, n, f1, f2 = r
        if s == 'no-score':
            print(f'{name:32s}   attacker not scored at {cday} (n={n})')
            res[name] = (kind, None)
            continue
        print(f'{name:32s} {s:6.3f} {rank:3d}/{n:<4d} {"YES" if f1 else "no":>6s} {"YES" if f2 else "no":>6s}')
        res[name] = (kind, f1)

    print()
    print('=' * 74)
    print('B. VISIBLE vs STEALTHY')
    print('=' * 74)
    for kind in ('visible', 'stealthy'):
        flagged = [n for n, (k, f) in res.items() if k == kind and f is True]
        total = [n for n, (k, f) in res.items() if k == kind and f is not None]
        if total:
            print(f'  {kind:9s}: {len(flagged)}/{len(total)} flagged at mean+1std  '
                  f'({", ".join(n.split()[0] for n in flagged) if flagged else "none"})')

    print()
    print('=' * 74)
    print('C. ORIGINAL ATTACKS - detection at their snapshots')
    print('=' * 74)
    print(f"{'attack':34s} {'score':>6s} {'rank':>8s} {'>1std':>6s} {'>2std':>6s}")
    for name, user, cday in ORIG:
        r = detection_row(daily, user, cday)
        if r is None or r[0] == 'no-score':
            print(f'{name:34s}   (not available / not scored at {cday})')
            continue
        s, rank, n, f1, f2 = r
        print(f'{name:34s} {s:6.3f} {rank:3d}/{n:<4d} {"YES" if f1 else "no":>6s} {"YES" if f2 else "no":>6s}')

    print()
    print('=' * 74)
    print('D. OVERALL ROC-AUC (all snapshots, model labels)')
    print('=' * 74)
    print('  (computed by cs_gad.py evaluate_scores at end of full run - see run log)')


if __name__ == '__main__':
    main()
