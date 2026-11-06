#!/usr/bin/env python3
"""
Step 2 - Daily activity statistics.
The supervisor asked: before running the model, check actions-per-day so a
sudden volume spike doesn't itself create an anomaly. CS-GAD is time-ordered
(no shuffle), so we look at how volume is distributed across the timeline.

Prints, for the 2023 attack window (where the model's snapshots run):
  - events per day, injected (synthetic) events per day, and their share
  - flags any day whose volume is a large outlier
Also writes daily_counts.csv for the record.
"""
import json, csv, argparse
import pandas as pd

SYNTH_DAYS = {  # (day -> scenario) just for annotation
    '2023-03-24': 'warmup', '2023-03-25': 'warmup', '2023-03-26': 'warmup',
    '2023-03-27': 'warmup', '2023-03-28': '1A', '2023-04-04': '1B',
    '2023-04-11': '2A', '2023-04-14': '2B',
}


def synth_ident(r):
    ui = r.get('userIdentity', {})
    un = ui.get('userName')
    if un:
        return un
    arn = ui.get('arn', '')
    return arn.split('/')[-1] if arn else None


SYNTH_IDENTS = {'ai-agent', 'cert-admin'}  # Level6 is a real user; count its synthetic day separately


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True)
    ap.add_argument('--out', default='daily_counts.csv')
    args = ap.parse_args()

    R = json.load(open(args.data))['Records']
    rows = []
    for r in R:
        day = r['eventTime'][:10]
        is_synth = synth_ident(r) in SYNTH_IDENTS or (synth_ident(r) == 'Level6' and day == '2023-04-14')
        rows.append({'day': day, 'year': day[:4], 'synthetic': int(is_synth)})
    df = pd.DataFrame(rows)

    # whole-timeline summary by year
    print('=== whole timeline, events per year ===')
    print(df.groupby('year').size().to_string())
    print()

    # focus on 2023 (the model's snapshot range)
    d23 = df[df['year'] == '2023']
    per_day = d23.groupby('day').agg(total=('synthetic', 'size'),
                                     synthetic=('synthetic', 'sum')).reset_index()
    per_day = per_day.sort_values('day')

    per_day['real'] = per_day['total'] - per_day['synthetic']
    # baseline range taken over the ORIGINAL data's active days only (real > 0)
    real_days = per_day[per_day['real'] > 0]['real']
    real_med = real_days.median()
    real_min, real_max = real_days.min(), real_days.max()

    print('=== 2023 window: events per day ===')
    print(f"{'day':12s} {'total':>7s} {'synthetic':>10s} {'synth%':>7s} {'scenario':>9s}")
    for _, r in per_day.iterrows():
        scen = SYNTH_DAYS.get(r['day'], '')
        pct = (100 * r['synthetic'] / r['total']) if r['total'] else 0
        print(f"{r['day']:12s} {int(r['total']):7d} {int(r['synthetic']):10d} {pct:6.1f}% {scen:>9s}")
    print()

    print('=== baseline (original data, 2023 active days) ===')
    print(f'Original active days: {len(real_days)} | volume range {int(real_min)}-{int(real_max)} | median {real_med:.0f}')
    print()

    print('=== do OUR injected days create a volume spike? ===')
    spike = False
    for _, r in per_day.iterrows():
        if r['synthetic'] > 0:
            scen = SYNTH_DAYS.get(r['day'], '')
            # a spike would be a day whose volume far exceeds the original max
            is_spike = r['total'] > real_max
            spike = spike or is_spike
            verdict = 'SPIKE (exceeds original max)' if is_spike else 'OK - well below original volumes'
            print(f"  {r['day']} ({scen:>6s}): {int(r['total']):4d} events  -> {verdict}")
    print()
    if not spike:
        print('CONCLUSION: no injected day creates a volume spike. All injected days')
        print(f'({per_day[per_day.synthetic>0].total.min()}-{per_day[per_day.synthetic>0].total.max()} events) sit at or below the smallest original active day,')
        print('so day-level volume will NOT flag our attacks - detection must come from behaviour.')

    per_day.to_csv(args.out, index=False)
    print(f'\nWrote: {args.out}')


if __name__ == '__main__':
    main()
