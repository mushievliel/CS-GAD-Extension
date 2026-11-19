#!/usr/bin/env python3
"""
Baseline (Modell et al. 2021) on the expanded dataset  -  SELF-CONTAINED.

Ported from the authors' Microsoft.ipynb baseline: a bipartite user-service
graph (binary edges), a SpectralEmbedding, and the scoring rule that gives a
user a score of 0 for any service it accessed before, otherwise the euclidean
nearest-neighbour distance to the closest peer that used that service in the
current time frame; a user's score is the maximum over services. Threshold is
mean + n*std over the per-user scores.

This file is self-contained: it inlines the faithful preprocessing (identity
resolution + 14-category mapping via event_category.json, then rules) so it has
no dependency on the CS-GAD script. It reproduces Table 6.6 of the report.

Scope: this reproduces the BASELINE RESULTS REPORTED IN THIS PROJECT on this
dataset. It is not a reproduction of the original published CS-GAD system.

Inputs (defaults assume the command is run from the GNN-AnomalyDetection-main/
repo root; override with --ec / --data):
  Utils/event_category.json                       (authors' category map; Git-LFS object)
  cs-gad-submission/data/attack_expanded_labeled.json
      (consolidated labelled dataset; regenerate with generate_synthetic_attacks.py
       + make_labeled.py - see REPRODUCE_STAGE2.md)

Run:  python3 cs-gad-submission/code/baseline_modell.py
Deps: numpy, pandas, networkx, scikit-learn   (no gensim / node2vec needed)
"""
import argparse, json, numpy as np, pandas as pd
from sklearn.manifold import SpectralEmbedding
from sklearn.neighbors import NearestNeighbors

# ---- categorization rules (authors' Node2Vec.ipynb cell 3) ----
STARTS_WITH = {
 'CreateObject': ['accept','request','create','copy','run','purchase','allocate','import','startinstances'],
 'ModifyExistingResource': ['modify','update','set','tag','deregister','deprecate','un','reject','register'],
 'ListResources':['list'], 'Download/UploadObjects':['enc','getobjects','upload'],
 'GetInfo':['describe','get','search'], 'AssociateResources':['associate','put'],
 'Login':['assume','login','switch','renewrole','renewdelegate','checkmfa'],
 'RemovePermissions':['remove'], 'GrantPermissions':['add','authorize']}
CONTAINS = {
 'Delete':['delet','terminate','revoke','drop','releaseaddress'],
 'DisableObjects':['disabl','stop','cancel','unlink','suspend'],
 'EnableObjects':['enabl','start','invoke','subscribe','test','complete'],
 'SensitiveInfo':['send','accesskey','secretkey','token','invite','exportapi','decode'],
 'Logout':['exit'], 'CreateObject':['create','copy'],
 'ModifyExistingResource':['failover','change','confirm','promote','reboot','rotate','replace','retire','detach','modify','update','set','tag','deregister','Deprecate','attach','upgrade','wipe','transfer','validate','publish'],
 'ListResources':['list'], 'Download/UploadObjects':['getobjects','upload'],
 'GetInfo':['describe','get','view','decrypt','generate','lookup','scan','simulate'],
 'AssociateResources':['associate','put'], 'Login':['assume','login','renewrole','sign','forgot'],
 'Logout':['logout']}

def make_change_name(ec):
    def cn(name):
        if name in ec: return ec[name]
        low = str(name).lower()
        for k, v in STARTS_WITH.items():
            for e in v:
                if low.startswith(e): return k
        for k, v in CONTAINS.items():
            for e in v:
                if e in low: return k
        return None
    return cn

def load_users(path, ec):
    """Faithful preprocessing: identity resolution + categorization + source-/target- prefixes."""
    data = json.load(open(path))['Records']
    awsc = pd.DataFrame.from_records(data)
    ui = pd.json_normalize(awsc['userIdentity'])
    users = ui.merge(awsc[['eventTime','eventName','eventSource','awsRegion','errorCode']],
                     left_index=True, right_index=True)
    for c in ['userName','arn','invokedBy','principalId']:
        if c not in users.columns: users[c] = np.nan
    users['userName'] = users['userName'].fillna(users['arn']).fillna(users['invokedBy'])\
        .fillna(users['invokedBy']).fillna(users['principalId']).fillna('accountId')
    users = users[['eventTime','type','userName','eventName','eventSource','awsRegion','errorCode']]
    users = users.rename(columns={'eventTime':'timestamp','userName':'Identifier',
                                  'eventSource':'TargetService','errorCode':'Error'})
    users['eventName'] = users['eventName'].apply(make_change_name(ec))
    users['timestamp'] = pd.to_datetime(users['timestamp']).map(pd.Timestamp.timestamp).map(int)
    users = users.sort_values('timestamp', ascending=True, ignore_index=True)
    users['Identifier'] = users['Identifier'].apply(lambda x: x if (len(str(x).split(":")) != 2) else str(x).split(":")[1])
    users = users[users['eventName'].notna()]
    users['Identifier'] = "source-" + users['Identifier'].astype(str)
    users['TargetService'] = "target-" + users['TargetService'].astype(str)
    return users

def ts(d): return int(pd.Timestamp(d, tz='UTC').timestamp())

def main():
    ap = argparse.ArgumentParser(description="Modell baseline on the expanded dataset (reproduces Table 6.6).")
    ap.add_argument("--ec", default="Utils/event_category.json",
                    help="path to event_category.json (default assumes repo root)")
    ap.add_argument("--data", default="cs-gad-submission/data/attack_expanded_labeled.json",
                    help="path to attack_expanded_labeled.json (default assumes repo root)")
    args = ap.parse_args()

    ec = json.load(open(args.ec))
    df = load_users(args.data, ec)

    users_all = sorted(df['Identifier'].unique())
    svcs_all = sorted(df['TargetService'].unique())
    nodes = users_all + svcs_all
    idx = {n: i for i, n in enumerate(nodes)}
    A = np.zeros((len(nodes), len(nodes)))
    for u, s in set(zip(df['Identifier'], df['TargetService'])):
        A[idx[u], idx[s]] = 1; A[idx[s], idx[u]] = 1
    nc = min(74, len(nodes) - 2)                       # authors used 74; cap for small graphs
    X = SpectralEmbedding(n_components=nc, affinity='precomputed').fit_transform(A)
    emb = {n: X[idx[n]] for n in nodes}

    first = df.groupby(['Identifier','TargetService'])['timestamp'].min().to_dict()

    # (name, attacker-substring, window-start day, snapshot day)
    SCEN = [('1A prompt-injection visible','ai-agent','2023-03-28','2023-03-29'),
            ('1B prompt-injection stealthy','ai-agent','2023-04-04','2023-04-05'),
            ('2A mitm visible','cert-admin','2023-04-11','2023-04-12'),
            ('2B mitm stealthy','source-Level6','2023-04-14','2023-04-15')]

    def match(sub):
        return {u for u in users_all if (sub == u) or (sub != 'source-Level6' and sub in u)}

    def score_at(cut_ts, window_start_ts):
        snap = df[df['timestamp'] < cut_ts]
        svc_users = snap.groupby('TargetService')['Identifier'].apply(lambda s: sorted(set(s))).to_dict()
        scores = {}
        for u in set(snap['Identifier']):
            best = 0.0
            for s in set(snap[snap['Identifier'] == u]['TargetService']):
                peers = [p for p in svc_users.get(s, []) if p != u and p in emb]
                if not peers: continue
                if first.get((u, s), 0) < window_start_ts:   # accessed before -> score 0
                    continue
                Xu = emb[u].reshape(1, -1); Xp = np.array([emb[p] for p in peers])
                d, _ = NearestNeighbors(n_neighbors=1).fit(Xp).kneighbors(Xu)  # euclidean
                best = max(best, float(d[0][0]))
            scores[u] = best
        return scores

    print("BASELINE (Modell et al.) on the expanded dataset")
    print(f"bipartite graph: {len(users_all)} users, {len(svcs_all)} services; SpectralEmbedding n_components={nc}\n")
    print("Rank = the attacker's position among all users at its snapshot (1 = most")
    print("anomalous). A score of 0.000 is the baseline's rule for a user that accessed")
    print("every service it used before; such a user is non-anomalous by construction and")
    print("ties with all the other 0-score users, so its rank is not meaningful. These")
    print("cases are shown as 'n/a (tie)' with the number of tied users, and counted as")
    print("'missed'.\n")
    print(f"{'scenario':30s} {'score':>7s} {'rank':>14s} {'>1sd':>5s} {'>2sd':>5s}  verdict")
    for name, sub, day0, day1 in SCEN:
        sc = score_at(ts(day1), ts(day0))
        vals = np.array(list(sc.values())); mu, sd = vals.mean(), vals.std()
        a = [sc[u] for u in match(sub) if u in sc]
        if not a:
            print(f"{name:30s}  (attacker not scored)"); continue
        amax = max(a)
        if amax <= 0.0:                                   # 0-score: rank is a meaningless tie
            n_tie = sum(1 for v in sc.values() if v <= 0.0)
            rank_str = f"n/a ({n_tie} tie)"
        else:
            rank = int(sum(1 for v in sc.values() if v > amax)) + 1
            rank_str = f"{rank}/{len(sc)}"
        f1, f2 = amax > mu + sd, amax > mu + 2 * sd
        verdict = "DETECTED" if f1 else "missed"
        print(f"{name:30s} {amax:7.3f} {rank_str:>14s} {str(f1):>5s} {str(f2):>5s}  {verdict}")

if __name__ == "__main__":
    main()
