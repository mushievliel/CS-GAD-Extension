#!/usr/bin/env python3
"""
CS-GAD reconstruction (single file)
===================================
Re-implementation of the CS-GAD pipeline (Marbel et al. 2023) on the CloudTrail
attack log, plus the evaluation used in this project.

Pipeline:
  1. Load CloudTrail JSON ({"Records": [...]}) -> table of (time, user, action, service)
  2. Map ~3000 raw event names to 14 action categories (rule-based)
  3. For each snapshot time, build the cumulative user-action-service graph
  4. Embed it with node2vec (from scratch: biased walks + skip-gram w/ negative sampling)
  5. Anomaly score = 1 - max cosine similarity to peers who used the same last service
  6. Evaluate vs. reverse-engineered attack labels: ROC-AUC, precision, recall, F1, FPR

Usage:
  pip install numpy pandas networkx scikit-learn
  python cs_gad_reconstruction.py --data attack.json                 # full run (~1 hour)
  python cs_gad_reconstruction.py --data attack.json --quick         # 3 snapshots, sanity check
  python cs_gad_reconstruction.py --data attack.json --out my.csv    # resumable: rerun to continue

Progress is saved after every snapshot, so an interrupted run resumes where it stopped.
"""
import argparse
import os
import random
import json

import numpy as np
import pandas as pd
import networkx as nx
from sklearn.metrics import roc_auc_score


# ----------------------------------------------------------------------------
# 1-2. Event categorization (14 categories) - rules recovered from the original notebook
# ----------------------------------------------------------------------------
STARTS_WITH = {
    'CreateObject': ['accept', 'request', 'create', 'copy', 'run', 'purchase', 'allocate', 'import', 'startinstances'],
    'ModifyExistingResource': ['modify', 'update', 'set', 'tag', 'deregister', 'deprecate', 'un', 'reject', 'register'],
    'ListResources': ['list'],
    'Download/UploadObjects': ['enc', 'getobjects', 'upload'],
    'GetInfo': ['describe', 'get', 'search'],
    'AssociateResources': ['associate', 'put'],
    'Login': ['assume', 'login', 'switch', 'renewrole', 'renewdelegate', 'checkmfa'],
    'RemovePermissions': ['remove'],
    'GrantPermissions': ['add', 'authorize'],
}

CONTAINS = {
    'Delete': ['delet', 'terminate', 'revoke', 'drop', 'releaseaddress'],
    'DisableObjects': ['disabl', 'stop', 'cancel', 'unlink', 'suspend'],
    'EnableObjects': ['enabl', 'start', 'invoke', 'subscribe', 'test', 'complete'],
    'SensitiveInfo': ['send', 'accesskey', 'secretkey', 'token', 'invite', 'exportapi', 'decode'],
    'Logout': ['exit'],
    'CreateObject': ['create', 'copy'],
    'ModifyExistingResource': ['failover', 'change', 'confirm', 'promote', 'reboot', 'rotate', 'replace', 'retire',
                               'detach', 'modify', 'update', 'set', 'tag', 'deregister', 'deprecate', 'attach',
                               'upgrade', 'wipe', 'transfer', 'validate', 'publish'],
    'ListResources': ['list'],
    'Download/UploadObjects': ['getobjects', 'upload'],
    'GetInfo': ['describe', 'get', 'view', 'decrypt', 'generate', 'lookup', 'scan', 'simulate'],
    'AssociateResources': ['associate', 'put'],
    'Login': ['assume', 'login', 'renewrole', 'sign', 'forgot'],
    'Logout': ['logout'],
}


def categorize_event(event_name: str):
    """Return one of the 14 action categories for a raw event name, or None if unmatched."""
    name_lower = event_name.lower()
    for category, prefixes in STARTS_WITH.items():
        for prefix in prefixes:
            if name_lower.startswith(prefix):
                return category
    for category, substrings in CONTAINS.items():
        for substr in substrings:
            if substr in name_lower:
                return category
    return None


# ----------------------------------------------------------------------------
# Data loading
# ----------------------------------------------------------------------------
def user_id(record):
    ui = record.get('userIdentity', {})
    return ui.get('userName') or ui.get('arn') or ui.get('type') or 'UNKNOWN'


def service_id(record):
    return record.get('eventSource', 'unknown').split('.')[0]   # "ec2.amazonaws.com" -> "ec2"


def load_events(path):
    with open(path) as f:
        recs = json.load(f)['Records']
    rows = [{
        'timestamp': r['eventTime'],
        'user': user_id(r),
        'action': categorize_event(r['eventName']),
        'service': service_id(r),
        'raw_event': r['eventName'],
    } for r in recs]
    df = pd.DataFrame(rows)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values('timestamp').reset_index(drop=True)


# ----------------------------------------------------------------------------
# 3. Cumulative tripartite graph (user - action - service), edge weight = count
# ----------------------------------------------------------------------------
def build_cumulative_graph(df_up_to_now: pd.DataFrame) -> nx.Graph:
    """Build one cumulative tripartite graph from all events up to 'now'."""
    G = nx.Graph()

    ua_weights = df_up_to_now.groupby(['user', 'action']).size()
    as_weights = df_up_to_now.groupby(['action', 'service']).size()

    for (user, action), w in ua_weights.items():
        G.add_edge(f'user:{user}', f'action:{action}', weight=int(w))
    for (action, service), w in as_weights.items():
        G.add_edge(f'action:{action}', f'service:{service}', weight=int(w))

    return G




# ----------------------------------------------------------------------------
# 4. node2vec (from scratch)
# ----------------------------------------------------------------------------
def generate_walks(G: nx.Graph, num_walks=10, walk_length=40, p=1.0, q=1.0, seed=42):
    """Biased random walks. p controls likelihood of returning to the
    previous node; q controls likelihood of exploring further away."""
    rng = random.Random(seed)
    nodes = list(G.nodes())
    neighbors_cache = {n: list(G.neighbors(n)) for n in nodes}
    weights_cache = {n: [G[n][nbr]['weight'] for nbr in neighbors_cache[n]] for n in nodes}

    walks = []
    for _ in range(num_walks):
        rng.shuffle(nodes)
        for start in nodes:
            if not neighbors_cache[start]:
                continue
            walk = [start]
            for step in range(walk_length - 1):
                cur = walk[-1]
                cur_nbrs = neighbors_cache[cur]
                if not cur_nbrs:
                    break
                if len(walk) == 1:
                    nxt = rng.choices(cur_nbrs, weights=weights_cache[cur], k=1)[0]
                else:
                    prev = walk[-2]
                    probs = []
                    for nbr, wt in zip(cur_nbrs, weights_cache[cur]):
                        if nbr == prev:
                            probs.append(wt / p)
                        elif G.has_edge(prev, nbr):
                            probs.append(wt)
                        else:
                            probs.append(wt / q)
                    nxt = rng.choices(cur_nbrs, weights=probs, k=1)[0]
                walk.append(nxt)
            walks.append(walk)
    return walks


def train_skipgram(walks, embedding_dim=128, window=5, negative=5, epochs=5, lr=0.025, seed=42):
    """Skip-gram with negative sampling -- learns a vector per node such
    that nodes appearing near each other across many walks end up with
    similar vectors."""
    rng = np.random.default_rng(seed)
    vocab = sorted({node for walk in walks for node in walk})
    node2idx = {n: i for i, n in enumerate(vocab)}
    V = len(vocab)

    freq = np.zeros(V)
    for walk in walks:
        for node in walk:
            freq[node2idx[node]] += 1
    neg_probs = freq ** 0.75
    neg_probs /= neg_probs.sum()

    W_in = (rng.random((V, embedding_dim)) - 0.5) / embedding_dim
    W_out = np.zeros((V, embedding_dim))

    def sigmoid(x):
        return 1 / (1 + np.exp(-np.clip(x, -30, 30)))

    max_norm = 10.0  # safety cap: prevents runaway growth on small/repetitive graphs

    def clip(vec):
        n = np.linalg.norm(vec)
        return vec * (max_norm / n) if n > max_norm else vec

    for epoch in range(epochs):
        cur_lr = max(lr * (1 - epoch / epochs), lr * 1e-4)
        for walk in walks:
            idxs = [node2idx[n] for n in walk]
            for center_pos, center in enumerate(idxs):
                win = rng.integers(1, window + 1)
                start = max(0, center_pos - win)
                end = min(len(idxs), center_pos + win + 1)
                for context_pos in range(start, end):
                    if context_pos == center_pos:
                        continue
                    context = idxs[context_pos]
                    u, v = W_in[center].copy(), W_out[context].copy()
                    score = sigmoid(np.dot(u, v))
                    grad = cur_lr * (1 - score)
                    W_in[center] = clip(u + grad * v)
                    W_out[context] = clip(v + grad * u)

                    negs = rng.choice(V, size=negative, p=neg_probs)
                    for neg in negs:
                        if neg == context:
                            continue
                        u_cur = W_in[center].copy()
                        v_neg = W_out[neg].copy()
                        score_neg = sigmoid(np.dot(u_cur, v_neg))
                        grad_neg = cur_lr * (0 - score_neg)
                        W_in[center] = clip(u_cur + grad_neg * v_neg)
                        W_out[neg] = clip(v_neg + grad_neg * u_cur)

    return {vocab[i]: W_in[i] for i in range(V)}


def node2vec_embed(G, dim=128, num_walks=10, walk_length=40, p=1.0, q=1.0, window=5, negative=5, epochs=5, seed=42):
    walks = generate_walks(G, num_walks=num_walks, walk_length=walk_length, p=p, q=q, seed=seed)
    return train_skipgram(walks, embedding_dim=dim, window=window, negative=negative, epochs=epochs, seed=seed)


# ----------------------------------------------------------------------------
# 5. Anomaly scoring
# ----------------------------------------------------------------------------
def cos_sim(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def compute_anomaly_scores(df_up_to_now, embeddings):
    """Returns {user: anomaly_score} for every user active up to this point."""
    scores = {}
    last_service = df_up_to_now.groupby('user').last()['service']

    for user, r in last_service.items():
        user_node = f'user:{user}'
        if user_node not in embeddings:
            continue
        peers = df_up_to_now.loc[
            (df_up_to_now['service'] == r) & (df_up_to_now['user'] != user), 'user'
        ].unique()
        peer_embeddings = [embeddings[f'user:{p}'] for p in peers if f'user:{p}' in embeddings]
        if not peer_embeddings:
            scores[user] = 0.0
            continue
        u_emb = embeddings[user_node]
        best_sim = max(cos_sim(u_emb, p_emb) for p_emb in peer_embeddings)
        scores[user] = 1 - best_sim
    return scores


def threshold_flags(scores, n_std=2.0):
    """Flag users whose score exceeds mean + n_std * std."""
    values = np.array(list(scores.values()))
    if len(values) == 0:
        return 0.0, []
    threshold = values.mean() + n_std * values.std()
    flagged = [u for u, s in scores.items() if s > threshold]
    return threshold, flagged




# ----------------------------------------------------------------------------
# Ground-truth labels (time-windowed; reverse-engineered from the data)
# The 5th attack (billing) could not be isolated and is excluded.
# End dates are exclusive-cutoff-safe (+1 day).
# ----------------------------------------------------------------------------
ATTACK_WINDOWS = [
    # (user, attack_type, start_date, end_date) -- end_date inclusive
    ('cloud_user', 'cryptojacking', '2023-03-14', '2023-03-22'),
    ('cloud_user', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('arn:aws:sts::123456789:assumed-role/flask-server/i-0d6d1080e1184b9b4', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('arn:aws:sts::123456789:assumed-role/backend_server/i-0e113c6c02d37490f', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('arn:aws:sts::123456789:assumed-role/final_instance/i-0a427bfae3dae42ae', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('vpc_peering', 'lateral_movement', '2023-04-20', '2023-04-21'),
    ('test', 'monitor_exploiting', '2023-04-23', '2023-04-24'),
    ('sec-check', 'targeted_services', '2023-04-23', '2023-04-24'),
    # --- synthetic attacks added by this project (Part 2) ---
    # ai-agent is an AssumedRole with no userName, so user_id() returns its full arn
    ('arn:aws:sts::123456789:assumed-role/ai-agent-role/ai-agent', 'prompt_injection_visible',  '2023-03-28', '2023-03-29'),
    ('arn:aws:sts::123456789:assumed-role/ai-agent-role/ai-agent', 'prompt_injection_stealthy', '2023-04-04', '2023-04-05'),
    ('cert-admin', 'mitm_visible',  '2023-04-11', '2023-04-12'),
    ('Level6',     'mitm_stealthy', '2023-04-14', '2023-04-15'),
]

ATTACK_TYPES = ['cryptojacking', 'lateral_movement', 'monitor_exploiting', 'targeted_services',
                'prompt_injection_visible', 'prompt_injection_stealthy', 'mitm_visible', 'mitm_stealthy']


def label_for(user, cutoff_timestamp):
    """cutoff_timestamp: the snapshot's cutoff time (pd.Timestamp, tz-aware)."""
    cutoff_date = pd.Timestamp(cutoff_timestamp).tz_convert('UTC').normalize()
    for u, attack, start, end in ATTACK_WINDOWS:
        if u != user:
            continue
        start_ts = pd.Timestamp(start, tz='UTC')
        end_ts = pd.Timestamp(end, tz='UTC')
        if start_ts <= cutoff_date <= end_ts:
            return attack
    return 'benign'


# ----------------------------------------------------------------------------
# 6. Evaluation (ROC-AUC, precision / recall / F1 / FPR at mean + n*std)
# ----------------------------------------------------------------------------
def evaluate_scores(scores_df, n_stds=(1.0, 2.0)):
    """scores_df must have columns: cutoff, user, score.
    Returns the labeled dataframe and prints ROC-AUC + precision/recall/F1/FPR
    at each threshold in n_stds."""
    df = scores_df.copy()
    df['cutoff'] = pd.to_datetime(df['cutoff'])
    df['label'] = df.apply(lambda row: label_for(row['user'], row['cutoff']), axis=1)
    df['is_attack'] = df['label'] != 'benign'

    print('Total (user, snapshot) samples:', len(df))
    print('Attack-labeled samples:', df['is_attack'].sum())
    if df['is_attack'].sum() > 0:
        print(df[df['is_attack']]['label'].value_counts())
    print()

    auc = roc_auc_score(df['is_attack'].astype(int), df['score'])
    print(f'ROC-AUC: {auc:.4f}')
    print()

    for n_std in n_stds:
        tp = fp = fn = tn = 0
        for cutoff, group in df.groupby('cutoff'):
            thresh = group['score'].mean() + n_std * group['score'].std()
            pred = group['score'] > thresh
            actual = group['is_attack']
            tp += (pred & actual).sum()
            fp += (pred & ~actual).sum()
            fn += (~pred & actual).sum()
            tn += (~pred & ~actual).sum()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        print(f'--- threshold = mean + {n_std}*std ---')
        print(f'  TP={tp} FP={fp} FN={fn} TN={tn}')
        print(f'  Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f} FPR={fpr:.3f}')

    return df


# ----------------------------------------------------------------------------
# Runner (resumable)
# ----------------------------------------------------------------------------
def run_snapshot(df, cutoff):
    df_snap = df[df['timestamp'] < cutoff]
    G = build_cumulative_graph(df_snap)
    emb = node2vec_embed(G, dim=16, num_walks=10, walk_length=20, p=1.0, q=1.0, epochs=5, seed=1)
    scores = compute_anomaly_scores(df_snap, emb)
    return scores, G.number_of_nodes(), G.number_of_edges()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True, help='path to the CloudTrail JSON (attack.json)')
    ap.add_argument('--out', default='cs_gad_results.csv', help='CSV for incremental results')
    ap.add_argument('--quick', action='store_true', help='only 3 snapshots (sanity check)')
    args = ap.parse_args()

    df = load_events(args.data)
    print(f'Loaded {len(df)} events, {df.timestamp.min()} -> {df.timestamp.max()}')
    print(f'Action-category coverage: {df.action.notna().mean():.1%}')

    daily = list(pd.date_range('2023-03-14', '2023-04-24', freq='1D', tz='UTC'))
    hourly = list(pd.date_range('2023-04-20 00:00', '2023-04-21 00:00', freq='1h', tz='UTC'))
    cutoffs = [('daily', c) for c in daily] + [('hourly', c) for c in hourly]
    if args.quick:
        cutoffs = [('daily', pd.Timestamp(d, tz='UTC')) for d in ('2023-03-15', '2023-04-21', '2023-04-24')]

    if not os.path.exists(args.out):
        pd.DataFrame(columns=['kind', 'cutoff', 'user', 'score', 'n_nodes', 'n_edges']).to_csv(args.out, index=False)
    existing = pd.read_csv(args.out)
    done = set(zip(existing['kind'], existing['cutoff'].astype(str)))

    for kind, cutoff in cutoffs:
        if (kind, str(cutoff)) in done:
            continue
        scores, n_nodes, n_edges = run_snapshot(df, cutoff)
        rows = [{'kind': kind, 'cutoff': str(cutoff), 'user': u, 'score': s,
                 'n_nodes': n_nodes, 'n_edges': n_edges} for u, s in scores.items()]
        pd.DataFrame(rows).to_csv(args.out, mode='a', header=False, index=False)
        print(f'[{kind}] {cutoff}: {len(scores)} users, {n_nodes} nodes', flush=True)

    print('\nALL DONE - evaluating')
    results = pd.read_csv(args.out)
    labeled = evaluate_scores(results)
    labeled.to_csv(args.out.replace('.csv', '_labeled.csv'), index=False)
    print('Saved:', args.out, 'and', args.out.replace('.csv', '_labeled.csv'))


if __name__ == '__main__':
    main()
