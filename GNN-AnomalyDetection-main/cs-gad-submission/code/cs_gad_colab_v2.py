#!/usr/bin/env python3
"""
CS-GAD faithful rebuild v2 — COLAB, using the AUTHORS' real stack.

Differences from v1 (cs_gad_colab.py), both aimed at the reproduction gap:
  1. WALK: real `node2vec` package (canonical Grover-Leskovec alias-sampling
     weighted biased walk) instead of the hand-rolled walk. Same parameters as
     the authors' stellargraph BiasedRandomWalk: p=0.5, q=2.0, walk_length=20,
     num_walks=10, weighted, + gensim Word2Vec(vector_size=128, window=5, sg=1,
     min_count=0, workers=1).  (stellargraph itself will not install on modern
     Python — that is why it must be substituted; node2vec is faithful to the
     same algorithm.)
  2. EVALUATION: mirrors the notebook's executed path (cell 42 `SL=gen_stellar([G])`):
     ONE cumulative graph over all records, embed once, action-based cosine-NN
     score = per-user MAX over actions, then ONE global threshold mean+n*std
     over the per-user scores (cells 61,67-70).  v1 instead scored at a single
     attack-day snapshot and thresholded within it.

HOW TO RUN IN COLAB
  !pip install -q node2vec gensim
  # upload event_category.json, attack_expanded_labeled.json, attack.json
  %run cs_gad_colab_v2.py
Read the REPRODUCTION CONTROL block first — if the original attacks don't line
up with paper Table 2 here, the gap is NOT the walk and we look at aggregation.
"""
import json, numpy as np, pandas as pd, networkx as nx
from sklearn.neighbors import NearestNeighbors
from node2vec import Node2Vec

EC_PATH="event_category.json"; EXPANDED_PATH="attack_expanded_labeled.json"
ORIGINAL_PATH="attack.json"   # set None to skip the control
SEEDS=[42,1,2]

# ---------- categorization (authors cell 3) ----------
STARTS_WITH={'CreateObject':['accept','request','create','copy','run','purchase','allocate','import','startinstances'],
 'ModifyExistingResource':['modify','update','set','tag','deregister','deprecate','un','reject','register'],
 'ListResources':['list'],'Download/UploadObjects':['enc','getobjects','upload'],'GetInfo':['describe','get','search'],
 'AssociateResources':['associate','put'],'Login':['assume','login','switch','renewrole','renewdelegate','checkmfa'],
 'RemovePermissions':['remove'],'GrantPermissions':['add','authorize']}
CONTAINS={'Delete':['delet','terminate','revoke','drop','releaseaddress'],'DisableObjects':['disabl','stop','cancel','unlink','suspend'],
 'EnableObjects':['enabl','start','invoke','subscribe','test','complete'],'SensitiveInfo':['send','accesskey','secretkey','token','invite','exportapi','decode'],
 'Logout':['exit'],'CreateObject':['create','copy'],
 'ModifyExistingResource':['failover','change','confirm','promote','reboot','rotate','replace','retire','detach','modify','update','set','tag','deregister','Deprecate','attach','upgrade','wipe','transfer','validate','publish'],
 'ListResources':['list'],'Download/UploadObjects':['getobjects','upload'],
 'GetInfo':['describe','get','view','decrypt','generate','lookup','scan','simulate'],
 'AssociateResources':['associate','put'],'Login':['assume','login','renewrole','sign','forgot'],'Logout':['logout']}
def make_cn(ec):
    def cn(n):
        if n in ec: return ec[n]
        l=str(n).lower()
        for k,v in STARTS_WITH.items():
            for e in v:
                if l.startswith(e): return k
        for k,v in CONTAINS.items():
            for e in v:
                if e in l: return k
        return None
    return cn

def load_users(path, ec):
    data=json.load(open(path))['Records']; awsc=pd.DataFrame.from_records(data)
    ui=pd.json_normalize(awsc['userIdentity'])
    users=ui.merge(awsc[['eventTime','eventName','eventSource','awsRegion','errorCode']],left_index=True,right_index=True)
    for c in ['userName','arn','invokedBy','principalId']:
        if c not in users.columns: users[c]=np.nan
    users['userName']=users['userName'].fillna(users['arn']).fillna(users['invokedBy']).fillna(users['invokedBy']).fillna(users['principalId']).fillna('accountId')
    users=users[['eventTime','type','userName','eventName','eventSource','awsRegion','errorCode']]
    users=users.rename(columns={'eventTime':'timestamp','userName':'Identifier','eventSource':'TargetService','errorCode':'Error'})
    cn=make_cn(ec); users['eventName']=users['eventName'].apply(cn)
    users['timestamp']=pd.to_datetime(users['timestamp']).map(pd.Timestamp.timestamp).map(int)
    users=users.sort_values('timestamp',ascending=True,ignore_index=True)
    users['Identifier']=users['Identifier'].apply(lambda x: x if (len(str(x).split(":"))!=2) else str(x).split(":")[1])
    users['identity-event']="source-"+users['Identifier'].astype(str)+"|"+"action-"+users['eventName'].astype(str)
    users['event-target']="action-"+users['eventName'].astype(str)+"|"+"target-"+users['TargetService'].astype(str)
    users=users[users['eventName'].notna()]
    users['Identifier']="source-"+users['Identifier'].astype(str)
    users['TargetService']="target-"+users['TargetService'].astype(str); users['eventName']="action-"+users['eventName'].astype(str)
    return users

def build_graph(df):                                    # authors cells 28-30, single cumulative graph
    G=nx.Graph()
    for col in ['Identifier','eventName','TargetService']:
        for n in df[col].unique():
            if n is not None: G.add_node(str(n))
    for col in ['identity-event','event-target']:
        e=df[col].value_counts(); e=e/e.max()
        for node,val in e.items():
            s,t=node.split('|')
            if "None" not in s and "None" not in t: G.add_edge(s,t,weight=float(val))
    return G

def embed(G, seed):                                     # real node2vec (authors cells 37-40)
    n2v=Node2Vec(G,dimensions=128,walk_length=20,num_walks=10,p=0.5,q=2.0,
                 weight_key='weight',workers=1,seed=seed,quiet=True)
    m=n2v.fit(window=5,min_count=0,sg=1,workers=1,seed=seed)   # workers=1 so Word2Vec is reproducible
    return {n:np.asarray(m.wv[str(n)]) for n in G.nodes() if str(n) in m.wv}

def scores(G, emb):
    # FAITHFUL to authors cells 48/53/54/61:
    #  - distance table over ALL source users, 0 for anyone never compared
    #  - per (user, nearest-neighbour) write, FIRST write wins (cell 53 `if ...==0`)
    #  - per-user score = row max over neighbours (cell 61 distance_df.T.max())
    #  - threshold population therefore INCLUDES all the zero-score users
    source_users=[n for n in G.nodes() if str(n).startswith('source-') and 'resource-' not in str(n)]
    dd={u:{} for u in source_users}                     # dd[u][nn] = first distance written
    for act in [n for n in G.nodes() if str(n).startswith('action-')]:   # G.nodes() order == adjacency col order
        us=[m for m in G.neighbors(act) if str(m).startswith('source-') and 'resource-' not in str(m) and m in emb]
        if len(us)<2: continue
        X=np.array([emb[u] for u in us])
        dist,ind=NearestNeighbors(n_neighbors=2,algorithm='brute',metric='cosine').fit(X).kneighbors(X)
        for i,u in enumerate(us):
            nn=us[ind[i][1]]; d=float(dist[i][1])
            if dd[u].get(nn,0.0)==0.0: dd[u][nn]=d       # first-write-wins
    return {u:(max(dd[u].values()) if dd[u] else 0.0) for u in source_users}   # 0 kept for unscored users

def flags(ans):
    v=np.array(list(ans.values())); return v.mean()+v.std(), v.mean()+2*v.std()

# ===================== REPRODUCTION CONTROL (original data) =====================
if ORIGINAL_PATH:
    ec=json.load(open(EC_PATH)); do=load_users(ORIGINAL_PATH,ec); allu=set(do['Identifier'].unique())
    def mo(subs): return {u for u in allu for s in subs if (s==u) or (s!='source-test' and s in u)}
    ATK={'cryptojacking':['cloud_user'],'lateral_movement':['flask-server','final_instance','backend_server','vpc_peering'],
         'monitor_exploiting':['source-test'],'targeted_services':['sec-check']}
    paper={'cryptojacking':'12/4','lateral_movement':'25/8','monitor_exploiting':'detected','targeted_services':'20/10'}
    allatk=set().union(*[mo(s) for s in ATK.values()])
    G=build_graph(do)
    print("\n========== REPRODUCTION CONTROL (original data, full cumulative graph) ==========")
    print(f"graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges  | real node2vec walk")
    print(f"{'attack':20s} {'seed42 detected?':18s} {'rank':>8s}   paper")
    an=scores(G,embed(G,42)); t1,t2=flags(an); v=np.array(list(an.values()))
    benign=[u for u in an if u not in allatk]
    for name,subs in ATK.items():
        atk=mo(subs); a=[an[u] for u in atk if u in an]
        if not a: print(f"{name:20s} (not scored)"); continue
        amax=max(a); rank=int(sum(1 for x in an.values() if x>amax))+1
        det='YES' if amax>t1 else ('YES(2sd)' if amax>t2 else 'no')
        print(f"{name:20s} {det:18s} {rank:>4d}/{len(an):<3d}   {paper[name]}")
    fpr1=100*sum(1 for u in benign if an[u]>t1)/len(benign); fpr2=100*sum(1 for u in benign if an[u]>t2)/len(benign)
    print(f"global FPR: {fpr1:.0f}% @1sd, {fpr2:.0f}% @2sd   (one threshold over all users)")

# ===================== EXPANDED DATA — our four attacks =====================
ec=json.load(open(EC_PATH)); df=load_users(EXPANDED_PATH,ec); allu=set(df['Identifier'].unique())
SCEN=[('1A prompt-injection visible','ai-agent'),('1B prompt-injection stealthy','ai-agent'),
      ('2A mitm visible (new user)','cert-admin'),('2B mitm stealthy (insider)','source-Level6')]
def m(sub): return {u for u in allu if (sub==u) or (sub!='source-Level6' and sub in u)}
G=build_graph(df)
print("\n========== EXPANDED DATA — our four attacks (full graph, 3 seeds) ==========")
print(f"graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
print(f"{'scenario':30s} {'seed':>4s} {'score':>6s} {'rank':>8s} {'>1sd':>5s} {'>2sd':>5s}")
from collections import defaultdict; agg=defaultdict(list)
for seed in SEEDS:
    an=scores(G,embed(G,seed)); t1,t2=flags(an)
    for name,sub in SCEN:
        a=[an[u] for u in m(sub) if u in an]
        if not a: print(f"{name:30s} {seed:4d} (not scored)"); continue
        amax=max(a); rank=int(sum(1 for x in an.values() if x>amax))+1
        f1=amax>t1; f2=amax>t2; agg[name].append((amax,f1,f2))
        print(f"{name:30s} {seed:4d} {amax:6.3f} {rank:>4d}/{len(an):<3d} {str(f1):>5s} {str(f2):>5s}")
print("\n--- per-scenario across seeds ---")
for name,_ in SCEN:
    g=agg[name]; print(f"  {name:30s} >1sd {sum(f1 for _,f1,_ in g)}/{len(g)} | >2sd {sum(f2 for _,_,f2 in g)}/{len(g)} | mean {np.mean([s for s,_,_ in g]):.3f}")
print("\nDone.")
