#!/usr/bin/env python3
"""
Descriptive statistical analysis of the CS-GAD dataset extension (READ-ONLY).
Does NOT modify data, labels, or run any model. It only reads the expanded
labeled dataset + the synthetic-record set, tags every record into one of four
classes, computes statistics, writes a summary CSV, and renders figures.

Four classes (strictly separated, as required):
  original_benign      - real records, label 0
  original_attack      - real records, label 1 (reverse-engineered attacks)
  synthetic_benign     - injected warm-up records, label 0
  synthetic_malicious  - injected attack records, label 1

Inputs (paths can be overridden with args):
  --expanded  attack_expanded_labeled.json   (has per-record 'label')
  --synth     synthetic_only.json            (the 109 injected records)
  --csgad     cs_gad.py                       (for the exact action categorizer)
Outputs:
  statistical_summary.csv
  figures/*.png
  stdout: structured tables used to write the report
"""
import argparse, json, csv, importlib.util, collections
from datetime import datetime
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def load_categorizer(path):
    spec = importlib.util.spec_from_file_location("csgad", path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m.categorize_event, m.user_id, m.service_id


def main():
    ap = argparse.ArgumentParser()
    # Defaults assume the three inputs sit next to this script (copy or symlink
    # them from the cs-gad-submission package), or pass explicit paths.
    ap.add_argument("--expanded", default="attack_expanded_labeled.json")
    ap.add_argument("--synth", default="synthetic_only.json")
    ap.add_argument("--csgad", default="cs_gad.py")
    ap.add_argument("--figdir", default="figures")
    ap.add_argument("--csv", default="statistical_summary.csv")
    args = ap.parse_args()

    categorize_event, user_id, service_id = load_categorizer(args.csgad)

    R = json.load(open(args.expanded))["Records"]
    synth_ids = {r["eventID"] for r in json.load(open(args.synth))["Records"]}

    # ---- tag every record ----
    rows = []
    for r in R:
        es = r.get("eventID")
        is_synth = es in synth_ids
        lab = r.get("label", 0)
        cls = (("synthetic_" if is_synth else "original_") +
               ("malicious" if lab == 1 else "benign")) if is_synth else \
              ("original_attack" if lab == 1 else "original_benign")
        if is_synth:
            cls = "synthetic_malicious" if lab == 1 else "synthetic_benign"
        ro = r.get("readOnly", None)
        rows.append({
            "time": r["eventTime"],
            "day": r["eventTime"][:10],
            "year": r["eventTime"][:4],
            "user": user_id(r),
            "service": service_id(r),
            "eventName": r["eventName"],
            "category": categorize_event(r["eventName"]),
            "readOnly": ro,
            "error": "errorCode" in r,
            "label": lab,
            "synthetic": is_synth,
            "cls": cls,
        })
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df["time"])
    summary = []  # (section, metric, value)

    def add(sec, metric, val): summary.append({"section": sec, "metric": metric, "value": val})

    orig = df[~df.synthetic]; synth = df[df.synthetic]

    print("="*78); print("SECTION 1 - DATASET OVERVIEW & LABEL DISTRIBUTION"); print("="*78)
    print("\nClass breakdown (expanded dataset):")
    cls_counts = df["cls"].value_counts()
    tot = len(df)
    for c in ["original_benign","original_attack","synthetic_benign","synthetic_malicious"]:
        n = int(cls_counts.get(c,0)); print(f"  {c:22s} {n:8d}  ({100*n/tot:5.2f}%)"); add("1.classes", c, n)
    print(f"  {'TOTAL':22s} {tot:8d}")
    add("1.classes","total",tot)
    print(f"\nOriginal total: {len(orig)}  (benign {int((orig.label==0).sum())}, attack {int((orig.label==1).sum())})")
    print(f"Expanded total: {len(df)}  (benign {int((df.label==0).sum())}, attack {int((df.label==1).sum())})")
    add("1.totals","original_total",len(orig)); add("1.totals","expanded_total",len(df))
    add("1.totals","original_attack",int((orig.label==1).sum()))
    add("1.totals","expanded_attack",int((df.label==1).sum()))

    print("\nSynthetic records by scenario:")
    # map synthetic records to scenario by (user, day)
    scen_map = {("ai-agent","2023-03-28"):"1A visible", ("ai-agent","2023-04-04"):"1B stealthy",
                ("cert-admin","2023-04-11"):"2A visible", ("Level6","2023-04-14"):"2B stealthy"}
    def scen_of(row):
        u = row.user.split("/")[-1] if "/" in str(row.user) else row.user
        k = (u, row.day)
        if k in scen_map: return scen_map[k]
        if u=="ai-agent" and row.day in ("2023-03-24","2023-03-25","2023-03-26","2023-03-27"): return "warm-up (benign)"
        return "?"
    synth = synth.copy(); synth["scen"] = synth.apply(scen_of, axis=1)
    for s, n in synth["scen"].value_counts().items():
        print(f"  {s:20s} {int(n):4d}"); add("1.scenario", s, int(n))

    # unique counts before/after
    print("\nUnique entities before (original) vs after (expanded):")
    for lab,sel in [("users","user"),("services","service"),("categories","category")]:
        b=orig[sel].nunique(); a=df[sel].nunique()
        print(f"  unique {lab:11s} before={b:4d}  after={a:4d}  (+{a-b})")
        add("1.unique", f"{lab}_before", b); add("1.unique", f"{lab}_after", a)
    b_days=orig.day.nunique(); a_days=df.day.nunique()
    print(f"  active days       before={b_days:4d}  after={a_days:4d}  (+{a_days-b_days})")
    add("1.unique","active_days_before",b_days); add("1.unique","active_days_after",a_days)

    # new users / services / raw actions / categories introduced by synthetic
    new_users = sorted(set(synth.user) - set(orig.user))
    new_services = sorted(set(synth.service) - set(orig.service))
    new_rawactions = sorted(set(synth.eventName) - set(orig.eventName))
    new_categories = sorted(set(synth.category.dropna()) - set(orig.category.dropna()))
    print(f"\nNEW users introduced by synthetic:      {new_users}")
    print(f"NEW services introduced by synthetic:   {new_services}")
    print(f"NEW CS-GAD categories (graph nodes):    {new_categories or 'NONE'}")
    print(f"NEW raw API actions (eventName):        {len(new_rawactions)} -> {new_rawactions}")
    add("1.new","new_users",";".join(new_users)); add("1.new","new_services",";".join(new_services))
    add("1.new","new_categories",";".join(new_categories) or "NONE")
    add("1.new","new_raw_actions",";".join(new_rawactions))

    # ---------------- SECTION 2 TEMPORAL ----------------
    print("\n"+"="*78); print("SECTION 2 - TEMPORAL ACTIVITY"); print("="*78)
    daily = df.groupby("day").size()
    daily_orig = orig.groupby("day").size()
    print(f"\nActive days: original={orig.day.nunique()}, synthetic-only days={sorted(set(synth.day)-set(orig.day))}")
    # 2023 window table
    d23 = df[df.year=="2023"]
    print("\n2023 window - events per day by class:")
    piv = d23.pivot_table(index="day", columns="cls", values="time", aggfunc="count", fill_value=0)
    print(piv.to_string())
    # are synthetic attack days empty of OTHER activity?
    print("\nOn each synthetic day, is there ANY original activity?")
    for d in sorted(set(synth.day)):
        n_orig_that_day = int((orig.day==d).sum())
        print(f"  {d}: original events = {n_orig_that_day}  ({'EMPTY of original' if n_orig_that_day==0 else 'has original'})")
        add("2.synthday_origcount", d, n_orig_that_day)
    # within-window temporal spread (visible vs stealthy)
    print("\nWithin-attack temporal spread (malicious records only):")
    for (u,d),label in scen_map.items():
        sub = synth[(synth.scen==label)]
        if len(sub)==0: continue
        t = sub.ts.sort_values()
        span = (t.iloc[-1]-t.iloc[0]).total_seconds()/60.0
        print(f"  {label:12s} n={len(sub):2d}  span={span:7.1f} min  ({t.iloc[0].strftime('%H:%M')}-{t.iloc[-1].strftime('%H:%M')})")
        add("2.span_min", label, round(span,1))
    # gaps between active periods
    days_sorted = sorted(pd.to_datetime(df.day.unique()))
    gaps = [(days_sorted[i+1]-days_sorted[i]).days for i in range(len(days_sorted)-1)]
    biggest = max(gaps); bi = gaps.index(biggest)
    print(f"\nLargest gap between active days: {biggest} days ({days_sorted[bi].date()} -> {days_sorted[bi+1].date()})")
    add("2.gap","largest_gap_days",biggest)

    # ---------------- SECTION 3 USERS ----------------
    print("\n"+"="*78); print("SECTION 3 - USER ACTIVITY"); print("="*78)
    AGENT = next((u for u in df.user.unique() if str(u).endswith("/ai-agent")), "ai-agent")
    top_benign = orig[orig.label==0].user.value_counts().head(3).index.tolist()
    focus = [("ai-agent", AGENT), ("cert-admin","cert-admin"), ("Level6","Level6")] + \
            [(str(x).split("/")[-1], x) for x in top_benign]
    print(f"\n(context) busiest original benign users: {[str(u).split('/')[-1] for u in top_benign]}")
    for uname, u in focus:
        sub = df[df.user==u]
        if len(sub)==0:
            print(f"\n{uname}: NOT FOUND"); continue
        nb=int((sub.label==0).sum()); na=int((sub.label==1).sum())
        svcs=sub.service.value_counts().to_dict()
        cats=sub.category.value_counts().to_dict()
        days=sorted(sub.day.unique())
        yrs=dict(sub[sub.label==0].year.value_counts())  # benign activity by year
        # dormancy: gap between last BENIGN day and first MALICIOUS day
        ben_days=sorted(sub[sub.label==0].ts); mal_days=sorted(sub[sub.label==1].ts)
        dorm = ((mal_days[0]-ben_days[-1]).days if ben_days and mal_days else None)
        print(f"\n{uname}:  total={len(sub)}  benign={nb}  malicious={na}")
        print(f"   active days: {days[0]}..{days[-1]}  ({sub.day.nunique()} days)")
        print(f"   benign activity by year: {yrs}")
        if dorm is not None:
            print(f"   dormancy before attack (last benign -> first malicious): {dorm} days")
        print(f"   services: {svcs}")
        print(f"   categories: {cats}")
        if uname in ("ai-agent","cert-admin","Level6"):
            add("3.user", f"{uname}_total", len(sub)); add("3.user", f"{uname}_benign", nb)
            add("3.user", f"{uname}_malicious", na); add("3.user", f"{uname}_services", ";".join(svcs))
            if dorm is not None: add("3.user", f"{uname}_dormancy_days", dorm)
    # Level6: history vs attack action categories on acm/elb
    print("\nLevel6 on ACM/ELB/Route53 - history vs attack, by eventName & category")
    print("   (NOTE: readOnly flag is null in 2017-2018 records, so read/write is judged by action name/category)")
    l6 = df[df.user=="Level6"]
    for svc in ["acm","elasticloadbalancing","route53"]:
        s = l6[l6.service==svc]
        hist = s[s.label==0]; atk = s[s.label==1]
        print(f"   {svc}:")
        print(f"      history eventNames: {dict(hist.eventName.value_counts())}")
        print(f"              categories: {dict(hist.category.value_counts())}")
        print(f"      attack  eventNames: {dict(atk.eventName.value_counts())}")
        print(f"              categories: {dict(atk.category.value_counts())}")
    # global readOnly availability by class (data-quality note)
    print("\nreadOnly field availability by class (data-quality limitation):")
    for c in ["original_benign","original_attack","synthetic_benign","synthetic_malicious"]:
        s=df[df.cls==c]; present=int(s.readOnly.notna().sum())
        print(f"   {c:22s} readOnly present in {present}/{len(s)} ({100*present/len(s):.1f}%)")

    # ---------------- SECTION 4 ACTION/SERVICE ----------------
    print("\n"+"="*78); print("SECTION 4 - ACTION & SERVICE DISTRIBUTION"); print("="*78)
    print("\nCS-GAD action category share (%) by class:")
    catshare = pd.crosstab(df.category, df.cls, normalize="columns")*100
    print(catshare.round(1).to_string())
    # services exclusive to a single user
    svc_users = df.groupby("service")["user"].nunique()
    excl = svc_users[svc_users==1]
    print(f"\nServices used by EXACTLY ONE user: {len(excl)}")
    for svc in excl.index:
        u = df[df.service==svc].user.iloc[0].split("/")[-1]
        nrec=int((df.service==svc).sum())
        tag = " <-- synthetic-only" if svc in new_services else ""
        if nrec>=3 or svc in new_services:
            print(f"   {svc:22s} used only by {u:20s} ({nrec} recs){tag}")
    # read/write + success/fail by class
    print("\nRead/Write and Success/Fail by class:")
    for c in ["original_benign","original_attack","synthetic_benign","synthetic_malicious"]:
        s=df[df.cls==c]
        ro=s.readOnly
        rt=int((ro==True).sum()); wr=int((ro==False).sum()); un=int(ro.isna().sum())
        err=int(s.error.sum()); errp=100*err/len(s) if len(s) else 0
        print(f"  {c:22s} read={rt:7d} write={wr:6d} unknown={un:6d} | errors={err} ({errp:.1f}%)")
        add("4.rw", f"{c}_read", rt); add("4.rw", f"{c}_write", wr)
        add("4.err", f"{c}_error_pct", round(errp,2))
    # bedrock focus
    print("\nBEDROCK focus:")
    bed = df[df.service=="bedrock"]
    print(f"   bedrock records: {len(bed)}  users: {set(x.split('/')[-1] for x in bed.user)}")
    print(f"   benign(warmup)={int((bed.label==0).sum())}  malicious={int((bed.label==1).sum())}")
    print(f"   eventNames: {dict(bed.eventName.value_counts())}  -> category: {set(bed.category)}")
    print(f"   is 'bedrock' service in original data? {'YES' if 'bedrock' in set(orig.service) else 'NO'}")
    print(f"   is InvokeModel category new? category={categorize_event('InvokeModel')}; "
          f"same category exists in original? {'YES' if categorize_event('InvokeModel') in set(orig.category) else 'NO'}")
    add("4.bedrock","records",len(bed)); add("4.bedrock","benign",int((bed.label==0).sum()))
    add("4.bedrock","malicious",int((bed.label==1).sum()))
    add("4.bedrock","service_in_original","bedrock" in set(orig.service))

    # ---------------- write CSV ----------------
    seen=set(); dedup=[]
    for r in summary:
        k=(r["section"],r["metric"])
        if k in seen: continue
        seen.add(k); dedup.append(r)
    with open(args.csv,"w",newline="") as f:
        w=csv.DictWriter(f, fieldnames=["section","metric","value"]); w.writeheader(); w.writerows(dedup)
    print(f"\nWrote {args.csv} ({len(summary)} rows)")

    # ================= FIGURES =================
    FD = args.figdir
    CLSCOL = {"original_benign":"#9e9e9e","original_attack":"#1565c0",
              "synthetic_benign":"#66bb6a","synthetic_malicious":"#c62828"}

    # Fig 1: full timeline (monthly), log scale, show the 2018->2023 gap
    fig,ax=plt.subplots(figsize=(11,3.6))
    mon = df.assign(m=df.ts.dt.to_period("M").astype(str)).groupby("m").size()
    ax.bar(range(len(mon)), mon.values, color="#607d8b")
    ax.set_yscale("log"); ax.set_xticks(range(0,len(mon),3)); ax.set_xticklabels(mon.index[::3],rotation=45,ha="right",fontsize=7)
    ax.set_title("Full timeline: events per month (log) - note the 2018->2023 gap"); ax.set_ylabel("events (log)")
    plt.tight_layout(); plt.savefig(f"{FD}/fig1_full_timeline.png",dpi=140); plt.close()

    # Fig 2: 2023 daily events, stacked by class, log scale, synthetic days marked
    d23p = d23.pivot_table(index="day", columns="cls", values="time", aggfunc="count", fill_value=0)
    order=[c for c in ["original_benign","original_attack","synthetic_benign","synthetic_malicious"] if c in d23p.columns]
    fig,ax=plt.subplots(figsize=(12,4.6))
    bottom=[0]*len(d23p)
    for c in order:
        ax.bar(range(len(d23p)), d23p[c].values, bottom=bottom, color=CLSCOL[c], label=c)
        bottom=[b+v for b,v in zip(bottom,d23p[c].values)]
    ax.set_yscale("log"); ax.set_xticks(range(len(d23p))); ax.set_xticklabels(d23p.index,rotation=60,ha="right",fontsize=7)
    synth_days=set(synth.day)
    for i,d in enumerate(d23p.index):
        if d in synth_days: ax.get_xticklabels()[i].set_color("#c62828"); ax.get_xticklabels()[i].set_fontweight("bold")
    ax.set_title("2023 window: events per day by class (log). Red bold labels = synthetic days")
    ax.set_ylabel("events (log)"); ax.legend(fontsize=8)
    plt.tight_layout(); plt.savefig(f"{FD}/fig2_daily_2023_by_class.png",dpi=140); plt.close()

    # Fig 3: user activity (3 focus users + context) benign vs malicious, log
    fig,ax=plt.subplots(figsize=(10,4.2))
    us = ["ai-agent","cert-admin","Level6"]+[u for u in top_benign]
    labs=[u.split("/")[-1] for u in us]
    ben=[int(((df.user==u)&(df.label==0)).sum()) for u in us]
    mal=[int(((df.user==u)&(df.label==1)).sum()) for u in us]
    x=range(len(us))
    ax.bar(x,[max(b,0.5) for b in ben],color="#9e9e9e",label="benign")
    ax.bar(x,[max(m,0.5) for m in mal],bottom=[max(b,0.5) for b in ben],color="#c62828",label="malicious")
    ax.set_yscale("log"); ax.set_xticks(list(x)); ax.set_xticklabels(labs,rotation=30,ha="right",fontsize=8)
    ax.set_title("User activity: benign vs malicious events (log). First 3 = synthetic-related")
    ax.set_ylabel("events (log)"); ax.legend(); ax.axvline(2.5,color="#888",ls="--",lw=1)
    plt.tight_layout(); plt.savefig(f"{FD}/fig3_user_activity.png",dpi=140); plt.close()

    # Fig 4: action-category share original_attack vs synthetic_malicious
    fig,ax=plt.subplots(figsize=(11,4.4))
    cmp=pd.crosstab(df.category,df.cls,normalize="columns")*100
    cats=sorted(set(cmp.index))
    oa=[cmp.loc[c,"original_attack"] if "original_attack" in cmp.columns and c in cmp.index else 0 for c in cats]
    sm=[cmp.loc[c,"synthetic_malicious"] if "synthetic_malicious" in cmp.columns and c in cmp.index else 0 for c in cats]
    x=range(len(cats)); w=0.4
    ax.bar([i-w/2 for i in x],oa,w,label="original_attack",color="#1565c0")
    ax.bar([i+w/2 for i in x],sm,w,label="synthetic_malicious",color="#c62828")
    ax.set_xticks(list(x)); ax.set_xticklabels(cats,rotation=45,ha="right",fontsize=7)
    ax.set_ylabel("% of that class's events"); ax.set_title("CS-GAD action-category share: original attack vs synthetic malicious")
    ax.legend(fontsize=8)
    plt.tight_layout(); plt.savefig(f"{FD}/fig4_action_category.png",dpi=140); plt.close()

    print(f"Wrote figures to {FD}/ : fig1_full_timeline, fig2_daily_2023_by_class, fig3_user_activity, fig4_action_category")


if __name__ == "__main__":
    main()
