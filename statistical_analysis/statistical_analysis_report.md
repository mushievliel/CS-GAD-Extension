# Descriptive Statistical Analysis — CS-GAD Dataset Extension

**Scope:** descriptive (read-only) analysis of the expanded dataset to assess how
the synthetic attack records compare with the original data and whether any
artificial patterns could make the attacks trivially detectable. **No data,
labels, or model were modified or run.** All numbers are reproducible with
`stat_analysis.py` from `data/attack_expanded_labeled.json` +
`data/synthetic_only.json`.

Records are separated into four classes throughout:
`original_benign`, `original_attack`, `synthetic_benign` (warm-up),
`synthetic_malicious`.

> **Stance:** this report is deliberately critical. Where the data reveals a
> weakness, it is stated as such. Observed differences are kept separate from
> hypotheses that would require a model experiment (ablation) to confirm.

## Reproduction

```bash
# place these 3 files (from the cs-gad-submission package) next to stat_analysis.py:
#   attack_expanded_labeled.json , synthetic_only.json , cs_gad.py
pip install pandas matplotlib
python stat_analysis.py          # or pass --expanded/--synth/--csgad paths
# writes: statistical_summary.csv and figures/*.png
```

---

## 1. Dataset overview and label distribution

| Class | Records | % of expanded |
|---|---:|---:|
| original_benign | 100,022 | 93.28% |
| original_attack | 7,094 | 6.62% |
| synthetic_benign (warm-up) | 25 | 0.02% |
| synthetic_malicious | 84 | 0.08% |
| **Total** | **107,225** | 100% |

Original = 107,116 (100,022 benign / 7,094 attack). Expanded = 107,225
(100,047 benign / 7,178 attack). The synthetic addition is **0.10%** of the
dataset (84 malicious + 25 benign).

**Synthetic records by scenario:**

| Scenario | Type | Records |
|---|---|---:|
| 1A | prompt injection, visible | 47 |
| 1B | prompt injection, stealthy | 14 |
| 2A | MITM, visible | 20 |
| 2B | MITM, stealthy | 3 |
| warm-up | benign (ai-agent) | 25 |

**Unique entities before vs after injection:**

| Entity | Original | Expanded | New |
|---|---:|---:|---:|
| Users | 26 | 28 | +2 |
| Services (`eventSource`) | 79 | 80 | +1 |
| CS-GAD action categories | 13 | 13 | **+0** |
| Active calendar days | 431 | 439 | +8 |

**Introduced by the synthetic data:**
- **New users (2):** `ai-agent` (AssumedRole) and `cert-admin` (IAMUser). `Level6` is a pre-existing user.
- **New service (1):** `bedrock` only.
- **New CS-GAD action categories / graph nodes: none.**
- **New raw API action names (6):** `ChangeResourceRecordSets`, `DescribeListeners`, `GetParameter`, `ImportCertificate`, `InvokeModel`, `ModifyListener` — **all map to pre-existing categories**, so they do not create new graph nodes.

> The dataset has only **26 users** originally (28 after). The graph CS-GAD
> operates on is small, which makes per-snapshot statistics sensitive.

---

## 2. Temporal activity analysis

**2023 window — events per day by class** (the only period where attacks occur):

| Day | orig_attack | orig_benign | synth_benign | synth_malicious |
|---|---:|---:|---:|---:|
| 03-14 | 1000 | 0 | 0 | 0 |
| 03-21 | 1000 | 19 | 0 | 0 |
| 03-24 | 0 | 0 | 6 | 0 |
| 03-25 | 0 | 0 | 6 | 0 |
| 03-26 | 0 | 0 | 6 | 0 |
| 03-27 | 0 | 0 | 7 | 0 |
| **03-28** | 0 | 0 | 0 | **47 (1A)** |
| **04-04** | 0 | 0 | 0 | **14 (1B)** |
| **04-11** | 0 | 0 | 0 | **20 (2A)** |
| **04-14** | 0 | 0 | 0 | **3 (2B)** |
| 04-18 | 0 | 3 | 0 | 0 |
| 04-20 | 1531 | 0 | 0 | 0 |
| 04-23 | 3563 | 0 | 0 | 0 |

**Within-attack temporal spread** (intended visible-vs-stealthy difference):

| Scenario | Events | Span | Pattern |
|---|---:|---|---|
| 1A visible | 47 | 4.0 min | tight burst |
| 1B stealthy | 14 | 480 min (8 h) | spread across the day |
| 2A visible | 20 | 6.0 min | tight burst |
| 2B stealthy | 3 | 15.1 min | spread (but only 3 events) |

→ The **visible/stealthy temporal distinction is present as intended**: visible
variants are minutes-long bursts; stealthy variants are spread out.

### Critical temporal findings

**(a) Synthetic attacks were injected on days with *no* original activity.**
All 8 synthetic days contain **zero** original events. The attacks therefore do
**not** blend into concurrent legitimate traffic — each attack day contains only
that attack (and, for the agent, its own warm-up).

**(b) The 2023 period is itself temporally isolated.** The largest gap between
active days is **1,792 days (~4.9 years)**, between 2018-04-17 and 2023-03-14.
The original benign population is almost entirely 2017–2018; the 2023 window
contains only 5 original active days (all attack traffic) plus our 8 synthetic
days.

**Why this matters (methodological limitation):** the earlier "no volume spike"
check is *weaker than it sounds* — there is no baseline legitimate activity on
the synthetic days to spike above. Injecting on empty days means the synthetic
attacks are temporally isolated rather than hidden inside normal traffic. This
is a genuine limitation of the dataset construction (and partly inherited from
the original data, whose 2023 portion is itself attack-only and sparse).
**Whether this isolation changes CS-GAD's scores is not claimed here** — CS-GAD
scores on a *cumulative* graph that still contains the full user population, so
the effect is a model-level question, not demonstrated by these counts.

---

## 3. User activity analysis

| User | Total | Benign | Malicious | Benign years | Dormancy before attack | Baseline? |
|---|---:|---:|---:|---|---:|---|
| `ai-agent` | 86 | 25 | 61 | 2023 only | 1 day | thin (25 events, 4 days) |
| `cert-admin` | 20 | 0 | 20 | — | — | **none** |
| `Level6` | 16,247 | 16,244 | 3 | 2017–2018 only | **1,823 days (~5 y)** | large but stale |

Context — the busiest *original* benign users (`backup` 37,463; `AWSService`
15,029; `Level6` 16,247) are all 2017–2018. There is no substantial benign user
active in 2023.

**ai-agent:** has a warm-up baseline (25 benign events over 03-24…27) using
`bedrock`, `secretsmanager`, `ssm`. The baseline is **small** and exists only in
2023 (the agent never appears in 2017–2018, consistent with a genuinely new
entity). It is enough to make `bedrock`/`secretsmanager` "previously seen" for
the agent, but it is a thin baseline.

**cert-admin:** **no benign activity at all** — all 20 records are the 2A attack,
on a single day. There is no normal behavior to contrast the attack against. This
is a fairness weakness for the 2A scenario (independent of the fact that the
model missed 2A).

**Level6 — read→write change is real, but the "insider" framing is weak.**
Using action names (the `readOnly` flag is absent in 2017–2018 — see §4), the
change from historical reads to attack writes is clear:

| Service | Historical (benign) | Attack (2B) |
|---|---|---|
| acm | `ListCertificates` ×31 (ListResources) | `ImportCertificate` ×1 (CreateObject) |
| elasticloadbalancing | `DescribeLoadBalancers`/`DescribeTargetGroups` ×314 (GetInfo) | `ModifyListener` ×1 (ModifyExistingResource) + 1 Describe |
| route53 | `ListHostedZones` ×66 (ListResources) | — (not touched in the attack) |

So the read→write distinction holds. **However**, Level6's last benign activity
was in 2018 and the attack is in 2023 — a **~5-year dormancy**. In the cumulative
graph it retains history, but it is effectively a dormant account reactivating
solely to attack, which weakens the "established, trusted insider" description
and is itself an unusual pattern.

---

## 4. Action and service distribution

**CS-GAD action-category share (% within each class):**

| Category | orig_attack | orig_benign | synth_benign | synth_malicious |
|---|---:|---:|---:|---:|
| GetInfo | 57.5 | 59.5 | 36.0 | 65.5 |
| ListResources | 10.7 | 13.2 | 0.0 | 11.9 |
| CreateObject | 15.4 | 5.4 | 0.0 | 3.6 |
| ModifyExistingResource | 0.5 | 0.1 | 0.0 | 9.5 |
| EnableObjects | 0.0 | 0.0 | 64.0 | 9.5 |
| Delete | 15.1 | 0.1 | 0.0 | 0.0 |
| Login | 0.0 | 21.6 | 0.0 | 0.0 |

Observations: `synthetic_malicious` is GetInfo-dominated like `original_attack`
(65.5% vs 57.5%) and has a similar ListResources share. It **differs** in having
more `ModifyExistingResource` (9.5% vs 0.5%) and `EnableObjects` (9.5% vs 0, =
Bedrock), and **no `Delete`** (vs 15.1% in original attacks). `synthetic_benign`
is dominated by `EnableObjects` (64% = Bedrock `InvokeModel` warm-up). These are
distributional differences; whether they affect anomaly scores is a model-level
question not addressed here.

**Read vs write and errors by class** (see data-quality note below):

| Class | read | write | readOnly present | error rate |
|---|---:|---:|---:|---:|
| original_benign | 2,536 | 110 | **2.6%** | 14.4% |
| original_attack | 4,839 | 2,255 | 100% | 4.4% |
| synthetic_benign | 9 | 16 | 100% | 0.0% |
| synthetic_malicious | 60 | 24 | 100% | 7.1% |

**Data-quality limitation:** the `readOnly` flag is present in only **2.6%** of
original-benign records (the 2017–2018 `eventVersion 1.04` records omit it), so
read/write cannot be compared across eras via that flag — it must be inferred
from the action category (as done for Level6 in §3). The synthetic error rate
(7.1%) is higher than original attacks (4.4%) but well within the dataset's range
(original benign 14.4%).

**Service exclusivity.** `bedrock` is used by exactly one user (`ai-agent`), but
**single-user services are common in this dataset — 34 services are used by only
one user** (e.g. `athena`, `glue`, `route53resolver` by `test`; `codecommit`,
`codedeploy` by `Level6`). So a service tied to one user is *not* structurally
unusual here; what makes `bedrock` distinct is that it is also **temporally new**
(absent before 2023) and **never appears in benign original traffic**.

**Bedrock — specific assessment (the supervisor's concern):**
- 24 records, all `ai-agent`; 16 benign (warm-up) + 8 malicious.
- `InvokeModel` → category `EnableObjects`, which **already exists** in the
  original data → **no new action node**.
- `bedrock` is **not** in the original data → it **is** a new *service* node.
- **New raw action vs new graph node:** the 6 new raw `eventName`s (incl.
  `InvokeModel`) create **no** new category/graph node; the only novel node is
  `service:bedrock`.
- **Could this make the agent attacks easier to detect?** This is a
  **hypothesis, not a demonstrated fact.** The novelty is confined to one service
  node; the agent is also connected through 5 shared services; single-user
  services are common here; and there is benign Bedrock traffic. These reduce the
  concern but do **not** rule it out, because `bedrock` is still agent-exclusive
  *and* temporally new. **Confirming or excluding it requires a Bedrock ablation
  (not run in this analysis).**

---

## 5. Statistical comparison and potential artifacts

For each item: **observed → why it matters → concern vs limitation → needs a
model experiment?**

1. **Empty-day injection / temporal isolation.** *Observed:* all 8 synthetic
   days have 0 original events; 1,792-day gap 2018→2023. *Why:* CS-GAD is
   temporal; attacks are not hidden inside concurrent legitimate traffic, and the
   volume-spike check has no baseline to compare against. *Concern vs limitation:*
   **genuine methodological limitation.** *Experiment needed:* a stronger design
   would inject concurrent with legitimate traffic; the effect on CS-GAD's scores
   specifically is unverified.

2. **Level6 ~5-year dormancy.** *Observed:* 1,823 days between last benign and
   the attack. *Why:* undermines the "trusted insider with current history"
   framing; reactivation after years is itself unusual. *Concern vs limitation:*
   **genuine concern for interpretation.** *Experiment:* whether it affects the
   score needs model-level analysis (CS-GAD embeddings ignore absolute time, but
   this is unverified for this case).

3. **cert-admin has no benign baseline.** *Observed:* 0/20 benign. *Why:* the 2A
   scenario cannot distinguish attack behavior from "new user does anything."
   *Concern vs limitation:* **genuine limitation** (fairness of 2A). *Experiment:*
   add benign cert-admin activity (future data change, out of scope here).

4. **Bedrock novelty (service node).** *Observed:* only new service, agent-only,
   temporally new; but no new category/node, has benign traffic, and single-user
   services are common (34). *Why:* a unique service node could shape the agent's
   embedding. *Concern vs limitation:* **open concern, partially mitigated.**
   *Experiment:* **requires the Bedrock ablation** to decide whether detection is
   behavior- or novelty-driven.

5. **Thin agent baseline.** *Observed:* 25 benign events, 4 days, 2023-only.
   *Why:* limited "normal" to compare against. *Concern:* limitation, not fatal;
   it does establish the agent's routine services.

6. **`readOnly` unusable historically.** *Observed:* present in 2.6% of original
   benign. *Why:* read/write comparisons across eras must use category.
   *Concern:* data-quality limitation; handled by using categories.

7. **Category-distribution differences.** *Observed:* synthetic malicious has
   more Modify/Enable, no Delete, less CreateObject than original attacks. *Why:*
   distribution shift could influence embeddings. *Concern:* observation; effect
   on scores is model-level and not demonstrated.

8. **Very low synthetic volumes.** *Observed:* 3–47 events/day; 2B only 3 events.
   *Why:* sparse per-day signal; but CS-GAD is cumulative, so impact is limited.
   *Concern:* limitation to note.

### What is reassuring (balanced view)
- **No new action category or graph node** — only one new service node.
- Synthetic malicious **error rate (7.1%)** sits within the dataset's range.
- Synthetic malicious **action profile is GetInfo-dominated**, like original attacks.
- The **Level6 read→write change is real** (via action names).
- The **visible/stealthy temporal difference is as designed**.

### Bottom line
The synthetic records are schema-consistent and, in action profile and error
rate, broadly comparable to the original attack traffic. The **main descriptive
weaknesses are temporal**: attacks sit on otherwise-empty days in a 2023 window
that is isolated by ~5 years from the benign population, `cert-admin` has no
baseline, and `Level6` is a long-dormant account. The **Bedrock service node**
is the one structural novelty that could, in principle, aid detection of the
agent attacks — but that is a hypothesis that only a model-level ablation can
settle, and it is explicitly **not** claimed here.
