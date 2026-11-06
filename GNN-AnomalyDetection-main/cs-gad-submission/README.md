# CS-GAD Dataset Extension — Synthetic Attack Injection and Evaluation

This package extends the CS-GAD cloud anomaly-detection dataset (Marbel et al.,
2023, *"Cloudy with a Chance of Anomalies"*) with four new synthetic attack
scenarios, consolidates everything into one labeled dataset, and runs the
reconstructed CS-GAD model on the expanded data.

> **Status:** preliminary. The data pipeline, labeling, statistical validation,
> and a **single** model run are complete and verified. The model results are an
> early signal, not a final evaluation — see **Limitations**.

---

## 1. Project overview

The original paper evaluated CS-GAD on AWS CloudTrail logs containing five
classic cloud attacks. This extension adds **newer, forward-looking attack
types** that did not exist when the paper was written, so the project *extends*
the dataset rather than only reproducing it, and then asks whether the original
detection method also catches the next generation of attacks.

## 2. Synthetic attacks

Two attack types, each in a **visible** (noisy, easy) and a **stealthy** (quiet)
variant — four scenarios in total:

| ID | Attack type | Variant | Injected day (2023) | Identity | Records |
|----|-------------|---------|---------------------|----------|---------|
| 1A | Agentic AI prompt injection | visible  | 03-28 | `ai-agent` (new AssumedRole) | 47 |
| 1B | Agentic AI prompt injection | stealthy | 04-04 | `ai-agent` (same) | 14 |
| 2A | MITM via rogue certificate  | visible  | 04-11 | `cert-admin` (new IAMUser) | 20 |
| 2B | MITM via rogue certificate  | stealthy | 04-14 | `Level6` (existing insider) | 3 |

Each step maps to a documented technique (MITRE ATT&CK / ATLAS). The `ai-agent`
also has **25 benign "warm-up" records** (2023-03-24…27) so it has a normal
behavioral baseline before the attacks.

## 3. Dataset

| | Records |
|---|---|
| Original dataset | 107,116 |
| Synthetic records added | 109 (84 attack + 25 benign warm-up) |
| **Expanded total** | **107,225** |
| Attack-labeled (`label=1`) | 7,178 (7,094 original + 84 synthetic) |
| Benign (`label=0`) | 100,047 |

- **Chronological order is preserved**: `data/attack_expanded_labeled.json` is
  sorted ascending by `eventTime` (2017-02-12 → 2023-04-23). The model also
  re-sorts by timestamp on load. No step shuffles events in time.
- Labeling exists in two consistent forms: **per-record** (`label` field in the
  JSON and `record_labels.csv`) and **per-(user, snapshot)** inside the model
  (`cs_gad.py: ATTACK_WINDOWS` → `label_for`).

## 4. Methodology — generation, seeds, reproducibility

Synthetic records are **copied from the real schema**, changing only what
defines the attack (identity, action, service, day, source IP), and merged into
the dataset on days that had no prior activity. Records are written in the exact
CloudTrail 2023 schema (`eventVersion 1.08`, management events, `us-east-1`).

Two **independent** seeds are used (they do different things):

- **Generator seed** `SEED = 20230328` (`generate_synthetic_attacks.py`):
  makes the generated records reproducible — the random `eventID`/`requestID`
  UUIDs, synthetic key-ID suffixes, and the within-attack time jitter. It affects
  only cosmetic/unique fields, **not** attack behavior.
- **Model seed** `seed = 1` (`cs_gad.py: run_snapshot`): makes the node2vec
  embedding reproducible — random walks, weight init, negative sampling. **This
  is the seed that affects the detection scores.** All reported model numbers are
  from this single seed.

Neither seed shuffles the data in time. (The model calls `shuffle` only on the
list of graph *nodes* for walk-start order, not on the time-ordered events.)

## 5. Implementation — reused / reconstructed / modified

- **Reconstructed (pre-existing work):** `cs_gad.py` is a from-scratch
  re-implementation of CS-GAD because the original repository depends on
  `stellargraph`, which is unmaintained and does not install on modern Python.
  node2vec (biased walks + skip-gram with negative sampling) is implemented in
  pure NumPy. The event→category rules (14 categories) are recovered from the
  original notebook.
- **Reused from the original:** the 14-category event taxonomy, the tripartite
  (user–action–service) cumulative-graph construction, and the anomaly score
  (`1 − max cosine similarity` to peers sharing the user's last service).
- **Modified in this work:** the only change to `cs_gad.py` for Part 2 is the
  addition of **4 rows to `ATTACK_WINDOWS`** (the synthetic attacks) and their
  names in `ATTACK_TYPES`, so the evaluation covers them. The algorithm, scoring,
  and hyperparameters are unchanged.

## 6. Validation (what was checked, and findings)

**Part-1 schema/realism checks** (`results/validation_report.txt`):
- Schema — every injected record matches the real field structure. **PASS**
- Categorizer — 100% of injected events map to the 14 categories. **PASS**
  (Notably `InvokeModel → EnableObjects`, so Bedrock introduces **no new action
  node**.)
- Realism — injected volume, error rate, and timing fall within the original
  2023 ranges. **PASS**
- Triviality — the stealthy variants (1B, 2B) are not caught by naive rules
  ("new IP / new service / new identity"); the visible ones are. **PASS**

**Part-2 statistical checks:**
- **Daily volume** (`results/daily_counts.csv`): injected days hold 3–47 events
  vs 1,000–3,563 on original active days — **no volume spike**; detection cannot
  come from day-level volume.
- **Bedrock**: `InvokeModel` is the shared `EnableObjects` action (no new action
  node); there is benign Bedrock traffic (16 benign vs 8 attack); the agent
  connects through 5 shared services. `bedrock` is the **only** service node that
  is new relative to the original data.

## 7. Evaluation (how it was run, metrics, results)

- One full run of `cs_gad.py` on the expanded dataset — **42 daily + 25 hourly =
  67 snapshots**, 1,607 `(user, snapshot)` samples, **seed = 1, no shuffle**.
- **Metrics computed:** ROC-AUC (pooled over all samples); precision / recall /
  F1 / FPR at per-snapshot thresholds `mean+1·std` and `mean+2·std`.
  **PR-AUC was not computed.**

**Overall (all attacks, originals + synthetic):**
- ROC-AUC = **0.697** (original paper reported ≈0.72).
- At `mean+1·std`: precision 0.201, recall 0.349, F1 0.255, FPR 0.101.
- **Caveat:** 91 of the 109 attack samples are `lateral_movement` (the hourly
  snapshots oversample that window). The overall AUC therefore reflects mostly
  the **original** attacks, not our four new ones.

**Per-scenario — our four synthetic attacks** (`results/results_report.txt`,
`results/detection_scores.png`); score = anomaly score at the snapshot where the
attack first becomes visible, rank among all users at that snapshot:

| Scenario | Score | Rank | Flagged (>1σ / >2σ) | Result |
|----------|-------|------|---------------------|--------|
| 1A prompt injection, visible  | 0.306 | 3/23 | yes / yes | **detected** |
| 1B prompt injection, stealthy | 0.689 | 1/23 | yes / yes | **detected** (strongest) |
| 2A MITM, visible              | 0.059 | 6/24 | no / no   | **missed** |
| 2B MITM, stealthy             | 0.170 | 4/24 | no / no   | **missed** |

Both prompt-injection variants are detected; both MITM variants are missed
(2B is elevated — rank 4/24 — but below threshold). Each scenario is a **single
sample at a single snapshot under one seed**.

## 8. Limitations (known methodological concerns)

1. **Bedrock novelty vs behavior (unresolved).** `bedrock` is used only by the
   `ai-agent` — the same identity behind both *detected* attacks (1A, 1B). Their
   high scores may be driven partly by Bedrock's novelty rather than by attack
   behavior. The warm-up reduces but does not remove this, because no other user
   uses Bedrock. An **ablation** is needed to separate the two; it has not been
   run.
2. **Single seed.** All model numbers come from `seed=1`. node2vec is stochastic,
   so scores would vary on re-run; robustness across seeds is unverified.
3. **Pooled AUC is dominated by one attack.** 0.697 is driven by
   `lateral_movement` (83% of positives) and does not measure the synthetic
   attacks. There is no separate AUC for originals vs synthetic.
4. **Class imbalance / missing PR-AUC.** Positives are 6.8% of samples; ROC-AUC
   is optimistic under imbalance and PR-AUC was not computed.
5. **`cert-admin` has no benign baseline** — all 20 of its records are the attack
   (unlike `ai-agent`, which has warm-up).
6. **No baseline comparison.** The Modell/spectral baseline was not run on the
   expanded data.
7. **Small graph.** ~20–28 distinct users per snapshot, so statistics are
   sensitive.
8. **Synthetic, self-labeled data**, and the generator is not the (unpublished)
   original attack generator — same limitation as the paper's own simulated
   attacks.
9. **Bedrock timing.** Bedrock was in preview in April 2023, a minor historical
   anachronism in the agent scenario.

## 9. Reproduction

**Environment:** Python 3.10–3.12; `pip install -r requirements.txt`.

**External dependency:** the original `attack.json` (~115 MB, Git LFS from the
original repository) is required **only** to regenerate the synthetic data from
scratch (step 1) and to re-run the Part-1 `validate.py` (step 4). The **model
results (steps 5–6) reproduce from the included
`data/attack_expanded_labeled.json` alone**, with no external file.

Run from the package root (outputs land in the working directory):

```bash
# 1. Generate + inject synthetic attacks         (needs original attack.json)
python code/generate_synthetic_attacks.py --input attack.json --outdir .
#    -> attack_expanded.json, synthetic_only.json, synthetic_labels.csv

# 2. Consolidate + label (0/1), keep original + add synthetic
python code/make_labeled.py --data attack_expanded.json
#    -> attack_expanded_labeled.json, record_labels.csv

# 3. Daily volume statistics
python code/daily_stats.py --data attack_expanded_labeled.json
#    -> daily_counts.csv

# 4. (optional) Part-1 validation  (needs attack.json, attack_expanded.json,
#    synthetic_only.json, synthetic_labels.csv in the current directory)
python code/validate.py            # prints the validation report

# 5. Run CS-GAD  (~50 min, CPU; seed=1; resumable — rerun to continue)
python code/cs_gad.py --data data/attack_expanded_labeled.json --out full_results.csv
#    -> full_results.csv, full_results_labeled.csv  (+ prints overall ROC-AUC/metrics)
#    quick sanity check (3 snapshots): add --quick

# 6. Per-scenario detection analysis
python code/analyze_results.py --results full_results.csv
```

The files already in `results/` are the outputs of steps 3–6 as run for this
submission, so the package can be reviewed without re-running anything.

## 10. Folder structure

```
cs-gad-submission/
├── README.md                 this file
├── SUPERVISOR_SUMMARY.md      short meeting summary
├── requirements.txt          Python dependencies
├── code/
│   ├── generate_synthetic_attacks.py  synthetic attack generator (seed 20230328)
│   ├── make_labeled.py                consolidation + 0/1 labeling
│   ├── daily_stats.py                 daily volume statistics
│   ├── validate.py                    Part-1 schema/realism/triviality checks
│   ├── cs_gad.py                      CS-GAD reconstruction (+ synthetic ATTACK_WINDOWS)
│   └── analyze_results.py             per-scenario detection analysis
├── data/
│   ├── attack_expanded_labeled.json   FINAL consolidated + labeled dataset (107,225 recs)
│   ├── synthetic_only.json            the 109 injected records
│   ├── synthetic_labels.csv           scenario-level ground truth (8 rows)
│   └── record_labels.csv              per-record 0/1 labels (107,225 rows)
└── results/
    ├── validation_report.txt          Part-1 validation output
    ├── daily_counts.csv               daily volume stats
    ├── full_results.csv               model anomaly scores (67 snapshots, seed 1)
    ├── full_results_labeled.csv       scores + per-(user,snapshot) labels
    ├── results_report.txt             overall + per-scenario detection summary
    └── detection_scores.png           chart: anomaly score per attack
```
