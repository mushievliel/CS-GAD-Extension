# Statistical Analysis — Plain-English Summary

A short, non-technical summary of the descriptive statistics we ran on the
expanded dataset **before** interpreting the model's detection results. Full
detail and tables are in `statistical_analysis_report.md`.

## What we checked

We compared the 109 injected records against the original 107,116, separating
four groups: original-benign, original-attack, synthetic-benign (the agent's
"warm-up"), and synthetic-malicious. We looked at: label counts, how many new
users/services/actions were introduced, daily activity over time, each key
user's behavior, and the distribution of services, actions, reads/writes, and
errors.

## What the numbers show

- **The dataset is dominated by old, benign traffic.** 93% is benign, almost all
  from 2017–2018. Attacks (original + ours) are ~6.7%. Our additions are only
  **0.1%** of the data (84 malicious + 25 benign warm-up).
- **We added very little that is structurally new:** 2 new users (`ai-agent`,
  `cert-admin`), **1 new service (`bedrock`)**, and **no new action categories**.
  The model represents actions by category, so our new API calls (e.g.
  `InvokeModel`, `ImportCertificate`) do **not** create new graph nodes — only
  `bedrock` does, as a service.
- **The visible vs stealthy design is visible in the data:** visible attacks are
  minute-long bursts; stealthy ones are spread over hours.
- **Our attacks look reasonable in "shape":** their action mix is dominated by
  information-gathering, like the original attacks, and their error rate (7%) is
  normal for this dataset.

## Are the synthetic attacks reasonably consistent with the original data?

**In content — yes.** Same record format, similar action profiles, similar error
rates, and almost nothing structurally new.

**In timing — this is where the honest weaknesses are:**
- **Our attacks sit on days with *no other activity*.** So they are not "hidden
  inside" normal traffic — each attack day contains only that attack. This also
  means the "no volume spike" result is weaker than it sounds: there is simply no
  normal activity on those days to stand out against.
- **The 2023 period is cut off from the normal data by ~5 years.** The benign
  users are from 2017–2018; the attacks are in 2023.
- **`Level6` (our "insider") was dormant for ~5 years** before the attack. It has
  history in the graph, but it is really a reactivated old account — so "trusted,
  currently-active insider" overstates it. The read→write change we rely on is
  real, though.
- **`cert-admin` has no normal activity at all** — it only ever appears to carry
  out its attack.

## What concerns remain

1. **Bedrock** is the one genuinely new service and only the agent uses it. This
   *might* help the model flag the agent's attacks for the wrong reason (novelty,
   not behavior). We reduced this risk (benign Bedrock traffic exists; many
   services in this dataset are used by a single user anyway), but we **cannot
   rule it out from statistics alone** — it needs a model ablation.
2. **Empty-day injection and the 5-year gap** make the temporal realism limited.
3. **`cert-admin` has no baseline**, and the **agent's baseline is small** (25
   events).
4. The `readOnly` flag is missing from the 2017–2018 records, so read-vs-write
   comparisons had to use the action names instead.

## What we can confidently tell the supervisor

- The consolidation, labeling, and chronological order are correct and verified.
- The synthetic records are schema-consistent and, in content, comparable to the
  real attack traffic — they are **not** obviously artificial in format or action
  mix.
- We have **not** found proof that an artifact makes the attacks trivially
  detectable — but we have identified **real temporal limitations** and **one
  open question (Bedrock)** that an ablation must answer before we claim the
  agent's detection is behavioral.
- Net: the data is good enough to interpret the model results **with these
  caveats stated**, and the two things most worth fixing/clarifying are the
  **Bedrock ablation** and the **temporal-realism limitations** (empty days,
  dormant insider, missing baselines).
