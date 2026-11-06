# CS-GAD Extension — Meeting Summary

A short status for our meeting. Full detail and reproduction steps are in
`README.md`.

## 1. What has been completed since last time

- **Consolidated the whole dataset into one labeled file** — original records +
  the four synthetic attacks, every record labeled `1` (attack) or `0` (benign),
  original labels kept and new ones added on top, in chronological order.
- **Ran the daily-volume statistics** you asked for — confirmed no spikes.
- **Handled the Bedrock concern** — checked how it appears to the model and that
  it has benign traffic.
- **Ran the CS-GAD model** on the expanded dataset (one run, no shuffle) and
  analyzed detection per attack.
- **Documented everything** in this package.

## 2. Deliverables now available

- `data/attack_expanded_labeled.json` — the final labeled dataset (107,225 records).
- `code/` — generator, labeling, statistics, validation, the CS-GAD model, and
  the analysis script.
- `results/` — validation report, daily statistics, model scores, a per-scenario
  results summary, and a results chart.
- `README.md` — full methodology, limitations, and reproduction instructions.

## 3. Preliminary results

**Important distinction — two different numbers:**

- **Overall ROC-AUC = 0.697** (the paper reported ≈0.72). *But* this number is
  dominated by the original `lateral_movement` attack (83% of the attack
  samples), so it mainly tells us the reconstruction behaves like the original —
  it does **not** measure our four new attacks.
- **Our four new attacks, individually:**

  | Attack | Detected? |
  |--------|-----------|
  | Prompt injection — visible (1A)  | **Yes** |
  | Prompt injection — stealthy (1B) | **Yes** (strongest signal of all) |
  | MITM — visible (2A)              | **No** |
  | MITM — stealthy (2B)             | **No** (elevated, but under threshold) |

  So detection split **by attack type, not by visible/stealthy**: the AI-agent
  prompt injection is caught (even when quiet); the certificate MITM is missed.

## 4. What we can and cannot conclude

**Can:**
- The full pipeline works end-to-end — the loop is closed.
- The expanded dataset is consistent with the original (schema, categorization,
  volume, and an AUC close to the paper's).
- Our synthetic attacks behave in the **same detection regime** as the originals
  (some caught, some missed) — i.e. they are not trivially easy or impossibly
  hard. This matches your point that a perfect score would be suspicious.

**Cannot (yet):**
- We **cannot** claim the agent's detection is driven by its *behavior* rather
  than by Bedrock being a brand-new service used only by that agent. This is the
  main open question and needs an ablation.
- We **cannot** treat the per-attack numbers as robust — they come from a single
  random seed and one sample per attack.

## 5. Checks still needed (by priority)

**Essential (before trusting the results):**
1. **Bedrock ablation** — give a benign user Bedrock traffic (or drop Bedrock)
   and re-score, to see whether the agent is detected by behavior or by novelty.
2. **Multiple seeds** — re-run with ~3 seeds to confirm the pattern is stable.

**Recommended (academic quality):**
3. Report metrics **per scenario** and separately for originals vs synthetic;
   add **PR-AUC** (the data is imbalanced).
4. Run the **baseline** (Modell) on the expanded data for comparison.
5. Add a benign baseline for `cert-admin` (currently it only appears in its
   attack).

**Optional:**
6. Hourly-resolution snapshots for the synthetic days; recover the 5th (billing)
   original attack if the original scripts are available.

## 6. Decisions / questions to discuss

- **Bedrock:** keep it (realistic for an AI-agent scenario, but introduces a new
  service node), or substitute an action that already exists in the data to
  remove the novelty confound? This directly affects how we interpret 1A/1B.
- **`cert-admin` has no benign history** — should we add warm-up activity for it,
  as we did for the agent, so the MITM-visible case is a fair test?
- **Evaluation metric:** is the pooled ROC-AUC acceptable for the report, or do
  you want a per-snapshot / per-attack metric (and PR-AUC) as the headline?
- Confirmation of the **final submission deadline**, to prioritize the remaining
  checks.
