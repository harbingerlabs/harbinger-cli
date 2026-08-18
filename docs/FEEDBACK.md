# Measurement instrument — pre-registered

**Freeze this before the first pilot run. Same discipline as everything else:
the bar is set in advance, in writing, and it does not move once data arrives.**

Two instruments, deliberately separate because they answer different questions
and one can pass while the other fails:

- **Instrument A — the decision question.** Would they make the fix? This is
  the product question.
- **Instrument B — the rank-correlation study.** Does our ordering match an
  expert's? This is the model question.

---

## Pre-registration

**Registered on:** _[DATE — fill before first run]_
**Registered by:** _[NAME]_
**Target N:** 6 design partners, ≥1 real directory each.
**Analysis is frozen below. No metric, threshold, or exclusion may be changed
after the first response is collected.** If something needs to change, it is a
new pre-registration with a new N, and the old one is reported as it stands.

### Primary endpoint

**Of the top-3 ranked routes shown to a partner, at least one is one they say
they would fix, in at least 4 of 6 partners.**

- **Pass:** ≥4/6.
- **Ambiguous:** 3/6 → not a pass; run a second cohort before concluding.
- **Fail:** ≤2/6.

### Secondary endpoints

1. **Top-1 usefulness.** The single highest-ranked route is one they would fix:
   ≥3/6.
2. **Novelty.** ≥1 route per partner they did not already know about: ≥4/6.
   A tool that only confirms what they know is a report, not a product.
3. **Rank correlation (Instrument B).** Median Spearman ρ ≥ **0.5** between our
   ranking and their engineer's blind ranking, across partners who complete it.
4. **Time to first report.** Median ≤ **15 minutes** from download to a report
   on screen, self-timed.
5. **Collection friction.** ≥4/6 complete collection without contacting us for
   help.

### Declared kill criterion

**If the primary endpoint fails AND novelty is ≤2/6, the ranked-paths thesis is
not supported for this audience.** That is a real outcome, recorded as such, not
a prompt to re-cut the data.

### Exclusions, declared in advance

- A partner who never completes a run on a real directory is excluded from all
  endpoints and reported separately as a funnel loss, with the reason.
- A partner whose export contains no path to any Tier Zero objective is excluded
  from endpoints 1–3 and reported under collection friction instead. This must
  be checked against the report's declared collection gaps: a gap is not an
  absence of risk.
- No other exclusions.

---

## Instrument A — after the first run (≤ 60 seconds)

Send immediately after their first report. Do not batch it; recall decays fast
and a same-day response is worth three a week later.

> **1. Look at the top 3 routes in the report. For each: would you make the
> fix?**
> Route 1 — Yes / No / Already done / Can't (constraint)
> Route 2 — Yes / No / Already done / Can't (constraint)
> Route 3 — Yes / No / Already done / Can't (constraint)
>
> **2. Did any of the three surprise you?**
> Yes, [which] / No, we knew about all of them
>
> **3. If you answered "Can't" to any: what is the constraint?**
> _[free text]_
>
> **4. How long from downloading it to seeing this report?**
> < 5 min / 5–15 min / 15–60 min / > 1 hour / didn't finish
>
> **5. Anything that nearly stopped you?**
> _[free text]_

Question 1 is the endpoint. Questions 2–5 tell you why it failed if it fails.

**"Already done"** counts as a **No** for the primary endpoint but is recorded
separately — it means we ranked a stale finding, which is a data-freshness
problem, not a ranking problem.

---

## Instrument B — the blind ranking study

**The engineer must rank before seeing our ranking. Once they have seen ours,
their independent judgment is gone and cannot be recovered.**

### Protocol

1. **We generate** the report but do not send it.
2. **We send only the path list**, stripped of every score, in **randomized
   order**, labelled A–J. No risk numbers, no "blind spot" flags, no ordering
   signal of any kind. Ten routes.
3. **Their engineer ranks** them 1–10: "if you could only fix these one at a
   time, in what order would you do it, and why for your top 3?"
4. **They send their ranking back.** Only then do we send the full report.
5. **We compute** Spearman's ρ between the two rankings.
6. **We ask one follow-up:** "Having now seen our ranking — where we disagree
   most, who do you think is right, and why?" The disagreements are the most
   valuable data in the whole pilot. That is where the model is either wrong or
   ahead of them, and their reasoning tells you which.

### Generating a blind list

```sh
harbinger analyze <export> --json --top 10 > full.json
```

Extract path descriptions only — drop `risk`, `evasion`, `blindSpot`, and
`rank` — and shuffle. **Shuffle with a recorded seed** so the randomization is
reproducible and auditable after the fact.

### Interpretation, fixed in advance

| Median ρ | Reading |
|---|---|
| ≥ 0.7 | Strong agreement. Our ranking encodes what an expert already knows — the value is speed and coverage, and we should sell it that way. |
| 0.5 – 0.7 | Useful agreement with real divergence. Examine every disagreement individually; this is the most informative band. |
| 0.2 – 0.5 | Weak. Either the model is wrong or it is seeing something they are not. The follow-up question decides which — do not assume the flattering answer. |
| < 0.2 | No relationship. The ranking is not defensible as expert-equivalent and must not be sold as such. |

**A low ρ is not automatically a failure of the model.** Detection-evasion
weighting is exactly the axis a human ranker under-weights, because they rank by
severity and reachability, not by how quiet a route is. But that argument must
be made from the *reasoning* in their follow-up, not asserted to rescue a bad
number. Write down before you look at the data which specific disagreement
pattern would count as "we are ahead of them" — anything else is post-hoc.

---

## Recording

One row per partner in `pilot/results.csv`, appended as responses arrive, never
edited:

```
partner_id,run_date,directory_size,collection_method,minutes_to_report,
top3_would_fix,top1_would_fix,novel_finding,already_done_count,
spearman_rho,rho_n,needed_help,excluded,exclusion_reason,notes
```

`partner_id` is a pseudonym. No client names, no directory contents, no export
data — not in the CSV, not in notes, not anywhere. The measurement of the
product must not itself become a data-handling problem, and everything in
[DATA_HANDLING.md](DATA_HANDLING.md) applies to us too.

## Reporting

Report all six partners including exclusions and funnel losses. Report the
primary endpoint first, before any secondary that happens to look better. If the
primary fails, say so in the first sentence.
