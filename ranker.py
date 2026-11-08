"""
ranker.py  -  Dashboard step 3: techniques -> candidate threat groups

WHAT THIS FILE DOES (simple version)
  A "group profile" is the list of techniques a threat group is known to use
  (from the dataset's scenario manifest). We compare the techniques seen in
  the logs with each group's list and give every group a score:

    Jaccard          = shared techniques / all techniques in either list
    Weighted Jaccard = the same, but a rare technique (used by few groups)
                       counts more than a common one (used by many groups)

  Both formulas are copied from notebook cell 13. The score says how well a
  group FITS the evidence. It is not the chance that the group did it.

  The file also finds groups that the evidence can never tell apart
  (identical lists of detectable techniques) and groups with very few
  detectable techniques, so the dashboard can warn about them.
"""
from __future__ import annotations

import math
from collections import Counter

import numpy as np
import pandas as pd

PS_LABEL = "PS_GROUP"

# Display hints (not tuned on test data; they only decide when to show a warning)
MIN_VISIBLE = 5          # fewer detectable techniques than this -> "weak evidence"
MIN_OBSERVED = 3         # fewer observed techniques than this -> "very little evidence"
CLOSE_GAP = 0.02         # top two scores closer than this -> "close call"


def load_profiles(path, ps_group) -> dict[str, set[str]]:
    """Read group_profiles.csv (columns: group, techniques) and apply the
    PowerShell grouping, exactly like the final model."""
    df = pd.read_csv(path, dtype=str).fillna("")
    ps = set(ps_group)
    return {r["group"].strip(): {PS_LABEL if t in ps else t for t in r["techniques"].split()}
            for _, r in df.iterrows()}


def weights(profiles) -> dict[str, float]:
    """Rare techniques get a bigger weight (notebook cell 13)."""
    n = len(profiles)
    df_ = Counter(t for P in profiles.values() for t in P)
    return {t: math.log((n + 1) / (c + 1)) + 1 for t, c in df_.items()}


def groups_using(profiles) -> Counter:
    """How many groups list each technique."""
    return Counter(t for P in profiles.values() for t in P)


def separability(profiles, detectable) -> tuple[dict, dict]:
    """Which groups can the detector tell apart at all?

    Returns
      visible:   group -> techniques on its list that the model can detect
      identical: group -> other groups with exactly the same visible list
    """
    detectable = set(detectable)
    visible = {g: P & detectable for g, P in profiles.items()}
    by_set = {}
    for g, V in visible.items():
        by_set.setdefault(frozenset(V), []).append(g)
    identical = {g: [o for o in by_set[frozenset(V)] if o != g] for g, V in visible.items()}
    return visible, {g: o for g, o in identical.items() if o}


def rank_groups(observed, profiles, w=None) -> pd.DataFrame:
    """Score every group against the observed technique set.

    Sorted by weighted Jaccard (main score), plain Jaccard shown alongside.
    Ties share the same rank number (1, 1, 3, ...).
    """
    observed = set(observed)
    w = w or weights(profiles)
    used_by = groups_using(profiles)
    rows = []
    for g, P in profiles.items():
        inter, union = observed & P, observed | P
        j = len(inter) / len(union) if union else 0.0
        wj = (sum(w.get(t, 1.0) for t in inter) / sum(w.get(t, 1.0) for t in union)) if union else 0.0
        rows.append({
            "group": g,
            "weighted_jaccard": round(wj, 9),
            "jaccard": round(j, 9),
            "n_matched": len(inter),
            # rarest first: these are the most telling matches
            "matched": sorted(inter, key=lambda t: (used_by[t], t)),
            "observed_not_in_profile": sorted(observed - P),
            "profile_size": len(P),
            "profile_not_seen": len(P - observed),
        })
    df = pd.DataFrame(rows).sort_values(["weighted_jaccard", "jaccard", "group"],
                                        ascending=[False, False, True])
    df["rank"] = df["weighted_jaccard"].rank(method="min", ascending=False).astype(int)
    df["rank_plain"] = df["jaccard"].rank(method="min", ascending=False).astype(int)
    return df.reset_index(drop=True)


def group_warnings(ranked, visible, identical) -> dict[str, list[str]]:
    """Plain-language warnings for each group in a ranking."""
    out = {}
    ties = ranked.groupby("rank")["group"].apply(list).to_dict()
    for _, r in ranked.iterrows():
        g, notes = r["group"], []
        if g in identical:
            notes.append("Same detectable technique list as " + ", ".join(identical[g])
                         + ": the logs can never tell these apart.")
        if len(visible.get(g, ())) < MIN_VISIBLE:
            notes.append(f"Only {len(visible.get(g, ()))} of its techniques can be detected "
                         "in these logs: weak evidence.")
        others = [o for o in ties.get(r["rank"], []) if o != g]
        if others and r["weighted_jaccard"] > 0:
            notes.append("Same score as " + ", ".join(others) + ".")
        out[g] = notes
    return out


def overall_warnings(ranked, observed) -> list[str]:
    """Warnings about the ranking as a whole."""
    notes = []
    if len(observed) < MIN_OBSERVED:
        notes.append(f"Only {len(observed)} technique(s) observed. Most groups share at least "
                     "this many, so the ranking says very little.")
    if ranked.empty or ranked.iloc[0]["weighted_jaccard"] == 0:
        notes.append("No group shares any observed technique.")
        return notes
    top = ranked.iloc[0]
    if top["n_matched"] < 2:
        notes.append("The top group matches only one observed technique.")
    if len(ranked) > 1 and top["weighted_jaccard"] - ranked.iloc[1]["weighted_jaccard"] < CLOSE_GAP:
        notes.append("The top two groups have almost the same score: treat them as equally likely candidates.")
    return notes


def simulate_observation(group, visible, detectable, share_ran, n_unrelated, rng):
    """Semi-synthetic test (like notebook cell 17, but with perfect detection):
    keep each detectable technique of the group with probability `share_ran`,
    then add `n_unrelated` techniques the group does not use."""
    kept = {t for t in sorted(visible[group]) if rng.random() < share_ran}
    pool = sorted(set(detectable) - visible[group])
    if n_unrelated and pool:
        kept |= set(rng.choice(pool, size=min(n_unrelated, len(pool)), replace=False))
    return kept


def new_rng(seed):
    return np.random.default_rng(seed)
