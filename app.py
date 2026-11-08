"""
app.py  -  the dashboard (run with:  streamlit run app.py)

PAGES (tabs)
  1. Overview          what is in the uploaded file
  2. Techniques        the model's top-3 guesses for every attack command
  3. Why? (SHAP)       which clues made the model choose a technique
  4. Candidate groups  which threat groups fit the detected techniques, and why
  5. Simulation        the semi-synthetic test: hide part of a group's
                       techniques, add unrelated ones, see where it ranks
  6. About             what the scores mean and what they do not mean

SECURITY
  - password login (auth.py)
  - CSV (or CSV.gz) only, size limit in .streamlit/config.toml
  - the upload stays in memory for this browser session only; it is never
    written to disk and is forgotten on log out
  - runs on this computer only (localhost)
"""
from __future__ import annotations

import gzip
import io
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import sklearn
import streamlit as st

import auth
import pipeline
import ranker
from explain import Explainer

HERE = Path(__file__).resolve().parent
# Model folders the sidebar can choose from (only those that exist are shown)
MODEL_DIRS = {
    "Full model (trained on all days)": "models",
    "Held-out model (never saw 9–10 Dec 2024)": "models_holdout",
}
MAX_ROWS = 300_000                     # alert rows per upload
MAX_UNZIPPED_MB = 600                  # protection against huge .gz files
LOW_CONF = 0.0                         # best score at or below this = low confidence
GREEN, RED, GREY = "#2e7d32", "#c62828", "#9e9e9e"

st.set_page_config(page_title="APT Dashboard", page_icon="🛡️", layout="wide")


# =====================================================================
# Loading the saved model and reference files (once, then cached)
# =====================================================================
@st.cache_resource(show_spinner="Loading the model...")
def load_resources(folder="models"):
    MODELS = HERE / folder
    needed = ["final_model.joblib", "final_model_info.json", "shap_background_mean.npy",
              "group_profiles.csv", "pipeline_settings.json"]
    missing = [f for f in needed if not (MODELS / f).exists()]
    if missing:
        raise FileNotFoundError("Missing in the models folder: " + ", ".join(missing)
                                + ". Run notebook cell 19.")
    model = joblib.load(MODELS / "final_model.joblib")
    info = json.loads((MODELS / "final_model_info.json").read_text(encoding="utf-8"))
    settings = json.loads((MODELS / "pipeline_settings.json").read_text(encoding="utf-8"))
    mu = np.load(MODELS / "shap_background_mean.npy")

    rule_desc = {}
    if (MODELS / "rule_descriptions.csv").exists():
        rd = pd.read_csv(MODELS / "rule_descriptions.csv", dtype=str).fillna("")
        rule_desc = dict(zip(rd.iloc[:, 0], rd.iloc[:, 1]))

    names = {}
    if (MODELS / "technique_names.csv").exists():
        tn = pd.read_csv(MODELS / "technique_names.csv", dtype=str).fillna("")
        names = dict(zip(tn["technique"], tn["name"]))

    ps_group = settings.get("ps_group_techniques", info.get("ps_group_techniques", []))
    profiles = ranker.load_profiles(MODELS / "group_profiles.csv", ps_group)
    classes = [str(c) for c in model[-1].classes_]
    visible, identical = ranker.separability(profiles, classes)
    return {
        "folder": folder,
        "model": model, "info": info, "settings": settings, "names": names,
        "explainer": Explainer(model, mu, rule_desc), "ps_group": ps_group,
        "profiles": profiles, "weights": ranker.weights(profiles),
        "classes": classes, "visible": visible, "identical": identical,
    }


def label(t, names, ps_group):
    """Technique ID -> 'T1112 – Modify Registry'."""
    if t == ranker.PS_LABEL:
        return f"PS_GROUP – PowerShell attack, exact type unclear ({len(ps_group)} techniques)"
    return f"{t} – {names[t]}" if t in names else t


# =====================================================================
# Processing one upload
# =====================================================================
def read_upload(uploaded) -> io.BytesIO:
    data = uploaded.getvalue()
    if uploaded.name.lower().endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            data = gz.read(MAX_UNZIPPED_MB * 1024 * 1024 + 1)
        if len(data) > MAX_UNZIPPED_MB * 1024 * 1024:
            raise ValueError(f"The unzipped file is larger than {MAX_UNZIPPED_MB} MB.")
    return io.BytesIO(data)


def process(uploaded, R):
    ev, linked, ex = pipeline.prepare_upload(
        read_upload(uploaded), include_launch_in_A=R["settings"].get("include_launch_in_A", False))
    if len(ev) > MAX_ROWS:
        raise ValueError(f"The file has {len(ev):,} rows; the limit is {MAX_ROWS:,}. "
                         "Please upload a smaller part (for example one or two days).")
    X = pipeline.model_inputs(ex)
    S = np.asarray(R["model"].decision_function(X))
    classes = np.asarray(R["classes"])
    order = np.argsort(-S, axis=1)[:, :3]
    for k in range(3):
        ex[f"guess{k + 1}"] = classes[order[:, k]]
        ex[f"score{k + 1}"] = S[np.arange(len(S)), order[:, k]].round(3)
    ex["time"] = pd.to_datetime(ex["ts"].str.replace("@", " ", regex=False),
                                format="mixed", errors="coerce")
    ex["day"] = ex["time"].dt.date
    # The Linear SVM scores each technique; above 0 means "yes, this one".
    # If even the best score is 0 or below, the model is not confident about any technique.
    ex["confident"] = ex["score1"] > LOW_CONF
    return {"name": uploaded.name, "rows": len(ev), "linked": len(linked),
            "ex": ex, "X": X.reset_index(drop=True)}


def _norm_time(ts):
    """Same moment, whatever the text format: 'Dec 9, 2024 @ 06:08:55.410' or '2024-12-09 06:08:55.410'."""
    return pd.to_datetime(ts.astype(str).str.replace("@", " ", regex=False).str.strip(),
                          format="mixed", errors="coerce")


def attach_answer_key(ex, key_file):
    """Add the true technique to each attack command, if an answer key was uploaded.
    The key is used only for checking: the model never sees it.
    Several ways of matching are tried; the one that matches the most commands is used."""
    ex = ex.drop(columns=[c for c in ("true_technique", "brand_new_attack", "right", "in_top3",
                                      "match_method") if c in ex.columns])
    if key_file is None:
        return ex, None
    key = pd.read_csv(io.BytesIO(key_file.getvalue()), dtype=str).fillna("")
    if not {"agent", "ts", "true_technique"} <= set(key.columns):
        return ex, "The answer key needs the columns agent, ts and true_technique."
    extra = [c for c in ("brand_new_attack",) if c in key.columns]

    L = ex.reset_index()
    idx_name = L.columns[0]
    L["_agent"] = L["agent"].astype(str).str.strip().str.lower()
    L["_time"] = _norm_time(L["ts"])
    K = key.copy()
    K["_agent"] = K["agent"].astype(str).str.strip().str.lower()
    K["_time"] = _norm_time(K["ts"])
    has_sha = "cmd_sha1" in K.columns and "cmd_sha1" in L.columns and (K["cmd_sha1"] != "").any()

    results = []
    # 1. computer + exact time + command fingerprint
    if has_sha:
        k1 = K.drop_duplicates(["_agent", "_time", "cmd_sha1"])
        m1 = L.merge(k1[["_agent", "_time", "cmd_sha1", "true_technique"] + extra],
                     on=["_agent", "_time", "cmd_sha1"], how="left")
        results.append(("computer + time + command fingerprint", m1))
    # 2. computer + exact time
    k2 = K.drop_duplicates(["_agent", "_time"])
    m2 = L.merge(k2[["_agent", "_time", "true_technique"] + extra], on=["_agent", "_time"], how="left")
    results.append(("computer + time", m2))
    # 3. computer + fingerprint + nearest time within 5 seconds
    if has_sha:
        Ls = L.dropna(subset=["_time"]).sort_values("_time")
        Ks = K.dropna(subset=["_time"]).sort_values("_time")
        m3 = pd.merge_asof(Ls, Ks[["_agent", "_time", "cmd_sha1", "true_technique"] + extra],
                           on="_time", by=["_agent", "cmd_sha1"],
                           tolerance=pd.Timedelta(seconds=5), direction="nearest")
        m3 = m3.set_index(idx_name).reindex(L[idx_name]).reset_index()
        results.append(("computer + command fingerprint + nearest time (5 s)", m3))

    method, best = max(results, key=lambda r: r[1]["true_technique"].notna().sum())
    best = best.drop_duplicates(idx_name).set_index(idx_name).reindex(ex.index)
    out = ex.copy()
    out["true_technique"] = best["true_technique"].fillna("").astype(str)
    for c in extra:
        out[c] = best[c].fillna("")
    has = out["true_technique"] != ""
    out["right"] = has & (out["guess1"] == out["true_technique"])
    out["in_top3"] = has & ((out["guess1"] == out["true_technique"]) |
                            (out["guess2"] == out["true_technique"]) |
                            (out["guess3"] == out["true_technique"]))
    out.attrs["match_method"] = method
    out.attrs["key_rows"] = len(key)
    return out, None


def answer_key_section(ex, R):
    from sklearn.metrics import f1_score
    st.subheader("Check against the answer key")
    k = ex[ex["true_technique"] != ""]
    if k.empty:
        st.warning("No attack command in this file matched the answer key. Check that the key "
                   "belongs to this file (same computers and times).")
        return
    st.caption(f"Matched {len(k):,} of {ex.attrs.get('key_rows', len(k)):,} answer-key rows "
               f"by {ex.attrs.get('match_method', 'computer + time')}.")
    held = R["info"].get("held_out_days")
    if held:
        st.success("Model in use: held-out copy. It was trained WITHOUT " + " and ".join(held)
                   + ", so this is an honest test on days it never saw.")
    else:
        st.warning("Model in use: full model. It was trained on these days too, so these scores "
                   "are optimistic. Switch to the held-out model in the sidebar for an honest test.")
    c = st.columns(5)
    c[0].metric("Commands checked", f"{len(k):,}")
    c[1].metric("First guess right", f"{k['right'].mean():.1%}")
    c[2].metric("Right one in top 3", f"{k['in_top3'].mean():.1%}")
    c[3].metric("Macro-F1", f"{f1_score(k['true_technique'], k['guess1'], average='macro'):.3f}")
    conf = k[k["confident"]]
    c[4].metric("First guess right, confident only",
                f"{conf['right'].mean():.1%}" if len(conf) else "–")
    if "brand_new_attack" in k.columns:
        new = k[k["brand_new_attack"].astype(str).str.lower().isin(["true", "1"])]
        if len(new):
            st.caption(f"Brand-new attacks (tests that never ran on a training day): {len(new)} "
                       f"commands, first guess right {new['right'].mean():.1%}, "
                       f"top 3 {new['in_top3'].mean():.1%}.")
    wrong = (k[~k["right"]].groupby(["true_technique", "guess1"]).size()
             .sort_values(ascending=False).head(8).reset_index(name="commands"))
    if len(wrong):
        wrong.columns = ["true technique", "model's first guess", "commands"]
        st.markdown("**Most common mistakes**")
        st.dataframe(wrong, hide_index=True)
    st.caption("Macro-F1: score from 0 to 1 where every technique counts equally. The answer "
               "key comes from matching each Caldera command to its Atomic Red Team test.")


# =====================================================================
# Page parts
# =====================================================================
def page_overview(res, R):
    ex = res["ex"]
    st.subheader("What is in this file")
    c = st.columns(6)
    c[0].metric("Alert rows", f"{res['rows']:,}")
    c[1].metric("Attack commands found", f"{len(ex):,}")
    c[2].metric("…that left a trail", f"{int(ex['has_trail'].sum()):,}")
    c[3].metric("Computers", ex["agent"].nunique())
    c[4].metric("Different techniques guessed", ex.loc[ex["has_trail"], "guess1"].nunique())
    c[5].metric("Low-confidence guesses", f"{int((ex['has_trail'] & ~ex['confident']).sum()):,}")
    st.caption("An *attack command* is a program started by the Caldera agent. "
               "A *trail* means the command left at least one alert row besides its own start. "
               "The model was trained only on commands with a trail, so commands without one "
               "get less reliable guesses. A *low-confidence* guess means even the model's best "
               "score was 0 or below: it was not sure about any technique.")

    counts = (ex[ex["has_trail"]]["guess1"].value_counts()
              .rename_axis("technique").reset_index(name="commands"))
    if len(counts):
        counts["label"] = [label(t, R["names"], R["ps_group"]) for t in counts["technique"]]
        counts = counts.iloc[::-1]
        fig = go.Figure(go.Bar(x=counts["commands"], y=counts["label"], orientation="h",
                               marker_color="#1565c0",
                               hovertemplate="%{y}<br>%{x} commands<extra></extra>"))
        fig.update_layout(title="Model's first guess, commands with a trail",
                          height=max(300, 22 * len(counts) + 80),
                          margin=dict(l=10, r=10, t=40, b=10), xaxis_title="attack commands")
        st.plotly_chart(fig)
    if "true_technique" in ex.columns:
        answer_key_section(ex, R)


def page_techniques(res, R):
    ex = res["ex"]
    st.subheader("The model's top-3 guesses for each attack command")
    st.caption("Score = the Linear SVM's score for that technique. Higher is more confident, "
               "but it is not a probability. On attacks seen before, the right technique was in "
               f"the top 3 for {R['info']['scores']['seen_attacks_top3']:.1%} of commands; on "
               f"brand-new attacks for {R['info']['scores']['new_attacks_top3']:.1%}.")

    c1, c2, c3 = st.columns([1, 1, 2])
    agents = c1.multiselect("Computer", sorted(ex["agent"].unique()))
    only_trail = c2.toggle("Only commands with a trail", value=True)
    hide_low = c2.toggle("Hide low-confidence guesses", value=False)
    techs = c3.multiselect("First guess", sorted(ex["guess1"].unique()),
                           format_func=lambda t: label(t, R["names"], R["ps_group"]))
    view = ex
    if agents:
        view = view[view["agent"].isin(agents)]
    if only_trail:
        view = view[view["has_trail"]]
    if techs:
        view = view[view["guess1"].isin(techs)]
    if hide_low:
        view = view[view["confident"]]

    table = pd.DataFrame({
        "time": view["ts"], "computer": view["agent"], "started with": view["launcher"],
        "confidence": np.where(view["confident"], "ok", "LOW"),
        "guess 1": view["guess1"], "score 1": view["score1"],
        "guess 2": view["guess2"], "score 2": view["score2"],
        "guess 3": view["guess3"], "score 3": view["score3"],
        "alert rows": view["n_rows"], "trail": view["has_trail"],
        "Wazuh's own tag": view["wazuh_ids"],
    })
    if "true_technique" in view.columns:
        table.insert(4, "true technique", view["true_technique"])
        table.insert(5, "right?", np.where(view["true_technique"] == "", "",
                                           np.where(view["right"], "yes",
                                                    np.where(view["in_top3"], "in top 3", "no"))))
    st.dataframe(table, hide_index=True, height=480)
    st.caption(f"{len(table):,} commands shown, {int((table['confidence'] == 'LOW').sum()):,} with "
               "LOW confidence (best score 0 or below: the model was not sure about any "
               "technique). 'Wazuh's own tag' is the label Wazuh's rules gave; in our tests it "
               "was right for only about 15% of commands.")
    st.download_button("Download this table (CSV)", table.to_csv(index=False).encode("utf-8"),
                       file_name="technique_predictions.csv", mime="text/csv")


def shap_chart(table, info, R):
    t = table.iloc[::-1]
    colors = [GREEN if p > 0 else RED for p in t["points"]]
    text = [f"{p:+.3f}" for p in t["points"]]
    ylab = [(s if len(s) <= 70 else s[:67] + "...") + ("" if pr else "  (absent)")
            for s, pr in zip(t["clue"], t["present"])]
    fig = go.Figure(go.Bar(x=t["points"], y=ylab, orientation="h", marker_color=colors,
                           text=text, textposition="outside",
                           customdata=t["type"],
                           hovertemplate="%{y}<br>%{customdata}<br>%{x:+.4f} points<extra></extra>"))
    fig.update_layout(title=f"Why '{label(info['class'], R['names'], R['ps_group'])}'",
                      height=max(320, 34 * len(t) + 100), margin=dict(l=10, r=40, t=50, b=10),
                      xaxis_title="SHAP points (green pushes towards this technique, red pushes away)")
    fig.add_vline(x=0, line_color="black", line_width=1)
    return fig


def page_shap(res, R):
    ex, X = res["ex"], res["X"]
    st.subheader("Why did the model choose this technique?")
    st.caption("SHAP gives each clue *points*. Green clues pushed the model towards the "
               "technique, red ones pushed it away. The model's score is the base score plus "
               "all the points. For a linear model these points are exact, not estimated.")

    trail = ex["has_trail"].to_numpy()
    idx = np.where(trail)[0] if trail.any() else np.arange(len(ex))
    if not len(idx):
        st.info("No attack commands to explain.")
        return

    def describe(i):
        r = ex.iloc[i]
        low = "" if r["confident"] else "  (low confidence)"
        return f"{r['ts']} | {r['agent']} | {label(r['guess1'], R['names'], R['ps_group'])}{low}"

    i = st.selectbox("Attack command", idx, format_func=describe)
    r = ex.iloc[i]
    options = [r["guess1"], r["guess2"], r["guess3"]]
    cls = st.radio("Explain which guess?", options, horizontal=True,
                   format_func=lambda t: label(t, R["names"], R["ps_group"]))
    top = st.slider("Number of clues to show", 5, 20, 10)

    table, info = R["explainer"].explain(X.iloc[[i]], class_name=cls, top=top)
    if table.empty:
        st.info("This command has no clues the model knows.")
        return
    st.plotly_chart(shap_chart(table, info, R))

    c = st.columns(4)
    c[0].metric("Base score (average attack)", f"{info['base']:+.3f}")
    c[1].metric("Points shown", f"{table['points'].sum():+.3f}")
    c[2].metric("Points of all other clues", f"{info['rest']:+.3f}")
    c[3].metric("Model score", f"{info['score']:+.3f}")
    st.caption("Base + points shown + other points = model score "
               f"(check gap {info['check_gap']:.1e}). '(absent)' marks a clue that is NOT in "
               "this command: its absence also moves the score.")


def find_bursts(view, gap_min):
    """Split commands into bursts: a new burst starts after a quiet gap longer than gap_min
    minutes. Each computer gets its own bursts."""
    v = view.dropna(subset=["time"]).sort_values(["agent", "time"])
    new = (v["agent"] != v["agent"].shift()) | (v["time"].diff() > pd.Timedelta(minutes=gap_min))
    return v.assign(burst=new.cumsum())


def choose_time(view):
    """Let the user pick one burst of activity (recommended) or a free time window."""
    if view["time"].notna().sum() < 2:
        return view
    mode = st.radio("Which time?", ["One burst of activity (recommended)", "Time window slider",
                                    "Everything selected above"], horizontal=True)
    if mode.startswith("Everything"):
        return view
    if mode.startswith("Time window"):
        times = view["time"].dropna()
        lo, hi = times.min().to_pydatetime(), times.max().to_pydatetime()
        if lo == hi:
            return view
        window = st.slider("Time window", min_value=lo, max_value=hi, value=(lo, hi),
                           format="MMM D, HH:mm")
        return view[view["time"].between(pd.Timestamp(window[0]), pd.Timestamp(window[1]))]

    gap = st.slider("A burst ends after a quiet gap of (minutes)", 2, 60, 10)
    b = find_bursts(view, gap)
    info = (b.groupby("burst").agg(agent=("agent", "first"), start=("time", "min"),
                                   end=("time", "max"), n=("time", "size"),
                                   techs=("guess1", "nunique"))
            .sort_values("start"))
    info = info[info["n"] >= 2]
    if info.empty:
        st.info("No bursts with at least 2 attack commands. Try a longer gap.")
        return view.iloc[0:0]

    def describe(k):
        r = info.loc[k]
        return (f"{r['agent']} | {r['start']:%b %d %H:%M}–{r['end']:%H:%M} | "
                f"{r['n']} commands, {r['techs']} techniques")

    # Start on the burst with the most different techniques: the most informative one
    keys = list(info.index)
    best = keys.index(info.sort_values(["techs", "n"], ascending=False).index[0])
    k = st.selectbox(f"Burst ({len(info)} found, in time order; starts on the one with the "
                     "most techniques)", keys, index=best, format_func=describe)
    return b[b["burst"] == k]


def page_groups(res, R):
    ex = res["ex"]
    st.subheader("Which threat groups fit the detected techniques?")
    st.warning("These are **candidate groups**: groups whose known technique lists fit the "
               "evidence. The score measures fit, not the chance that the group did it. "
               "The method was tested on simulated attacks (see the Simulation tab).")

    with st.expander("1. Choose which attack commands count as one observation", expanded=True):
        c1, c2, c3 = st.columns(3)
        agents = c1.multiselect("Computer (empty = all)", sorted(ex["agent"].unique()))
        days = sorted(d for d in ex["day"].dropna().unique())
        chosen_days = c2.multiselect("Day (empty = all)", days)
        use_no_trail = c3.toggle("Also use commands without a trail", value=False)
        use_low = c3.toggle("Also use low-confidence guesses", value=False)
        view = ex
        if agents:
            view = view[view["agent"].isin(agents)]
        if chosen_days:
            view = view[view["day"].isin(chosen_days)]
        if not use_no_trail:
            view = view[view["has_trail"]]
        n_low = int((~view["confident"]).sum())
        if not use_low:
            view = view[view["confident"]]

        view = choose_time(view)
        st.info("Tip: whole days contain many different attacks mixed together. Then groups "
                "with long technique lists fit best almost automatically. Rank one burst of "
                "activity on one computer for a meaningful result. The file also contains "
                "clean-up and preparation steps, which the logs cannot tell apart from attack "
                "steps.")
        detected = sorted(view["guess1"].unique())
        observed = st.multiselect(
            "Techniques used for ranking (remove any you do not trust)", detected, default=detected,
            format_func=lambda t: label(t, R["names"], R["ps_group"]))
        st.caption(f"{len(view):,} attack commands, {len(observed)} different techniques"
                   + ("" if use_low else f" ({n_low:,} low-confidence guesses on these computers and days left out)") + ".")

    if not observed:
        st.info("No techniques selected.")
        return
    show_results(set(observed), R)


def show_results(observed, R, true_group=None):
    ranked = ranker.rank_groups(observed, R["profiles"], R["weights"])
    gw = ranker.group_warnings(ranked, R["visible"], R["identical"])
    for note in ranker.overall_warnings(ranked, observed):
        st.warning(note)

    top = ranked.head(10).copy()
    fig = go.Figure()
    fig.add_bar(y=top["group"][::-1], x=top["weighted_jaccard"][::-1], orientation="h",
                name="Weighted Jaccard (main)", marker_color="#1565c0")
    fig.add_bar(y=top["group"][::-1], x=top["jaccard"][::-1], orientation="h",
                name="Plain Jaccard", marker_color=GREY)
    fig.update_layout(barmode="group", title="Top 10 candidate groups",
                      height=460, margin=dict(l=10, r=10, t=50, b=10),
                      xaxis_title="fit score (0 = nothing shared, 1 = identical lists)",
                      legend=dict(orientation="h", y=-0.15))
    st.plotly_chart(fig)

    table = pd.DataFrame({
        "rank": top["rank"], "group": top["group"],
        "weighted score": top["weighted_jaccard"].round(3),
        "plain score": top["jaccard"].round(3), "plain rank": top["rank_plain"],
        "techniques shared": top["n_matched"], "list size": top["profile_size"],
        "warning": [" ".join(gw[g]) for g in top["group"]],
    })
    st.dataframe(table, hide_index=True)

    st.markdown("**Why each group ranks where it does**")
    used_by = ranker.groups_using(R["profiles"])
    n_groups = len(R["profiles"])
    for _, r in top.head(5).iterrows():
        title = f"#{r['rank']} {r['group']} — weighted {r['weighted_jaccard']:.3f}"
        if true_group and r["group"] == true_group:
            title += "  ← the simulated group"
        with st.expander(title):
            if r["matched"]:
                st.markdown("**Shared techniques** (rarest first; rare ones count more):")
                for t in r["matched"]:
                    st.markdown(f"- {label(t, R['names'], R['ps_group'])} — on the list of "
                                f"{used_by[t]} of {n_groups} groups")
            else:
                st.markdown("No shared techniques.")
            st.markdown(f"**Seen in the logs but not on this group's list:** "
                        f"{len(r['observed_not_in_profile'])} technique(s)"
                        + (": " + ", ".join(r["observed_not_in_profile"])
                           if r["observed_not_in_profile"] else ""))
            st.markdown(f"**On the group's list but not seen:** {r['profile_not_seen']} of "
                        f"{r['profile_size']}. Not seeing a technique does not prove the group "
                        "would not use it; many techniques leave no alert in these logs.")
            for note in gw[r["group"]]:
                st.warning(note)
    return ranked


def page_simulation(R):
    st.subheader("Simulation: would the ranker find a known group?")
    st.info("This is a **simulation**, not real data: we take one group's known techniques, "
            "keep only part of them, add some unrelated ones, and see where the group ranks. "
            "It shows how much evidence the ranker needs. Detection is assumed perfect here.")
    groups = sorted(R["profiles"])
    c1, c2, c3, c4 = st.columns(4)
    g = c1.selectbox("Group", groups)
    share = c2.slider("Share of its techniques that ran", 0.25, 1.0, 0.75, 0.05)
    noise = c3.slider("Unrelated techniques added", 0, 10, 2)
    seed = c4.number_input("Random seed", 0, 9999, 42)

    vis = R["visible"][g]
    st.caption(f"{g}: {len(R['profiles'][g])} techniques on its list, {len(vis)} of them "
               "detectable by the model.")
    observed = ranker.simulate_observation(g, R["visible"], R["classes"], share, noise,
                                           ranker.new_rng(int(seed)))
    if not observed:
        st.warning("No techniques were kept in this trial. Raise the share or change the seed.")
        return
    st.markdown("**Simulated observation:** " + ", ".join(sorted(observed)))
    ranked = show_results(observed, R, true_group=g)
    pos = ranked.loc[ranked["group"] == g, "rank"].iloc[0]
    (st.success if pos == 1 else st.warning if pos <= 3 else st.error)(
        f"{g} ranked #{pos} of {len(ranked)}.")

    with st.expander("Run 100 trials (takes a few seconds)"):
        if st.button("Run"):
            rng = ranker.new_rng(int(seed))
            ranks = []
            for _ in range(100):
                obs = ranker.simulate_observation(g, R["visible"], R["classes"], share, noise, rng)
                rk = ranker.rank_groups(obs, R["profiles"], R["weights"])
                ranks.append(int(rk.loc[rk["group"] == g, "rank"].iloc[0]) if obs else len(rk))
            ranks = np.array(ranks)
            c = st.columns(3)
            c[0].metric("Ranked #1", f"{(ranks == 1).mean():.0%}")
            c[1].metric("In top 3", f"{(ranks <= 3).mean():.0%}")
            c[2].metric("Average rank", f"{ranks.mean():.1f}")


def page_about(R):
    s = R["info"]["scores"]
    st.subheader("What the numbers mean")
    st.markdown(f"""
**Model.** {R['info']['model']}, C = {R['info']['C']}, trained on
{R['info']['trained_on_executions']:,} attack commands from {R['info']['dataset']},
{R['info']['number_of_classes']} classes.

**Measured performance** (each command predicted by a model that never saw it):

| Test | Macro-F1 | Right answer in top 3 |
|---|---|---|
| Attacks seen before, on new days | {s['seen_attacks_macro_F1']:.3f} | {s['seen_attacks_top3']:.1%} |
| Brand-new attacks (test hidden) | {s['new_attacks_macro_F1']:.3f} | {s['new_attacks_top3']:.1%} |

*Macro-F1* is a score from 0 to 1 where every technique counts equally.

**PS_GROUP.** {len(R['ps_group'])} PowerShell techniques leave exactly the same trace in
these logs (the dataset has no PowerShell log), so no model can separate them. They are
shown as one class.

**Candidate groups.** The ranking compares detected techniques with each group's list from
the dataset's scenario manifest. The score shows how well the lists fit. It is not a
probability and not proof of who attacked. Groups with identical detectable lists can never
be separated.

{"**This is the held-out demo copy.** It was trained without " + " and ".join(R["info"]["held_out_days"]) + f", on {R['info']['trained_on_executions']:,} executions. Its score on those days: first guess right {R['info']['holdout_scores']['accuracy']:.1%}, top 3 {R['info']['holdout_scores']['top3']:.1%}, macro-F1 {R['info']['holdout_scores']['macro_F1']:.3f}." if R["info"].get("held_out_days") else ""}

**Important for the demo.** If you upload days from the Windows-APT 2025 dataset, the model
has already seen those commands in training, so its guesses there will look better than
the measured scores above. The measured scores are the honest ones.
""")


# =====================================================================
# Main
# =====================================================================
def main():
    if not auth.check_login():
        return
    auth.logout_button()

    available = {k: v for k, v in MODEL_DIRS.items() if (HERE / v / "final_model.joblib").exists()}
    if not available:
        st.error("No model found. Run notebook cell 19.")
        st.stop()
    st.sidebar.header("Model")
    choice = st.sidebar.radio("Which model?", list(available), label_visibility="collapsed",
                              help="The held-out model never saw 9–10 Dec 2024. Use it with "
                                   "the demo file for an honest test.")
    try:
        R = load_resources(available[choice])
    except Exception as e:
        st.error(f"Could not load the model files: {e}")
        st.stop()

    if R["info"].get("scikit_learn") and R["info"]["scikit_learn"] != sklearn.__version__:
        st.sidebar.warning(f"The model was saved with scikit-learn {R['info']['scikit_learn']} "
                           f"but {sklearn.__version__} is installed. Install the same version.")

    st.sidebar.header("Upload")
    up = st.sidebar.file_uploader("Wazuh alert export (.csv or .csv.gz)", type=["csv", "gz"],
                                  help="Same columns as combined.csv. The file stays in memory "
                                       "for this session only and is never saved.")
    key_file = st.sidebar.file_uploader("Answer key (optional, for checking)", type=["csv"],
                                        help="demo_answer_key.csv: the true technique of each "
                                             "attack command. Used only to score the model.")
    with st.sidebar.expander("What should my CSV contain?"):
        st.markdown(
            "A **Wazuh alert export** (one row per alert), with these columns:\n\n"
            "**Required** (the dashboard needs all of these):\n"
            "- `_source.@timestamp` – when the alert happened\n"
            "- `_source.agent.name` – the computer\n"
            "- `_source.rule.id` – Wazuh rule number\n"
            "- `_source.data.win.system.eventID` – Sysmon event (1, 3, 11, 13, 22…)\n"
            "- `_source.data.win.eventdata.image` – the program\n"
            "- `_source.data.win.eventdata.parentImage` – the program that started it\n"
            "- `_source.data.win.eventdata.commandLine` – the command\n"
            "- `_source.data.win.eventdata.processGuid` – the program's ID\n"
            "- `_source.data.win.eventdata.parentProcessGuid` – the parent's ID\n\n"
            "**Used if present** (better results): `_source.rule.description`, "
            "`_source.rule.mitre.id`, and under `_source.data.win.eventdata.`: "
            "`sourceProcessGUID`, `targetFilename`, `targetObject`, `imageLoaded`, "
            "`destinationPort`, `targetImage`, `queryName`.\n\n"
            "An **attack** is any program whose parent is the Caldera agent "
            "(`splunkd.exe` or `caldera-agent3.exe`). The dashboard follows the "
            "process IDs to collect each attack's alerts.")
        tmpl = pd.DataFrame(columns=list(pipeline.REQUIRED) + list(pipeline.OPTIONAL)
                            + [pipeline.P + f for f in pipeline.EXTRA_FIELDS])
        st.download_button("Download empty template (CSV)",
                           tmpl.to_csv(index=False).encode("utf-8"),
                           file_name="csv_template.csv", mime="text/csv")
    run_id = (up.file_id, R["folder"]) if up is not None else None
    if up is not None and st.session_state.get("file_id") != run_id:
        with st.spinner("Linking alerts to attack commands and running the model..."):
            try:
                st.session_state["result"] = process(up, R)
                st.session_state["file_id"] = run_id
            except ValueError as e:
                st.session_state.pop("result", None)
                st.sidebar.error(str(e))
            except Exception:
                st.session_state.pop("result", None)
                st.sidebar.error("This file could not be read. Check that it is a Wazuh alert "
                                 "CSV export with the same columns as combined.csv.")
    if up is None:
        st.session_state.pop("result", None)
        st.session_state.pop("file_id", None)

    st.title("APT Technique & Candidate Group Dashboard")
    tabs = st.tabs(["Overview", "Techniques", "Why? (SHAP)", "Candidate groups",
                    "Simulation", "About"])
    res = st.session_state.get("result")
    if res is not None:
        ex2, err = attach_answer_key(res["ex"], key_file)
        if err:
            st.sidebar.error(err)
        res = dict(res, ex=ex2)
    for t, fn in zip(tabs[:4], [page_overview, page_techniques, page_shap, page_groups]):
        with t:
            if res is None:
                st.info("Upload a Wazuh alert CSV in the sidebar to start.")
            else:
                fn(res, R)
    with tabs[4]:
        page_simulation(R)
    with tabs[5]:
        page_about(R)


main()
