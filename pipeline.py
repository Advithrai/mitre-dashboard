"""
pipeline.py  -  Dashboard step 1: raw Wazuh alerts -> model inputs

WHAT THIS FILE DOES (simple version)
  1. load_alerts()      read an alert CSV and check it has the right columns
  2. find_launches()    find the attack commands (started by the Caldera agent)
  3. link_rows()        follow each attack's "family tree" of programs and
                        collect every alert row that belongs to that attack
  4. build_executions() make one row per attack, with the three clue columns
                        A, cmds and extra that the saved model expects

WHY A SEPARATE FILE?
  The dashboard must prepare uploaded data in EXACTLY the same way the
  notebook prepared the training data. If one small rule differs, the model
  sees different clues and its answers change. Every rule below is copied
  from 01_clean_pipeline.ipynb (cells 1, 7 and 9).
  After any change here, run the check cell (cell 19) again.

This file holds no attack command text, so antivirus should leave it alone.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque

import pandas as pd

P = "_source.data.win.eventdata."

# Columns the dashboard cannot work without (CSV name -> short name)
REQUIRED = {
    "_source.@timestamp": "ts",
    "_source.agent.name": "agent",
    "_source.rule.id": "rule_id",
    "_source.data.win.system.eventID": "event_id",
    P + "image": "image",
    P + "parentImage": "parentImage",
    P + "commandLine": "cmd",
    P + "processGuid": "guid",
    P + "parentProcessGuid": "parentGuid",
}

# Columns that are used if present
OPTIONAL = {
    "_source.rule.description": "rule_desc",
    "_source.rule.mitre.id": "wazuh_ids",
    P + "sourceProcessGUID": "sourceGuid",
}

# Extra clues (notebook cell 9). Order matters: keep it the same.
EXTRA_FIELDS = {
    "targetFilename": "file_",
    "targetObject": "reg_",
    "imageLoaded": "lib_",
    "destinationPort": "port_",
    "targetImage": "target_",
    "queryName": "dns_",
}

# The Caldera agent that launched every attack command (notebook cell 1)
LAUNCHER_PATTERN = r"(?:splunkd|caldera-agent3)\.exe$"


# ---------------------------------------------------------------------------
# 1. Load and check the CSV
# ---------------------------------------------------------------------------
def _rewind(source):
    """An uploaded file is read twice (header, then data); go back to the start."""
    if hasattr(source, "seek"):
        source.seek(0)


def load_alerts(source) -> pd.DataFrame:
    """Read a Wazuh alert CSV (same columns as combined.csv).

    `source` can be a file path or an uploaded file.
    The index is the row position in the file (called row_index).
    Raises ValueError with a plain message if columns are missing.
    """
    _rewind(source)
    header = pd.read_csv(source, nrows=0).columns
    _rewind(source)

    missing = [c for c in REQUIRED if c not in header]
    if missing:
        raise ValueError(
            "This file is missing columns the dashboard needs: "
            + ", ".join(missing)
            + ". Please upload a Wazuh alert export with the same columns as combined.csv."
        )

    rename = dict(REQUIRED)
    rename.update({c: n for c, n in OPTIONAL.items() if c in header})
    rename.update({P + f: "x_" + f for f in EXTRA_FIELDS if P + f in header})

    ev = (pd.read_csv(source, usecols=list(rename), dtype=str, low_memory=False)
            .rename(columns=rename)
            .fillna(""))
    # Empty cells sometimes hold only spaces. Strip them so empty really means empty.
    for c in ev.columns:
        ev[c] = ev[c].astype(str).str.strip()

    # Optional columns that were absent become empty columns
    for name in list(OPTIONAL.values()) + ["x_" + f for f in EXTRA_FIELDS]:
        if name not in ev.columns:
            ev[name] = ""

    # Process IDs (GUIDs): same format everywhere, so they can be matched
    for c in ("guid", "parentGuid", "sourceGuid"):
        ev[c] = ev[c].str.strip("{}").str.lower()

    ev.index.name = "row_index"
    return ev


# ---------------------------------------------------------------------------
# 2. Find the attack commands
# ---------------------------------------------------------------------------
def find_launches(ev: pd.DataFrame) -> pd.DataFrame:
    """Rows where the Caldera agent started a program = one attack execution each."""
    is_launch = ev["parentImage"].str.contains(LAUNCHER_PATTERN, case=False, regex=True)
    launches = ev.loc[is_launch].copy()
    # Fingerprint of the command, so it can be matched without storing its text
    launches["cmd_sha1"] = launches["cmd"].map(
        lambda s: hashlib.sha1(s.encode("utf-8")).hexdigest())
    return launches


# ---------------------------------------------------------------------------
# 3. Link alert rows to each attack (process family tree)
# ---------------------------------------------------------------------------
def link_rows(ev: pd.DataFrame, launches: pd.DataFrame) -> pd.DataFrame:
    """Return the alert rows that belong to an attack, with a `root` column
    (row_index of the attack's launch row) and an `is_launch` column.

    A row belongs to an attack if, on the same computer,
      - its program (processGuid) is the attack program or one of its
        children, grandchildren, ... (followed through parentProcessGuid), or
      - its sourceProcessGUID is one of those programs.
    """
    # Family tree: parent program -> child programs, per computer
    edge = (ev["guid"] != "") & (ev["parentGuid"] != "") & (ev["guid"] != ev["parentGuid"])
    children = defaultdict(set)
    for agent, parent, child in ev.loc[edge, ["agent", "parentGuid", "guid"]].itertuples(
            index=False, name=None):
        children[(agent, parent)].add(child)

    # Walk down each attack's tree
    owner = {}                                   # (agent, guid) -> root
    for root, agent, guid in launches[["agent", "guid"]].itertuples(name=None):
        if not guid or (agent, guid) in owner:
            continue
        queue = deque([guid])
        while queue:
            g = queue.popleft()
            if (agent, g) in owner:
                continue
            owner[(agent, g)] = root
            queue.extend(children.get((agent, g), ()))

    by_process = pd.Series([owner.get(k) for k in zip(ev["agent"], ev["guid"])],
                           index=ev.index, dtype=object)
    by_source = pd.Series([owner.get(k) for k in zip(ev["agent"], ev["sourceGuid"])],
                          index=ev.index, dtype=object)
    root = by_process.where(by_process.notna(), by_source)
    root.loc[launches.index] = launches.index    # a launch row always belongs to itself

    linked = ev.loc[root.notna()].copy()
    linked["root"] = root[root.notna()].astype(int)
    linked["is_launch"] = linked.index.to_numpy() == linked["root"].to_numpy()
    return linked.sort_index()


# ---------------------------------------------------------------------------
# 4. Clue text (copied from notebook cells 7 and 9)
# ---------------------------------------------------------------------------
def tokens(s, prefix):
    return " ".join(prefix + t.lower() for t in re.findall(r"[A-Za-z0-9_.\-]+", s))


def programs(s, prefix):
    names = re.findall(r"([^\\/|;,\[\]'\"\s]+\.(?:exe|dll|com|bat|cmd|ps1|vbs|js|scr|msi))",
                       s, flags=re.IGNORECASE)
    return " ".join(prefix + n.lower() for n in names)


def clue_text_A(row):
    return " ".join([
        tokens(row["rule_ids"], "rule_"),
        tokens(row["event_ids"], "event_"),
        programs(row["images"], "prog_"),
        programs(row["launch_image"], "launch_"),
    ])


def hide_answers(s):
    s = re.sub(r"T\d{4}(?:\.\d{3})?", " TID ", s, flags=re.IGNORECASE)   # technique IDs
    s = re.sub(r"\b[0-9a-f]{6}_", " ", s, flags=re.IGNORECASE)         # Caldera payload prefixes
    return s


def clean_value(s):
    s = hide_answers(s).lower()
    s = re.sub(r"[0-9a-f]{6,}", " hex ", s)          # random IDs and hashes
    s = re.sub(r"\d+", " n ", s)                      # random numbers
    return s


def row_clues(r):
    parts = []
    for f, prefix in EXTRA_FIELDS.items():
        v = r["x_" + f]
        if not v:
            continue
        if f == "destinationPort":
            parts.append(prefix + v)
        else:
            words = re.findall(r"[a-z_]{2,}", clean_value(v))
            parts.extend(prefix + w for w in words)
    return " ".join(parts)


def _join(values):
    return " ".join(v for v in values if v)


def _join_unique(values):
    """Each value once, first-seen order, ignoring upper/lower case.
    The notebook's bundle file kept each alert, event and program only once
    per attack, and Windows treats C:\\WINDOWS and C:\\Windows as the same
    folder. Checked in cells 19 and 20: A matches the notebook 100%."""
    seen = {}
    for v in values:
        if v and v.lower() not in seen:
            seen[v.lower()] = v
    return " ".join(seen.values())


# ---------------------------------------------------------------------------
# 5. One row per attack execution
# ---------------------------------------------------------------------------
def build_executions(ev, launches, linked, include_launch_in_A=False) -> pd.DataFrame:
    """One row per attack execution (index = launch row_index).

    Model columns: A, cmds, extra.
    Display columns: ts, agent, launcher, n_rows, has_trail, rule_descs,
                     wazuh_ids, cmd_sha1.

    include_launch_in_A: whether the launch row's own alert, event and program
    count as clues in A. The check cell (19) decides which setting matches
    the notebook.
    """
    kids = linked[~linked["is_launch"]]
    a_rows = linked if include_launch_in_A else kids

    ex = pd.DataFrame(index=launches.index)
    ex.index.name = "root"
    ex["ts"] = launches["ts"]
    ex["agent"] = launches["agent"]
    ex["launch_image"] = launches["image"]
    ex["launcher"] = launches["image"].str.extract(r"([^\\/]+)$", expand=False).fillna("").str.lower()
    ex["cmd_sha1"] = launches["cmd_sha1"]

    g = a_rows.groupby("root")
    ex["rule_ids"] = g["rule_id"].agg(_join_unique).reindex(ex.index).fillna("")
    ex["event_ids"] = g["event_id"].agg(_join_unique).reindex(ex.index).fillna("")
    ex["images"] = g["image"].agg(_join_unique).reindex(ex.index).fillna("")

    # Child commands, answers hidden (cell 7). The launch command is NOT used:
    # the labels were made from it.
    with_cmd = kids[kids["cmd"] != ""]
    ex["cmds"] = (with_cmd.groupby("root")["cmd"]
                  .apply(lambda x: hide_answers(" ".join(x)))
                  .reindex(ex.index).fillna(""))

    # Files, registry keys, libraries, ports, DNS names (cell 9)
    if len(kids):
        clues = kids.apply(row_clues, axis=1)
        clues = clues[clues != ""]
        ex["extra"] = (clues.groupby(kids.loc[clues.index, "root"]).apply(" ".join)
                       .reindex(ex.index).fillna(""))
    else:
        ex["extra"] = ""

    ex["A"] = ex.apply(clue_text_A, axis=1)

    # For the dashboard's explanations and warnings
    ex["n_rows"] = linked.groupby("root").size().reindex(ex.index).fillna(0).astype(int)
    ex["has_trail"] = kids.groupby("root").size().reindex(ex.index).fillna(0).astype(int) > 0
    ex["rule_descs"] = (linked.groupby("root")["rule_desc"]
                        .agg(lambda s: " | ".join(dict.fromkeys(v for v in s if v)))
                        .reindex(ex.index).fillna(""))
    # Wazuh's own technique tags, as a clean list (for comparison only, never a model input)
    ex["wazuh_ids"] = (linked.groupby("root")["wazuh_ids"]
                       .agg(lambda s: ", ".join(sorted(set(
                           re.findall(r"T\d{4}(?:\.\d{3})?", " ".join(s), flags=re.IGNORECASE)))))
                       .reindex(ex.index).fillna(""))
    return ex


def model_inputs(ex: pd.DataFrame) -> pd.DataFrame:
    """The three columns the saved model reads."""
    return ex[["A", "cmds", "extra"]].copy()


def prepare_upload(source, include_launch_in_A=False):
    """Everything in one call: file -> (alert rows, linked rows, executions)."""
    ev = load_alerts(source)
    launches = find_launches(ev)
    if launches.empty:
        raise ValueError("No attack commands found: no program in this file was "
                         "started by the Caldera agent (splunkd.exe or caldera-agent3.exe).")
    linked = link_rows(ev, launches)
    ex = build_executions(ev, launches, linked, include_launch_in_A)
    return ev, linked, ex
