"""
explain.py  -  Dashboard step 2: why did the model choose this technique?

WHAT THIS FILE DOES (simple version)
  SHAP gives every clue a number of "points": how much that clue pushed the
  model towards (+) or away from (-) an answer. For a linear model such as
  the Linear SVM there is an exact formula (notebook cell 18):

      points of clue j for class c = weight[c, j] * (value_j - average value_j)

      model score = base score + sum of all points

  "average value" comes from the training data and is saved in
  shap_background_mean.npy. The points are in the model's own score units;
  they are not percentages or probabilities.

  This file also turns raw clue names such as "a__rule_92041" into words,
  such as "Wazuh alert 92041: <rule description>".
"""
from __future__ import annotations

import numpy as np
import pandas as pd

KIND = {"a": "Alert/program", "c": "Command words", "ch": "Command letters",
        "e": "File/registry/network"}

# Windows / Sysmon event numbers -> words
EVENT_NAMES = {
    "1": "program started", "3": "network connection", "5": "program ended",
    "7": "library (DLL) loaded", "8": "remote thread created", "10": "another program's memory opened",
    "11": "file created", "12": "registry key created or deleted", "13": "registry value set",
    "15": "file stream created", "17": "pipe created", "18": "pipe connected",
    "22": "DNS name looked up", "23": "file deleted", "255": "Sysmon error",
    "4624": "logon", "4625": "failed logon", "4688": "process created (Security log)",
    "4720": "user account created", "4732": "user added to a group",
}

EXTRA_PREFIX = {"file_": "file path word", "reg_": "registry word", "lib_": "library word",
                "port_": "network port", "target_": "opened program word", "dns_": "DNS name word"}


class Explainer:
    def __init__(self, model, background_mean, rule_desc=None):
        self.feat = model.named_steps["feat"]
        self.clf = model.named_steps["clf"]
        self.W = np.asarray(self.clf.coef_)
        self.classes = list(self.clf.classes_)
        self.names = self.feat.get_feature_names_out()
        self.mu = np.asarray(background_mean).ravel()
        if self.mu.shape[0] != self.W.shape[1]:
            raise ValueError("shap_background_mean.npy does not belong to this model "
                             f"({self.mu.shape[0]} values, model has {self.W.shape[1]} clues). "
                             "Run notebook cell 19 again.")
        self.base = self.clf.intercept_ + self.W @ self.mu
        self.rule_desc = rule_desc or {}

    # ---------- clue names in words ----------
    def readable(self, raw):
        part, _, tok = raw.partition("__")
        kind = KIND.get(part, part)
        if part == "a":
            if tok.startswith("rule_"):
                n = tok[5:]
                d = self.rule_desc.get(n, "")
                return kind, f"Wazuh alert {n}" + (f": {d}" if d else "")
            if tok.startswith("event_"):
                n = tok[6:]
                return kind, f"Event {n}" + (f" ({EVENT_NAMES[n]})" if n in EVENT_NAMES else "")
            if tok.startswith("prog_"):
                return kind, f"Program run: {tok[5:]}"
            if tok.startswith("launch_"):
                return kind, f"Attack started with: {tok[7:]}"
            return kind, tok
        if part == "e":
            for p, label in EXTRA_PREFIX.items():
                if tok.startswith(p):
                    return kind, f"{label}: {tok[len(p):]}"
            return kind, tok
        if part == "ch":
            return kind, f"command letters: '{tok}'"
        if part == "c":
            return kind, f"command word{'s' if ' ' in tok else ''}: {tok}"
        return kind, tok

    # ---------- one execution ----------
    def explain(self, X_row: pd.DataFrame, class_name=None, top=10):
        """Explain one execution (a 1-row DataFrame with columns A, cmds, extra).

        Returns (table, info). table has the top clues by size of points;
        info has the class, its model score, the base score and the points of
        all the clues not shown, so that base + shown + rest = score.
        """
        xs = self.feat.transform(X_row)
        x = xs.toarray().ravel()
        scores = self.clf.decision_function(xs)[0]
        c = int(np.argmax(scores)) if class_name is None else self.classes.index(class_name)
        contrib = self.W[c] * (x - self.mu)

        order = np.argsort(-np.abs(contrib))[:top]
        rows = []
        for j in order:
            if contrib[j] == 0:
                continue
            kind, text = self.readable(self.names[j])
            rows.append({"clue": text, "type": kind, "points": float(contrib[j]),
                         "present": bool(x[j] > 0)})
        table = pd.DataFrame(rows)
        shown = table["points"].sum() if len(table) else 0.0
        info = {
            "class": self.classes[c],
            "score": float(scores[c]),
            "base": float(self.base[c]),
            "rest": float(contrib.sum() - shown),
            "check_gap": float(abs(self.base[c] + contrib.sum() - scores[c])),
        }
        return table, info
