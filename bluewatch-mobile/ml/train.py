#!/usr/bin/env python3
"""
Train and evaluate the BlueWatch Mobile baseline classifier.

    python bluewatch-mobile/ml/prepare.py   # first
    python bluewatch-mobile/ml/train.py

Evaluates three splits and writes metrics for all of them:
  A  random stratified 80/20    - same eras and families on both sides; deployed model
  B  per-class temporal 80/20   - train on each class's oldest 80%, test on newest 20% (drift check)
  C  unseen malware families    - test malware families never seen in training

The deployed model is the one trained on split A, and demo samples are drawn from A's
test set, so they were never seen during training. Split B shows how the same
configuration degrades on newer apps; it must be quoted alongside A.

Writes to insider-threat-lab/app/mobile_risk/artifacts/:
  model.joblib, model_meta.json, metrics.json, demo_samples.json
"""

import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "bluewatch-mobile" / "data" / "processed"
ART = ROOT / "insider-threat-lab" / "app" / "mobile_risk" / "artifacts"
SEED = 42
THRESHOLD = 0.5
MODEL_VERSION = "bwm-rf-0.1.0"


def make_model():
    return RandomForestClassifier(n_estimators=150, max_depth=25, min_samples_leaf=3,
                                  class_weight="balanced_subsample", n_jobs=-1,
                                  random_state=SEED)


def evaluate(model, X, y):
    t0 = time.perf_counter()
    score = model.predict_proba(X)[:, 1]
    elapsed = time.perf_counter() - t0
    pred = (score >= THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {
        "test_size": int(len(y)),
        "test_class_counts": {"benign": int((y == 0).sum()), "malware": int((y == 1).sum())},
        "threshold": THRESHOLD,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else float("nan"), 6),
        "batch_inference_ms_per_sample": round(1000 * elapsed / len(y), 4),
    }
    if len(set(y)) == 2:
        out["pr_auc"] = round(float(average_precision_score(y, score)), 4)
        out["roc_auc"] = round(float(roc_auc_score(y, score)), 4)
    return out


MANIFEST_COUNTS = {"nr_permissions", "normal", "dangerous", "signature", "custom_yes", "nr_custom",
                   "total_perm", "CFileSize", "UFileSize", "FilesInsideAPK", "Activities",
                   "NrIntServices", "NrIntServicesActions", "NrIntActivities",
                   "NrIntActivitiesActions", "NrIntReceivers", "NrIntReceiversActions",
                   "TotalIntentFilters", "NrServices"}


def is_runtime_feature(name):
    """KronoDroid: permissions are UPPER_CASE, system calls are lower-case names."""
    return name == "NrContactedIps" or (not name.isupper() and name not in MANIFEST_COUNTS)


def date_range(ds):
    ds = sorted(str(x) for x in ds)
    return [ds[0], ds[-1]]


def temporal_split(y, dates, frac=0.8):
    train, test = [], []
    for cls in (0, 1):
        idx = np.where(y == cls)[0]
        idx = idx[np.argsort(dates[idx], kind="stable")]
        cut = int(len(idx) * frac)
        train.extend(idx[:cut])
        test.extend(idx[cut:])
    return np.array(sorted(train)), np.array(sorted(test))


def main():
    d = np.load(DATA / "kronodroid_real_v1.npz")
    X, y, dates, sha, fam = d["X"], d["y"], d["dates"], d["sha256"], d["family"]
    names = [str(n) for n in d["feature_names"]]
    prep = json.loads((DATA / "prepare_report.json").read_text())

    splits = {}

    # A: random stratified (deployed)
    tr, te = train_test_split(np.arange(len(y)), test_size=0.2, stratify=y, random_state=SEED)
    t0 = time.perf_counter()
    model = make_model().fit(X[tr], y[tr])
    train_s = time.perf_counter() - t0
    splits["A_random_stratified"] = {
        "description": "Random stratified 80/20. Deployed model. Same eras and families appear "
                       "in train and test, so this is an upper bound.",
        **evaluate(model, X[te], y[te])}

    # B: per-class temporal (drift check)
    btr, bte = temporal_split(y, dates)
    m = make_model().fit(X[btr], y[btr])
    splits["B_per_class_temporal"] = {
        "description": "Within each class, train on the oldest 80% by HighestModDate and test on "
                       "the newest 20%. Shows degradation on newer apps (concept drift).",
        "train_date_range": {c: date_range(dates[btr][y[btr] == i])
                             for i, c in enumerate(["benign", "malware"])},
        "test_date_range": {c: date_range(dates[bte][y[bte] == i])
                            for i, c in enumerate(["benign", "malware"])},
        **evaluate(m, X[bte], y[bte])}

    # C: unseen malware families (benign split randomly alongside)
    mal = np.where(y == 1)[0]
    ben = np.where(y == 0)[0]
    groups = np.where(fam[mal] == "", "unknown", fam[mal])
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    mtr, mte = next(gss.split(mal, groups=groups))
    ctr_b, cte_b = train_test_split(ben, test_size=0.2, random_state=SEED)
    ctr = np.concatenate([mal[mtr], ctr_b])
    cte = np.concatenate([mal[mte], cte_b])
    m = make_model().fit(X[ctr], y[ctr])
    splits["C_unseen_malware_families"] = {
        "description": "Malware families in test never appear in training "
                       f"({len(set(groups[mte]))} held-out families); benign split randomly.",
        **evaluate(m, X[cte], y[cte])}

    # D: runtime behaviour only (system calls + contacted IPs), same random split as A.
    # Answers "how much of the signal is behaviour rather than declared permissions?"
    behaviour_cols = [i for i, n in enumerate(names) if is_runtime_feature(n)]
    m = make_model().fit(X[tr][:, behaviour_cols], y[tr])
    splits["D_runtime_behaviour_only"] = {
        "description": f"Same split as A, trained only on {len(behaviour_cols)} runtime features "
                       "(system-call counts and contacted IPs; no permissions or manifest data). "
                       "Comparison only; not deployed.",
        **evaluate(m, X[te][:, behaviour_cols], y[te])}

    # Evidence statistics from the deployed model's training split only
    Xb = X[tr][y[tr] == 0]
    Xm = X[tr][y[tr] == 1]
    ART.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, ART / "model.joblib", compress=3)

    meta = {
        "model_version": MODEL_VERSION,
        "features_version": prep["features_version"],
        "algorithm": "sklearn.ensemble.RandomForestClassifier",
        "params": {k: v for k, v in model.get_params().items() if k != "n_jobs"},
        "threshold": THRESHOLD,
        "score_semantics": "Fraction of trees voting 'malware' (0-1). Uncalibrated risk score, "
                           "not a probability. >= threshold means 'flag for analyst review'.",
        "trained_on": "A_random_stratified train split",
        "train_rows": int(len(tr)),
        "trained_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "train_seconds": round(train_s, 1),
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "dataset": {"name": "KronoDroid real-device v1", "url": "https://github.com/aleguma/kronodroid",
                    "citation": "Guerra-Manzanares, Bahsi, Nomm. KronoDroid. Computers & Security 110 "
                                "(2021) 102399. doi:10.1016/j.cose.2021.102399",
                    "sources": prep["sources"]},
        "feature_names": names,
        "importance": [round(float(v), 6) for v in model.feature_importances_],
        "benign_median": [float(v) for v in np.median(Xb, axis=0)],
        "benign_p90": [float(v) for v in np.percentile(Xb, 90, axis=0)],
        "malware_median": [float(v) for v in np.median(Xm, axis=0)],
    }
    (ART / "model_meta.json").write_text(json.dumps(meta))

    metrics = {"model_version": MODEL_VERSION, "prepare_report": prep, "splits": splits}
    (ART / "metrics.json").write_text(json.dumps(metrics, indent=2))

    # Demo samples: 3 malware + 3 benign from A's test set, chosen at random (seeded),
    # not by whether the model gets them right.
    rng = np.random.default_rng(SEED)
    demo = []
    for cls in (1, 0):
        pick = rng.choice(te[y[te] == cls], size=3, replace=False)
        for i in pick:
            demo.append({
                "sample_id": f"kd-{sha[i][:12]}",
                "expected_label": "malware" if cls else "benign",
                "family": str(fam[i]) or None,
                "date": str(dates[i]),
                "source": "KronoDroid real-device v1, split A test set (not used in training)",
                "features": {n: float(v) for n, v in zip(names, X[i]) if v != 0},
            })
    (ART / "demo_samples.json").write_text(json.dumps(demo, indent=2))

    print(json.dumps({k: {kk: v[kk] for kk in ("test_size", "precision", "recall", "f1",
                                               "false_positive_rate", "pr_auc", "confusion_matrix")}
                      for k, v in splits.items()}, indent=2))
    print("model size MB:", round((ART / "model.joblib").stat().st_size / 1e6, 1))


if __name__ == "__main__":
    main()
