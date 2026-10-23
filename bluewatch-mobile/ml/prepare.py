#!/usr/bin/env python3
"""
Build the BlueWatch Mobile feature matrix from the KronoDroid real-device CSVs.

    python bluewatch-mobile/ml/prepare.py

Reads  bluewatch-mobile/data/raw/real_{legitimate,malware}_v1.zip
Writes bluewatch-mobile/data/processed/kronodroid_real_v1.npz
       bluewatch-mobile/data/processed/prepare_report.json

Dataset: KronoDroid (Guerra-Manzanares, Bahsi, Nomm, Computers & Security 110, 2021,
doi:10.1016/j.cose.2021.102399), https://github.com/aleguma/kronodroid. Released for
research purposes on condition the paper is cited.
"""

import csv
import hashlib
import io
import json
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "processed"
FILES = {"real_legitimate_v1.zip": 0, "real_malware_v1.zip": 1}

# Identifiers, labels and antivirus-scan metadata. Training on these would leak the
# label (Detection_Ratio is literally the share of AV engines flagging the app).
EXCLUDE = {"Package", "Malware", "sha256", "EarliestModDate", "HighestModDate",
           "Scanners", "Detection_Ratio", "TimesSubmitted", "MalFamily"}
FEATURES_VERSION = "kronodroid-real-v1/features-1"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_date(s):
    try:
        return datetime.strptime(s.strip(), "%m/%d/%Y")
    except ValueError:
        return None


def read_rows(path):
    with zipfile.ZipFile(path) as zf:
        with zf.open(zf.namelist()[0]) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8", errors="replace"))
            header = next(reader)
            return header, list(reader)


def main():
    report = {"features_version": FEATURES_VERSION, "sources": {}, "dropped": Counter()}
    header = None
    records = []
    for name, label in FILES.items():
        path = RAW / name
        h, rows = read_rows(path)
        if header is None:
            header = h
        elif h != header:
            raise SystemExit(f"column mismatch in {name}")
        report["sources"][name] = {"sha256": sha256_file(path), "rows": len(rows)}
        idx = {c: i for i, c in enumerate(header)}
        for r in rows:
            if int(r[idx["Malware"]]) != label:
                report["dropped"]["label_mismatch_with_file"] += 1
                continue
            records.append((label, r))

    idx = {c: i for i, c in enumerate(header)}
    feature_names = [c for c in header if c not in EXCLUDE]
    feat_idx = [idx[c] for c in feature_names]

    # Drop hashes that appear with both labels, then keep the first of any duplicate.
    labels_by_sha = {}
    for label, r in records:
        labels_by_sha.setdefault(r[idx["sha256"]].strip(), set()).add(label)
    conflicting = {s for s, ls in labels_by_sha.items() if len(ls) > 1}
    seen = set()
    X, y, dates, shas, families = [], [], [], [], []
    for label, r in records:
        sha = r[idx["sha256"]].strip()
        if sha in conflicting:
            report["dropped"]["conflicting_label_sha256"] += 1
            continue
        if sha in seen:
            report["dropped"]["duplicate_sha256"] += 1
            continue
        d = parse_date(r[idx["HighestModDate"]])
        if d is None or not 2008 <= d.year <= 2021:
            report["dropped"]["invalid_or_out_of_range_date"] += 1
            continue
        try:
            # Manifest-metadata columns use the literal "None" when extraction failed.
            row = [np.nan if r[i].strip() in ("", "None") else float(r[i]) for i in feat_idx]
        except ValueError:
            report["dropped"]["non_numeric_feature"] += 1
            continue
        seen.add(sha)
        X.append(row)
        y.append(label)
        dates.append(d.strftime("%Y-%m-%d"))
        shas.append(sha)
        families.append(r[idx["MalFamily"]].strip() if label else "")

    X = np.asarray(X, dtype=np.float64)
    missing = int(np.isnan(X).sum())
    # Missing-value rule: an absent count/flag is treated as 0 (not observed).
    X = np.nan_to_num(X, nan=0.0)
    y = np.asarray(y, dtype=np.int8)

    OUT.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(OUT / "kronodroid_real_v1.npz", X=X, y=y, dates=np.array(dates),
                        sha256=np.array(shas), family=np.array(families),
                        feature_names=np.array(feature_names))
    report.update({
        "dropped": dict(report["dropped"]),
        "rows_out": int(len(y)),
        "class_counts": {"benign": int((y == 0).sum()), "malware": int((y == 1).sum())},
        "n_features": len(feature_names),
        "missing_values_filled_with_zero": missing,
        "excluded_columns": sorted(EXCLUDE),
        "date_range": [min(dates), max(dates)],
        "malware_families": len(set(f for f in families if f)),
    })
    (OUT / "prepare_report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
