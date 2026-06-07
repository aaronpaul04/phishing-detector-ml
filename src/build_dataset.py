"""
Build the feature matrix from raw URLs.
Filters to phishing + benign, extracts features, saves to data/processed/.
"""

import os
import sys
import pandas as pd
from tqdm import tqdm

# Make sure we can import features.py whether run from project root or src/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
from features import extract_features

RAW_PATH = os.path.join(PROJECT_ROOT, "data", "raw", "malicious_phish.csv")
OUT_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
OUT_PATH = os.path.join(OUT_DIR, "features.csv")

# Sample size per class to keep training fast.
# Bump these up later for a stronger model.
N_PER_CLASS = 50_000

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print("Loading raw dataset...")
    df = pd.read_csv(RAW_PATH)
    print(f"Loaded {len(df):,} rows")

    # Binary: phishing vs benign
    df = df[df["type"].isin(["phishing", "benign"])].copy()
    df["label"] = (df["type"] == "phishing").astype(int)
    print(f"After filter: {len(df):,} rows ({df['label'].sum():,} phishing)")

    # Balanced subsample
    phish = df[df["label"] == 1].sample(n=min(N_PER_CLASS, (df["label"] == 1).sum()), random_state=42)
    benign = df[df["label"] == 0].sample(n=min(N_PER_CLASS, (df["label"] == 0).sum()), random_state=42)
    df = pd.concat([phish, benign]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"Subsampled to {len(df):,} balanced rows")

    print("Extracting features...")
    tqdm.pandas()
    feats = df["url"].progress_apply(extract_features).apply(pd.Series)
    out = pd.concat([df[["url", "label"]].reset_index(drop=True), feats.reset_index(drop=True)], axis=1)

    out.to_csv(OUT_PATH, index=False)
    print(f"Saved {len(out):,} rows to {OUT_PATH}")
    print(f"Columns: {list(out.columns)}")


if __name__ == "__main__":
    main()