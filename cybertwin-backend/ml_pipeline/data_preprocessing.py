"""
data_preprocessing.py – Phase 6
CyberTwin ML Pipeline

Loads all 10 CSE-CIC-IDS2018 Parquet files, cleans them,
normalises features, and saves preprocessed artefacts ready
for model_trainer.py.

Dataset location (never moved):
  C:/Users/Abiha Afzal/Documents/FINALYP/fyp dataset/archive (1)/

Outputs saved to:
  cybertwin-backend/app/models/trained/
    ├── X_train.npy
    ├── X_test.npy
    ├── y_train.npy
    ├── y_test.npy
    ├── feature_names.json
    ├── label_encoder.pkl
    └── feature_scaler.pkl
"""

import os, json, warnings, logging
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("preprocessor")

# ── Paths ──────────────────────────────────────────────────────────────────────
DATASET_DIR = Path("C:/Users/Abiha Afzal/Documents/FINALYP/fyp dataset/archive (1)")
OUTPUT_DIR  = Path(__file__).parent.parent / "app" / "models" / "trained"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Constants ──────────────────────────────────────────────────────────────────
LABEL_COL   = "Label"
TEST_SIZE   = 0.20
RANDOM_SEED = 42

# Features to DROP (metadata / ID columns, not network features)
DROP_COLS = [
    "Timestamp", "Dst Port", "Protocol",   # non-numeric or metadata
    "Flow ID", "Src IP", "Dst IP",          # identifiers
]

# ── Human-readable label map (CIC-IDS2018 raw labels → short names) ──────────
LABEL_MAP = {
    "Benign":                        "Benign",
    "BENIGN":                        "Benign",
    "Bot":                           "Botnet",
    "Brute Force -Web":              "BruteForce-Web",
    "Brute Force -XSS":              "BruteForce-XSS",
    "FTP-BruteForce":                "BruteForce-FTP",
    "SSH-Bruteforce":                "BruteForce-SSH",
    "DoS attacks-GoldenEye":         "DoS-GoldenEye",
    "DoS attacks-Hulk":              "DoS-Hulk",
    "DoS attacks-SlowHTTPTest":      "DoS-SlowHTTP",
    "DoS attacks-Slowloris":         "DoS-Slowloris",
    "DDoS attack-HOIC":              "DDoS-HOIC",
    "DDoS attack-LOIC-HTTP":         "DDoS-LOIC",
    "DDOS attack-LOIC-UDP":          "DDoS-LOIC-UDP",
    "Infilteration":                 "Infiltration",
    "SQL Injection":                 "SQLInjection",
}


def load_all_parquets() -> pd.DataFrame:
    """Load and concatenate all 10 parquet files in the dataset directory."""
    files = sorted(DATASET_DIR.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files found in {DATASET_DIR}")

    frames = []
    for f in files:
        log.info(f"  Loading {f.name} ...")
        df = pd.read_parquet(f, engine="pyarrow")
        frames.append(df)
        log.info(f"    → {len(df):,} rows, label dist: {df[LABEL_COL].value_counts().to_dict()}")

    combined = pd.concat(frames, ignore_index=True)
    log.info(f"Combined dataset: {len(combined):,} rows × {combined.shape[1]} columns")
    return combined


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Drop metadata columns, fix infinities, remove NaN rows."""
    # Drop non-feature columns that exist in this df
    drop = [c for c in DROP_COLS if c in df.columns]
    df = df.drop(columns=drop, errors="ignore")

    # Replace ±inf with NaN then drop
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df.dropna(inplace=True)
    log.info(f"  Dropped {before - len(df):,} rows with NaN/Inf")

    # Remove exact duplicates
    before = len(df)
    df.drop_duplicates(inplace=True)
    log.info(f"  Dropped {before - len(df):,} duplicate rows")

    return df


def encode_labels(df: pd.DataFrame):
    """Normalise raw label strings and integer-encode them."""
    df[LABEL_COL] = df[LABEL_COL].str.strip().map(LABEL_MAP).fillna(df[LABEL_COL])
    le = LabelEncoder()
    y = le.fit_transform(df[LABEL_COL])
    log.info(f"  Classes ({len(le.classes_)}): {list(le.classes_)}")
    return y, le


def main():
    log.info("═" * 60)
    log.info("CyberTwin – Data Preprocessing Pipeline")
    log.info("═" * 60)

    # 1. Load
    df = load_all_parquets()

    # 2. Clean
    log.info("Cleaning …")
    df = clean(df)

    # 3. Encode labels
    log.info("Encoding labels …")
    y, le = encode_labels(df)

    # 4. Build feature matrix
    feature_cols = [c for c in df.columns if c != LABEL_COL]
    X = df[feature_cols].values.astype(np.float32)
    log.info(f"Feature matrix: {X.shape} — {len(feature_cols)} features")

    # 5. Train / test split (stratified)
    log.info("Splitting train/test …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )

    # 6. Scale
    log.info("Fitting StandardScaler …")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # 7. Save artefacts
    log.info(f"Saving artefacts to {OUTPUT_DIR} …")
    np.save(OUTPUT_DIR / "X_train.npy", X_train)
    np.save(OUTPUT_DIR / "X_test.npy",  X_test)
    np.save(OUTPUT_DIR / "y_train.npy", y_train)
    np.save(OUTPUT_DIR / "y_test.npy",  y_test)
    joblib.dump(le,     OUTPUT_DIR / "label_encoder.pkl")
    joblib.dump(scaler, OUTPUT_DIR / "feature_scaler.pkl")
    with open(OUTPUT_DIR / "feature_names.json", "w") as f:
        json.dump(feature_cols, f, indent=2)

    log.info("✅ Preprocessing complete.")
    log.info(f"   Train rows : {len(X_train):,}")
    log.info(f"   Test  rows : {len(X_test):,}")
    log.info(f"   Features   : {len(feature_cols)}")
    log.info(f"   Classes    : {list(le.classes_)}")


if __name__ == "__main__":
    main()
