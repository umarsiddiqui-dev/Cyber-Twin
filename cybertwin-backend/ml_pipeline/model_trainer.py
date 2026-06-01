"""
model_trainer.py – Phase 6
CyberTwin ML Pipeline

Trains a LightGBM + Random Forest voting ensemble on the
preprocessed CIC-IDS2018 data. Saves the final ensemble model
as threat_model.pkl for real-time inference.

Run AFTER data_preprocessing.py.

Usage:
  python ml_pipeline/model_trainer.py
"""

import json, logging, time, warnings
from pathlib import Path

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score
)
from imblearn.over_sampling import RandomOverSampler
import lightgbm as lgb

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("trainer")

# ── Paths ──────────────────────────────────────────────────────────────────────
MODEL_DIR = Path(__file__).parent.parent / "app" / "models" / "trained"
MODEL_DIR.mkdir(parents=True, exist_ok=True)


def load_data():
    log.info("Loading preprocessed data …")
    X_train = np.load(MODEL_DIR / "X_train.npy")
    X_test  = np.load(MODEL_DIR / "X_test.npy")
    y_train = np.load(MODEL_DIR / "y_train.npy")
    y_test  = np.load(MODEL_DIR / "y_test.npy")
    le      = joblib.load(MODEL_DIR / "label_encoder.pkl")
    log.info(f"  Train: {X_train.shape}, Test: {X_test.shape}")
    log.info(f"  Classes: {list(le.classes_)}")
    return X_train, X_test, y_train, y_test, le


def balance(X_train, y_train, le):
    """
    Balance minority attack classes using random over-sampling and downsample the majority Benign class.
    We cap the Benign class to 300,000 samples to make training fast and prevent memory/CPU exhaustion.
    We cap minority attack classes to 100,000 samples.
    """
    log.info("Downsampling majority and oversampling minority classes...")
    benign_idx = list(le.classes_).index("Benign")
    
    # Split Benign and Non-Benign indices
    benign_indices = np.where(y_train == benign_idx)[0]
    non_benign_indices = np.where(y_train != benign_idx)[0]
    
    # Downsample Benign indices to 300,000
    if len(benign_indices) > 300_000:
        np.random.seed(42)
        benign_indices = np.random.choice(benign_indices, size=300_000, replace=False)
        
    # Combine selected indices
    selected_indices = np.concatenate([benign_indices, non_benign_indices])
    X_train = X_train[selected_indices]
    y_train = y_train[selected_indices]
    
    label_counts = {i: int(np.sum(y_train == i)) for i in range(len(le.classes_))}
    
    # Cap minority classes to 100,000
    cap = 100_000
    sampling_strategy = {}
    for i, cnt in label_counts.items():
        if i == benign_idx:
            continue
        if cnt < cap:
            sampling_strategy[i] = cap
            
    if not sampling_strategy:
        return X_train, y_train
        
    ros = RandomOverSampler(sampling_strategy=sampling_strategy, random_state=42)
    X_bal, y_bal = ros.fit_resample(X_train, y_train)
    log.info(f"  After downsampling + balancing: {X_bal.shape}")
    return X_bal, y_bal



def build_ensemble(n_features: int):
    """
    Voting ensemble of:
    - LightGBM (fast, high accuracy on tabular data)
    - Random Forest (robust, interpretable, handles noise)
    """
    lgbm = lgb.LGBMClassifier(
        n_estimators=100,
        num_leaves=31,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        n_jobs=-1,
        random_state=42,
        verbose=-1,
    )
    rf = RandomForestClassifier(
        n_estimators=30,
        max_depth=15,
        min_samples_split=5,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    ensemble = VotingClassifier(
        estimators=[("lgbm", lgbm), ("rf", rf)],
        voting="soft",          # average predicted probabilities
        n_jobs=1,               # VotingClassifier parallel handled by sub-models
    )
    return ensemble


def train_and_evaluate(X_train, X_test, y_train, y_test, le):
    n_features = X_train.shape[1]
    log.info(f"Building ensemble model ({n_features} features) …")
    model = build_ensemble(n_features)

    log.info("Training … (this may take 5-15 minutes on first run)")
    t0 = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - t0
    log.info(f"  Training complete in {elapsed:.1f}s")

    log.info("Evaluating on held-out test set …")
    y_pred = model.predict(X_test)
    macro_f1 = f1_score(y_test, y_pred, average="macro")

    report = classification_report(
        y_test, y_pred,
        target_names=le.classes_,
        output_dict=False,
    )
    log.info(f"\n{report}")
    log.info(f"  Macro F1: {macro_f1:.4f}")

    # Save evaluation metrics
    metrics = {
        "macro_f1": round(macro_f1, 4),
        "classes": list(le.classes_),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "train_time_seconds": round(elapsed, 1),
    }
    with open(MODEL_DIR / "eval_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    return model, macro_f1


def main():
    log.info("═" * 60)
    log.info("CyberTwin – Model Training Pipeline")
    log.info("═" * 60)

    X_train, X_test, y_train, y_test, le = load_data()

    # Balance training set only (keep test set real-world distribution)
    X_bal, y_bal = balance(X_train, y_train, le)

    model, macro_f1 = train_and_evaluate(X_bal, X_test, y_bal, y_test, le)

    # Save model
    model_path = MODEL_DIR / "threat_model.pkl"
    log.info(f"Saving model to {model_path} …")
    joblib.dump(model, model_path, compress=3)

    log.info("✅ Training complete.")
    log.info(f"   Macro F1  : {macro_f1:.4f}")
    log.info(f"   Model saved: {model_path}")

    if macro_f1 < 0.85:
        log.warning("⚠️  Macro F1 below 0.85 — consider tuning hyperparameters.")


if __name__ == "__main__":
    main()
