"""
Train a LightGBM phishing detector with feature importance analysis.
SHAP will be added later via Colab or HF Spaces deployment.
"""

import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, classification_report, confusion_matrix, ConfusionMatrixDisplay,
    roc_curve
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "features.csv")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)


def main():
    print("Loading features...")
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded {len(df):,} rows, {df['label'].sum():,} phishing")

    X = df.drop(columns=["url", "label"])
    y = df["label"]
    feature_names = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train):,}  Test: {len(X_test):,}")

    print("Training LightGBM...")
    model = lgb.LGBMClassifier(
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=63,
        max_depth=-1,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], callbacks=[lgb.early_stopping(30)])

    # Evaluation
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("\n=== Test set performance ===")
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1:        {f1_score(y_test, y_pred):.4f}")
    print(f"ROC AUC:   {roc_auc_score(y_test, y_proba):.4f}")
    print("\n", classification_report(y_test, y_pred, target_names=["benign", "phishing"]))

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    ConfusionMatrixDisplay(cm, display_labels=["benign", "phishing"]).plot(cmap="Blues")
    plt.title("Confusion Matrix")
    plt.savefig(os.path.join(DOCS_DIR, "confusion_matrix.png"), dpi=120, bbox_inches="tight")
    plt.close()

    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc_score(y_test, y_proba):.3f}")
    plt.plot([0, 1], [0, 1], "k--", alpha=0.4)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(DOCS_DIR, "roc_curve.png"), dpi=120, bbox_inches="tight")
    plt.close()

    # Feature importance (gain-based, most meaningful for tree models)
    importance = pd.DataFrame({
        "feature": feature_names,
        "importance": model.booster_.feature_importance(importance_type="gain")
    }).sort_values("importance", ascending=True)

    plt.figure(figsize=(8, 7))
    plt.barh(importance["feature"], importance["importance"])
    plt.xlabel("Gain Importance")
    plt.title("Feature Importance (LightGBM Gain)")
    plt.tight_layout()
    plt.savefig(os.path.join(DOCS_DIR, "feature_importance.png"), dpi=120, bbox_inches="tight")
    plt.close()

    print("\n=== Top 10 features ===")
    print(importance.sort_values("importance", ascending=False).head(10).to_string(index=False))

    # Save model + feature names
    model_path = os.path.join(MODEL_DIR, "phishing_lgbm.joblib")
    joblib.dump({"model": model, "features": feature_names}, model_path)
    print(f"\nSaved model to {model_path}")
    print(f"Saved plots to {DOCS_DIR}")


if __name__ == "__main__":
    main()