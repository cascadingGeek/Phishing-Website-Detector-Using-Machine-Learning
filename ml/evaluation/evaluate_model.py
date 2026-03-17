"""
Evaluate the saved SVM model against the full dataset.

Usage:
    uv run python -m ml.evaluation.evaluate_model
"""
from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
)

DATASET_PATH = Path(__file__).parents[2] / "ml" / "datasets" / "dataset.csv"
MODEL_PATH = Path(__file__).parents[2] / "backend" / "app" / "models" / "svm_model.pkl"


def main() -> None:
    print(f"Loading model from {MODEL_PATH} …")
    model = joblib.load(MODEL_PATH)

    print(f"Loading dataset from {DATASET_PATH} …")
    df = pd.read_csv(DATASET_PATH)
    X = df.drop("Result", axis=1)
    y = df["Result"]

    preds = model.predict(X)
    acc = accuracy_score(y, preds)

    print(f"\nFull-dataset accuracy: {acc * 100:.2f}%\n")
    print(classification_report(y, preds, target_names=["Phishing (-1)", "Legitimate (1)"]))
    print("Confusion matrix:\n", confusion_matrix(y, preds))


if __name__ == "__main__":
    main()
