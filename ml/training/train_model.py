"""
Train the SVM phishing detection model and save it to backend/app/models/.

Usage:
    uv run python -m ml.training.train_model
"""
from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC

DATASET_PATH = Path(__file__).parents[2] / "ml" / "datasets" / "dataset.csv"
MODEL_OUTPUT = Path(__file__).parents[2] / "backend" / "app" / "models" / "svm_model.pkl"


def load_data(path: Path) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(path)
    X = df.drop("Result", axis=1)
    y = df["Result"]
    return X, y


def train(X_train: pd.DataFrame, y_train: pd.Series) -> SVC:
    model = SVC(kernel="rbf", probability=True, random_state=42)
    model.fit(X_train, y_train)
    return model


def evaluate(model: SVC, X_test: pd.DataFrame, y_test: pd.Series) -> None:
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"\nAccuracy: {acc * 100:.2f}%\n")
    print(classification_report(y_test, preds, target_names=["Phishing", "Legitimate"]))
    print("Confusion matrix:\n", confusion_matrix(y_test, preds))


def main() -> None:
    print(f"Loading dataset from {DATASET_PATH} …")
    X, y = load_data(DATASET_PATH)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )

    print(f"Training SVM on {len(X_train)} samples …")
    model = train(X_train, y_train)

    evaluate(model, X_test, y_test)

    MODEL_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT)
    print(f"\nModel saved to {MODEL_OUTPUT}")


if __name__ == "__main__":
    main()
