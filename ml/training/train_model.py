"""
Train the SVM phishing detection model and save artifacts to app/artifacts/v1/.

Usage:
    uv run python -m ml.training.train_model
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

DATASET_PATH = Path(__file__).parents[2] / "ml" / "datasets" / "dataset.csv"
ARTIFACT_DIR = Path(__file__).parents[2] / "app" / "artifacts" / "v1"

FEATURE_COLUMNS = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report",
]

# Dataset uses -1 = legitimate, 1 = phishing
CLASS_MAPPING = {"-1": "legitimate", "1": "phishing"}


def load_data(path: Path) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(path)
    X = df[FEATURE_COLUMNS]
    y = df["Result"]
    return X, y


def train(
    X_train: pd.DataFrame, y_train: pd.Series
) -> tuple[SVC, StandardScaler]:
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    model = SVC(kernel="rbf", probability=True, random_state=42)
    model.fit(X_scaled, y_train)

    return model, scaler


def evaluate(
    model: SVC, scaler: StandardScaler, X_test: pd.DataFrame, y_test: pd.Series
) -> None:
    X_scaled = scaler.transform(X_test)
    preds = model.predict(X_scaled)
    acc = accuracy_score(y_test, preds)
    print(f"\nAccuracy: {acc * 100:.2f}%\n")
    print(classification_report(y_test, preds, target_names=["Legitimate (-1)", "Phishing (1)"]))
    print("Confusion matrix:\n", confusion_matrix(y_test, preds))


def save_artifacts(model: SVC, scaler: StandardScaler, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, output_dir / "model.joblib")
    joblib.dump(scaler, output_dir / "scaler.joblib")

    metadata = {
        "model_version": "v1",
        "training_date": str(date.today()),
        "kernel": "rbf",
        "scaler_type": "StandardScaler",
        "class_mapping": CLASS_MAPPING,
        "feature_list": FEATURE_COLUMNS,
        "feature_order": FEATURE_COLUMNS,
        "notes": "",
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    print(f"\nArtifacts saved to {output_dir}")
    print(f"  model.joblib   ({(output_dir / 'model.joblib').stat().st_size // 1024} KB)")
    print(f"  scaler.joblib  ({(output_dir / 'scaler.joblib').stat().st_size // 1024} KB)")
    print(f"  metadata.json")


def main() -> None:
    print(f"Loading dataset from {DATASET_PATH} …")
    X, y = load_data(DATASET_PATH)
    print(f"  {len(X)} samples, {len(FEATURE_COLUMNS)} features")
    print(f"  Class distribution: {dict(y.value_counts())}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )

    print(f"\nTraining SVM on {len(X_train)} samples …")
    model, scaler = train(X_train, y_train)

    evaluate(model, scaler, X_test, y_test)
    save_artifacts(model, scaler, ARTIFACT_DIR)


if __name__ == "__main__":
    main()
