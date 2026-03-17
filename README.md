# Phish.io — Phishing Website Detector

A production-ready phishing detection system that uses a trained **Support Vector Machine (SVM)** to classify any URL as phishing or legitimate in real time.

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [Objectives](#2-objectives)
3. [How It Works](#3-how-it-works)
4. [Architecture](#4-architecture)
5. [Feature Extraction Engine](#5-feature-extraction-engine)
6. [Machine Learning Model](#6-machine-learning-model)
7. [Tools and Packages](#7-tools-and-packages)
8. [Project Structure](#8-project-structure)
9. [Getting Started](#9-getting-started)
10. [Running the App](#10-running-the-app)
11. [API Reference](#11-api-reference)
12. [Re-training the Model](#12-re-training-the-model)

---

## 1. What Is This Project?

Phishing attacks trick users into visiting fraudulent websites that impersonate legitimate services to steal credentials, financial data, or personal information. Traditional blocklist-based defences fail against newly registered phishing domains that have not yet been reported.

**Phish.io** addresses this by analysing the structural and behavioural properties of a URL rather than relying on known-bad lists. Given any URL, the system extracts 30 features from the URL itself, its DNS/WHOIS records, and the content of the live page, then feeds them into an SVM classifier to produce a prediction and a confidence score — all within seconds.

---

## 2. Objectives

| #   | Objective                                                                         |
| --- | --------------------------------------------------------------------------------- |
| 1   | Detect phishing websites in real time without relying solely on blocklists        |
| 2   | Extract interpretable, URL- and page-level features that explain every decision   |
| 3   | Expose detection as a clean REST API consumed by any client                       |
| 4   | Provide a professional, interactive UI for non-technical users                    |
| 5   | Maintain a modular, production-quality codebase with clear separation of concerns |

---

## 3. How It Works

```
User enters URL
      │
      ▼
┌─────────────────────┐
│  Streamlit Frontend │  ── POST /api/v1/detect ──►
└─────────────────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │   FastAPI Backend    │
                        │                      │
                        │  1. Validate input   │
                        │  2. Extract features │
                        │  3. Run SVM model    │
                        │  4. Return result    │
                        └──────────────────────┘
                                   │
                      ◄── JSON response ──────────
      │
      ▼
┌─────────────────────┐
│  Results + Charts   │
└─────────────────────┘
```

1. The user pastes a URL into the Streamlit interface and clicks **Scan**.
2. Streamlit sends a `POST /api/v1/detect` request to the FastAPI backend.
3. The backend validates the input with Pydantic, runs the feature extraction engine, and passes the resulting 30-dimensional vector to the SVM model.
4. The model returns a class prediction (`-1` phishing / `1` legitimate) and a confidence score derived from the decision function via sigmoid normalisation.
5. The response is rendered in the UI with a result card, risk indicators, a feature bar chart, and a confidence gauge.

---

## 4. Architecture

The project follows a **clean three-layer architecture** with strict separation between the API, ML inference, feature extraction, and UI layers.

```
phishing-detection-framework/
│
├── backend/                        ← FastAPI application
│   └── app/
│       ├── main.py                 ← App factory + lifespan (model loaded once at startup)
│       ├── api/
│       │   └── routes.py           ← POST /api/v1/detect  ·  GET /api/v1/health
│       ├── core/
│       │   └── config.py           ← Pydantic Settings  (env-var / .env support)
│       ├── models/
│       │   └── svm_model.pkl       ← Serialised trained SVM
│       ├── schemas/
│       │   ├── request.py          ← DetectionRequest  (Pydantic v2)
│       │   └── response.py         ← DetectionResponse · FeatureVector
│       └── services/
│           ├── detection_service.py ← SVM inference wrapper
│           └── feature_extractor.py ← 30-feature extraction engine
│
├── frontend/                       ← Streamlit UI
│   ├── streamlit_app.py            ← Entry point; calls backend via requests
│   └── components/
│       ├── header.py               ← Branded page header
│       ├── scanner.py              ← URL input form
│       ├── results.py              ← Detection result card
│       └── visualizations.py       ← Plotly feature chart + confidence gauge
│
├── ml/                             ← Machine learning pipeline
│   ├── datasets/
│   │   ├── dataset.csv             ← 11,056-row labelled dataset (30 features + Result)
│   │   └── phising_urls.xlsx       ← Supplementary phishing URL list
│   ├── training/
│   │   └── train_model.py          ← Train SVM and save to backend/app/models/
│   └── evaluation/
│       └── evaluate_model.py       ← Full-dataset evaluation + confusion matrix
│
├── scripts/
│   ├── run_backend.sh              ← uvicorn backend.app.main:app --reload
│   └── run_frontend.sh             ← streamlit run frontend/streamlit_app.py
│
├── pyproject.toml                  ← uv / hatchling project manifest
└── README.md
```

### Layer responsibilities

| Layer                                           | Responsibility                                                             |
| ----------------------------------------------- | -------------------------------------------------------------------------- |
| **API** (`routes.py`)                           | Receive requests, validate with Pydantic, delegate to service, return JSON |
| **Service** (`detection_service.py`)            | Hold the loaded model in memory, run inference, compute confidence         |
| **Feature extraction** (`feature_extractor.py`) | Fetch and parse the target URL, compute all 30 features                    |
| **UI** (`streamlit_app.py` + components)        | Render forms, call API, display results and charts                         |
| **ML pipeline** (`ml/`)                         | Train, evaluate and serialise the SVM model independently                  |

---

## 5. Feature Extraction Engine

Every prediction is driven by 30 hand-engineered features grouped into three categories.

### URL-based features

| Feature                    | What it measures                                                   |
| -------------------------- | ------------------------------------------------------------------ |
| `having_IP_Address`        | IP literal used in place of a domain name                          |
| `URL_Length`               | Short (<54), medium (54–75), or long (>75) URL                     |
| `Shortining_Service`       | Matches against 60+ known URL shorteners                           |
| `having_At_Symbol`         | `@` symbol present (forces browser to ignore everything before it) |
| `double_slash_redirecting` | `//` appears after the protocol segment                            |
| `Prefix_Suffix`            | Hyphen (`-`) in the domain name                                    |
| `having_Sub_Domain`        | Number of sub-domain levels                                        |
| `SSLfinal_State`           | HTTPS vs HTTP                                                      |
| `HTTPS_token`              | The literal string "https" in the URL                              |
| `port`                     | Non-standard port specified in the domain                          |

### Domain / WHOIS-based features

| Feature                       | What it measures                       |
| ----------------------------- | -------------------------------------- |
| `Domain_registeration_length` | Domain expires within 12 months        |
| `age_of_domain`               | Domain registered less than 1 year ago |
| `DNSRecord`                   | WHOIS record exists for the domain     |
| `web_traffic`                 | Global Alexa-style rank < 100,000      |
| `Page_Rank`                   | Global rank < 10,000                   |
| `Google_Index`                | URL appears in Google search results   |
| `Statistical_report`          | Domain or IP matches known-bad lists   |

### Behavioural / page-content features

| Feature                  | What it measures                                                   |
| ------------------------ | ------------------------------------------------------------------ |
| `Favicon`                | Favicon loaded from an external domain                             |
| `Request_URL`            | % of embedded resources (img, audio, iframe) from external domains |
| `URL_of_Anchor`          | % of anchor `<a>` tags pointing outside the domain                 |
| `Links_in_tags`          | % of `<link>` / `<script>` tags with external sources              |
| `SFH`                    | Form `action` points to blank, external, or email destination      |
| `Submitting_to_email`    | Form submits to a `mailto:` address                                |
| `Abnormal_URL`           | Domain name absent from WHOIS response                             |
| `Redirect`               | Number of HTTP redirects before reaching the final page            |
| `on_mouseover`           | `onmouseover` event used to change the status bar                  |
| `RightClick`             | Right-click disabled via JavaScript                                |
| `popUpWidnow`            | `prompt()` call detected in page source                            |
| `Iframe`                 | `<iframe>` or `<frameBorder>` detected                             |
| `Links_pointing_to_page` | Number of back-links found in page source                          |

Each feature is encoded as **1** (legitimate indicator), **0** (suspicious), or **−1** (phishing indicator), producing a 30-dimensional integer vector fed directly to the SVM.

---

## 6. Machine Learning Model

### Algorithm

**Support Vector Machine (SVM)** with an RBF (Radial Basis Function) kernel.

SVMs are well-suited to this task because:

- The feature space is fixed-dimension and fully numerical.
- The decision boundary between phishing and legitimate sites is non-linear in feature space.
- SVMs generalise well on moderate-sized datasets without overfitting.

### Dataset

| Property         | Value                              |
| ---------------- | ---------------------------------- |
| Source           | UCI Phishing Websites Dataset      |
| Rows             | 11,056 URLs                        |
| Features         | 30                                 |
| Labels           | `-1` (phishing) · `1` (legitimate) |
| Train/test split | 70% / 30% (stratified)             |

### Training

The model is trained with `probability=True` so that `predict_proba` scores are available. For the legacy pre-trained model (saved without `probability=True`), confidence is derived from the SVM decision function via sigmoid normalisation:

```
confidence = 1 / (1 + exp(−decision_function_score))
```

Re-train with the included script to enable native probability output:

```bash
uv run python -m ml.training.train_model
```

---

## 7. Tools and Packages

### Backend

| Package             | Purpose                                                             |
| ------------------- | ------------------------------------------------------------------- |
| `fastapi`           | Async REST API framework                                            |
| `uvicorn`           | ASGI server for FastAPI                                             |
| `pydantic` v2       | Request/response validation and serialisation                       |
| `pydantic-settings` | Environment variable / `.env` configuration                         |
| `scikit-learn`      | SVM model (`SVC`), metrics, train/test split                        |
| `pandas`            | Feature vector → DataFrame for model inference                      |
| `numpy`             | Numerical operations                                                |
| `joblib`            | Model serialisation (new models); falls back to `pickle` for legacy |

### Frontend

| Package     | Purpose                                          |
| ----------- | ------------------------------------------------ |
| `streamlit` | Interactive web UI without writing HTML/JS       |
| `plotly`    | Feature bar chart and confidence gauge           |
| `requests`  | HTTP calls from Streamlit to the FastAPI backend |

### Feature extraction

| Package           | Purpose                                       |
| ----------------- | --------------------------------------------- |
| `beautifulsoup4`  | Parse live page HTML for behavioural features |
| `python-whois`    | WHOIS queries for domain age and DNS records  |
| `tldextract`      | Reliable domain/subdomain parsing             |
| `python-dateutil` | Date parsing for domain registration checks   |

### Tooling

| Tool        | Purpose                                                                            |
| ----------- | ---------------------------------------------------------------------------------- |
| `uv`        | Fast Python package and project manager                                            |
| `honcho`    | Process manager — starts backend and frontend from a single command via `Procfile` |
| `hatchling` | Build backend for the project package                                              |

---

## 8. Project Structure

```
.
├── backend/          FastAPI REST API
├── frontend/         Streamlit UI
├── ml/               Training data + model training / evaluation scripts
├── scripts/          Helper shell scripts (individual process start)
├── Procfile          honcho process definitions (backend + frontend)
├── pyproject.toml    Single source of truth for dependencies (uv)
└── README.md
```

---

## 9. Getting Started

### Prerequisites

- Python ≥ 3.12
- [uv](https://docs.astral.sh/uv/) — install with:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Install dependencies

```bash
uv sync
```

---

## 10. Running the App

The project uses **[honcho](https://honcho.readthedocs.io/)** as a process manager. A single command reads the `Procfile` and starts both the FastAPI backend and the Streamlit frontend in one terminal, with colour-coded, prefixed log output for each process.

```bash
uv run honcho start
```

| Service              | URL                        |
| -------------------- | -------------------------- |
| Streamlit UI         | http://localhost:8501      |
| FastAPI backend      | http://localhost:8000      |
| Interactive API docs | http://localhost:8000/docs |

**What the `Procfile` declares:**

```
backend:  uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
frontend: streamlit run frontend/streamlit_app.py --server.port 8501
```

To run only one process:

```bash
uv run honcho start backend
uv run honcho start frontend
```

To stop all processes press `Ctrl + C` — honcho sends `SIGTERM` to every managed process cleanly.

---

## 11. API Reference

### `POST /api/v1/detect`

Analyse a URL for phishing indicators.

**Request body**

```json
{
  "url": "https://example.com"
}
```

**Response**

```json
{
  "url": "https://example.com",
  "prediction": "legitimate",
  "confidence": 0.9314,
  "global_rank": 4821,
  "features": {
    "having_IP_Address": 1,
    "URL_Length": 1,
    "Shortining_Service": 1,
    "having_At_Symbol": 1,
    "double_slash_redirecting": 1,
    "Prefix_Suffix": 1,
    "having_Sub_Domain": 1,
    "SSLfinal_State": 1,
    "Domain_registeration_length": 1,
    "Favicon": 1,
    "port": 1,
    "HTTPS_token": 1,
    "Request_URL": 1,
    "URL_of_Anchor": 1,
    "Links_in_tags": 0,
    "SFH": 1,
    "Submitting_to_email": 1,
    "Abnormal_URL": 1,
    "Redirect": -1,
    "on_mouseover": 1,
    "RightClick": 1,
    "popUpWidnow": 1,
    "Iframe": -1,
    "age_of_domain": 1,
    "DNSRecord": 1,
    "web_traffic": 1,
    "Page_Rank": 1,
    "Google_Index": 1,
    "Links_pointing_to_page": 1,
    "Statistical_report": 1
  }
}
```

**Feature values**

| Value | Meaning                |
| ----- | ---------------------- |
| `1`   | Legitimate indicator   |
| `0`   | Suspicious / uncertain |
| `-1`  | Phishing indicator     |

### `GET /api/v1/health`

```json
{ "status": "ok" }
```

---

## 12. Re-training the Model

The repository ships with a pre-trained model. To re-train from scratch using the included dataset:

```bash
uv run python -m ml.training.train_model
```

This will:

1. Load `ml/datasets/dataset.csv`
2. Split 70/30 train/test
3. Train `SVC(kernel='rbf', probability=True)`
4. Print accuracy and classification report
5. Save the new model to `backend/app/models/svm_model.pkl`

To evaluate the saved model against the full dataset:

```bash
uv run python -m ml.evaluation.evaluate_model
```
