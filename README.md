# Phish.io — Phishing Website Detector

A production-grade phishing detection API that uses a trained **Support Vector Machine (SVM)** to classify any URL as phishing, legitimate, or uncertain in real time. Built with FastAPI, SQLAlchemy (async), and PostgreSQL.

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [Objectives](#2-objectives)
3. [How It Works](#3-how-it-works)
4. [Architecture](#4-architecture)
5. [Layer Boundaries](#5-layer-boundaries)
6. [Feature Extraction Engine](#6-feature-extraction-engine)
7. [Machine Learning Model](#7-machine-learning-model)
8. [Database Schema](#8-database-schema)
9. [Tools and Packages](#9-tools-and-packages)
10. [Project Structure](#10-project-structure)
11. [Getting Started](#11-getting-started)
12. [Running the API](#12-running-the-api)
13. [API Reference](#13-api-reference)
14. [Re-training the Model](#14-re-training-the-model)
15. [Database Migrations](#15-database-migrations)

---

## 1. What Is This Project?

Phishing attacks trick users into visiting fraudulent websites that impersonate legitimate services to steal credentials, financial data, or personal information. Traditional blocklist-based defences fail against newly registered phishing domains that have not yet been reported.

**Phish.io** addresses this by analysing the structural and behavioural properties of a URL rather than relying on known-bad lists. Given any URL, the system:

1. Extracts 30 engineered features from the URL structure, DNS/WHOIS records, and live page content
2. Scales the feature vector using a trained `StandardScaler`
3. Passes the scaled vector through an SVM classifier with an RBF kernel
4. Returns a structured prediction with a confidence score, the full feature breakdown, and the model version — all within seconds

Users can also submit corrections to predictions via the feedback endpoint, building a labeled queue for future retraining runs.

---

## 2. Objectives

| # | Objective |
|---|---|
| 1 | Detect phishing websites in real time without relying solely on blocklists |
| 2 | Extract 30 interpretable, URL- and page-level features that explain every decision |
| 3 | Expose detection and feedback as a versioned, observable REST API |
| 4 | Persist labeled URLs and user feedback in PostgreSQL for future retraining |
| 5 | Enforce strict separation of concerns across routes, controllers, services, and database layers |
| 6 | Load and version ML artifacts (model + scaler + metadata) safely at startup |

---

## 3. How It Works

```
Client
  │
  │  POST /api/v1/detect  { "url": "..." }
  ▼
┌─────────────────────────────────────────────────────────┐
│                    routes/v1/predict.py                  │
│  Validates request with Pydantic, delegates to controller│
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│                controllers/v1/predict.py                 │
│  Times the call, maps DetectionResult → DetectionResponse│
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│              services/detection_service.py               │
│  1. feature_extractor.extract(url) → dict[str, float]    │
│  2. scaler.transform(vector)                             │
│  3. model.predict(scaled)                                │
│  4. sigmoid(decision_function) → confidence             │
│  5. Apply confidence threshold → label                   │
└─────────────────────────────────────────────────────────┘
                        │
  ◄─────────────────────┘
  JSON: { label, confidence, features_used, model_version, latency_ms }
```

**Labels**

| Label | Meaning |
|---|---|
| `legitimate` | SVM predicts class 1, confidence ≥ threshold |
| `phishing` | SVM predicts class 0, confidence ≥ threshold |
| `uncertain` | Confidence below the configured threshold (default 0.7) |

---

## 4. Architecture

The backend follows a **five-layer architecture** with strict import boundaries between each layer.

```
app/
├── main.py                        ← FastAPI factory; wires lifespan, middleware, router
│
├── core/                          ← Cross-cutting concerns
│   ├── config.py                  ← Pydantic Settings; all env vars in one place
│   ├── exceptions.py              ← Custom exception hierarchy
│   ├── logging.py                 ← Structured logging configuration
│   └── lifespan.py                ← Startup: load artifacts + init DB pool; Shutdown: dispose pool
│
├── database/                      ← Persistence layer
│   ├── engine.py                  ← Async SQLAlchemy engine, session factory, Base, get_db
│   ├── models/
│   │   ├── url.py                 ← labeled_urls table (UUID pk, JSONB features)
│   │   └── feedback.py            ← feedback_queue table (user corrections)
│   └── migrations/                ← Alembic; never use create_all() in production
│       └── versions/
│
├── schemas/                       ← Pydantic request/response contracts (HTTP shape only)
│   ├── request.py                 ← DetectionRequest · FeedbackRequest
│   └── response.py                ← DetectionResponse · FeedbackResponse · ErrorResponse
│
├── services/                      ← Business logic; no HTTP knowledge
│   ├── feature_extractor.py       ← 30-feature extraction engine; single source of truth
│   ├── detection_service.py       ← DetectionResult dataclass; predict(url, app_state)
│   └── feedback_service.py        ← submit_feedback(); only writer to feedback_queue
│
├── controllers/v1/
│   └── predict.py                 ← handle_predict() · handle_feedback(); maps service results to schemas
│
├── routes/v1/
│   └── predict.py                 ← FastAPI router; POST /detect · POST /feedback · GET /health
│
├── middleware/
│   ├── cors.py                    ← CORS origins from settings
│   └── rate_limit.py              ← In-memory sliding-window rate limiter (60 req/min/IP)
│
├── artifacts/v1/                  ← Versioned ML artifacts; loaded once at startup
│   ├── model.joblib               ← Trained SVM (SVC, RBF kernel)
│   ├── scaler.joblib              ← Fitted StandardScaler
│   └── metadata.json             ← feature_list, feature_order, class_mapping, model_version
│
└── scripts/
    └── run_backend.py             ← Artifact migration + uvicorn launcher
```

**Root-level files**

```
pyproject.toml       ← uv/hatchling manifest; packages = ["app", "ml"]
alembic.ini          ← Points to app/database/migrations
.env.example         ← All supported environment variables with comments
uv.lock              ← Pinned dependency lockfile
ml/                  ← Training pipeline (separate from the API)
  datasets/          ← 11,056-row labeled dataset (30 features + Result)
  training/          ← train_model.py
  evaluation/        ← evaluate_model.py
```

---

## 5. Layer Boundaries

Each layer is only permitted to import from the layers listed in the **Allowed** column. Violations break the separation of concerns contract.

| Layer | Allowed to import from | Must NOT import from |
|---|---|---|
| `routes/` | `schemas`, `controllers`, `database.get_db` | services, ML artifacts, ORM models |
| `controllers/` | `services`, `schemas` | database models, HTTP objects |
| `services/` | `core`, `database.models` (feedback only) | routes, controllers, schemas, HTTP |
| `database/` | `core.config`, SQLAlchemy | services, schemas, routes |
| `core/` | stdlib + third-party only | any other app layer |
| `schemas/` | Pydantic only | database models, services |

**`feature_extractor.py` is the single source of truth** for feature logic. Neither `detection_service.py` nor any training script may duplicate feature extraction code — they must call `feature_extractor.extract()`.

---

## 6. Feature Extraction Engine

`services/feature_extractor.py` extracts 30 features from a URL. The module exposes three public symbols:

| Symbol | Type | Description |
|---|---|---|
| `FEATURE_LIST` | `list[str]` | Canonical ordered list of 30 feature names — shared by training and inference |
| `extract(url)` | `dict[str, float]` | **The only interface callers should use.** Returns a named feature dict |
| `validate_feature_vector(features)` | `bool` | Asserts all 30 features are present and numeric |

Each feature is encoded as `1` (legitimate), `0` (suspicious), or `−1` (phishing indicator).

### URL-based features

| Feature | What it measures |
|---|---|
| `having_IP_Address` | IP literal used in place of a domain name |
| `URL_Length` | Short (<54 chars), medium (54–75), or long (>75) |
| `Shortining_Service` | Matches against 60+ known URL shortening services |
| `having_At_Symbol` | `@` forces browsers to ignore everything before it |
| `double_slash_redirecting` | `//` appears after the 7th character of the URL |
| `Prefix_Suffix` | Hyphen (`-`) in the domain name |
| `having_Sub_Domain` | Number of subdomain levels (dots in domain part) |
| `SSLfinal_State` | HTTPS present vs HTTP |
| `HTTPS_token` | The literal string "https" embedded in the URL |
| `port` | Non-standard port specified explicitly in the domain |

### Domain / WHOIS-based features

| Feature | What it measures |
|---|---|
| `Domain_registeration_length` | Domain expires within 12 months |
| `age_of_domain` | Domain was registered less than 1 year ago |
| `DNSRecord` | WHOIS record exists for the domain |
| `web_traffic` | Global rank < 100,000 |
| `Page_Rank` | Global rank < 10,000 |
| `Google_Index` | URL found in Google search results |
| `Statistical_report` | Domain or resolved IP matches a known-bad list |

### Page-content / behavioural features

| Feature | What it measures |
|---|---|
| `Favicon` | Favicon loaded from an external domain |
| `Request_URL` | % of embedded resources (img, audio, iframe) from external domains |
| `URL_of_Anchor` | % of `<a>` tags pointing outside the domain |
| `Links_in_tags` | % of `<link>` / `<script>` tags with external sources |
| `SFH` | Form `action` targets blank, external, or `mailto:` destination |
| `Submitting_to_email` | Form submits directly to a `mailto:` address |
| `Abnormal_URL` | Domain name absent from the WHOIS response body |
| `Redirect` | Number of HTTP redirects before reaching the final page |
| `on_mouseover` | `onmouseover` used to manipulate the status bar |
| `RightClick` | Right-click disabled via `event.button == 2` |
| `popUpWidnow` | `prompt()` detected in page source |
| `Iframe` | `<iframe>` or `<frameBorder>` tag detected |
| `Links_pointing_to_page` | Count of back-links found in page source |

---

## 7. Machine Learning Model

### Algorithm

**Support Vector Machine (SVM)** with an RBF kernel (`sklearn.svm.SVC`).

SVMs are well-suited to this task because:

- The feature space is fixed-dimension (30) and fully numerical
- The decision boundary between phishing and legitimate is non-linear in feature space
- SVMs generalise well on moderate-sized datasets without overfitting

### Dataset

| Property | Value |
|---|---|
| Source | UCI Phishing Websites Dataset |
| Rows | 11,056 URLs |
| Features | 30 |
| Labels | `−1` (phishing) · `1` (legitimate) |
| Train / test split | 70% / 30% stratified |

### Artifact versioning

All artifacts live in `app/artifacts/<version>/` and are loaded **once at startup** via `core/lifespan.py`. The server refuses to start if any artifact is missing or if the feature count in `metadata.json` does not match the model's expected input dimension.

```
app/artifacts/v1/
├── model.joblib      ← SVC trained on 30 features
├── scaler.joblib     ← StandardScaler fitted on training data
└── metadata.json     ← feature_list, feature_order, class_mapping, model_version, kernel
```

`metadata.json` is the contract between training and inference. After every retraining run, update it to reflect the new model's feature list and training date.

### Confidence scoring

Confidence is derived from the SVM decision function via sigmoid normalisation, which works even when `probability=False`:

```
confidence = 1 / (1 + exp(−decision_function_score))
```

If `predict_proba` is available (model trained with `probability=True`), `max(proba)` is used instead. If confidence falls below `CONFIDENCE_THRESHOLD` (default `0.7`), the label is set to `"uncertain"` regardless of the model's raw prediction.

---

## 8. Database Schema

PostgreSQL is used for persistence. All schema changes go through Alembic — `create_all()` is never used in production code.

### `labeled_urls`

Stores URLs with ground-truth labels for training and retraining.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `url` | Text | The raw URL |
| `label` | Enum | `phishing` · `legitimate` · `unknown` |
| `source` | Text | e.g. `"phishtank"`, `"alexa"`, `"user_report"` |
| `features_json` | JSONB | Feature vector captured at labelling time |
| `created_at` | Timestamptz | Server default `now()` |

### `feedback_queue`

Stores user corrections to model predictions. Reviewed by a human before being promoted to training data.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `url` | Text | The URL that was classified |
| `predicted_label` | Text | What the model said |
| `reported_label` | Text | What the user says it actually is |
| `confidence` | Float | Model confidence at prediction time |
| `prediction_id` | UUID | Links to a future prediction-log table |
| `reviewed` | Boolean | Set by a human reviewer; default `false` |
| `created_at` | Timestamptz | Server default `now()` |

---

## 9. Tools and Packages

### API

| Package | Purpose |
|---|---|
| `fastapi` | Async REST framework with automatic OpenAPI docs |
| `uvicorn` | ASGI server |
| `pydantic` v2 | Request / response validation |
| `pydantic-settings` | Environment variable configuration via `.env` |

### Machine learning

| Package | Purpose |
|---|---|
| `scikit-learn` | `SVC`, `StandardScaler`, metrics, train/test split |
| `numpy` | Numerical operations |
| `joblib` | ML artifact serialisation (model + scaler) |

### Feature extraction

| Package | Purpose |
|---|---|
| `requests` | Fetch live page HTML |
| `beautifulsoup4` | Parse HTML for behavioural features |
| `python-whois` | WHOIS queries for domain age and DNS records |
| `tldextract` | Reliable domain / subdomain parsing |
| `python-dateutil` | Date parsing for registration checks |

### Database

| Package | Purpose |
|---|---|
| `sqlalchemy[asyncio]` | Async ORM and query builder |
| `asyncpg` | PostgreSQL driver for async SQLAlchemy |
| `alembic` | Schema migrations |
| `python-dotenv` | `.env` file loading |

### Tooling

| Tool | Purpose |
|---|---|
| `uv` | Fast Python package and project manager |
| `hatchling` | Build backend for the project package |

---

## 10. Project Structure

```
.
├── app/                     ← FastAPI application (the entire backend)
│   ├── main.py
│   ├── core/                ← config · exceptions · logging · lifespan
│   ├── database/            ← engine · ORM models · Alembic migrations
│   ├── schemas/             ← Pydantic request/response contracts
│   ├── services/            ← feature_extractor · detection_service · feedback_service
│   ├── controllers/v1/      ← handle_predict · handle_feedback
│   ├── routes/v1/           ← POST /detect · POST /feedback · GET /health
│   ├── middleware/          ← cors · rate_limit
│   ├── artifacts/v1/        ← model.joblib · scaler.joblib · metadata.json
│   └── scripts/             ← run_backend.py (artifact migration + server start)
│
├── ml/                      ← Training pipeline (separate from the API)
│   ├── datasets/            ← dataset.csv · phising_urls.xlsx
│   ├── training/            ← train_model.py
│   └── evaluation/          ← evaluate_model.py
│
├── alembic.ini              ← Alembic configuration
├── pyproject.toml           ← uv / hatchling project manifest
├── .env.example             ← All supported environment variables
└── uv.lock                  ← Pinned dependency lockfile
```

---

## 11. Getting Started

### Prerequisites

- Python ≥ 3.12
- [uv](https://docs.astral.sh/uv/) — install with:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

- PostgreSQL (for the feedback and labeled-URL persistence layer)

### Install dependencies

```bash
uv sync
```

### Configure environment

Copy `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://user:password@localhost:5432/phishing_db` | Async PostgreSQL connection string |
| `ARTIFACT_DIR` | `app/artifacts` | Directory containing versioned artifact folders |
| `MODEL_VERSION` | `v1` | Active artifact version (loads `artifacts/<MODEL_VERSION>/`) |
| `CONFIDENCE_THRESHOLD` | `0.7` | Predictions below this become `"uncertain"` |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `DEBUG` | `false` | Enables SQLAlchemy query logging and uvicorn `--reload` |

### Apply database migrations

Ensure PostgreSQL is running and `DATABASE_URL` is set, then:

```bash
uv run alembic upgrade head
```

---

## 12. Running the API

The startup script handles **artifact migration** (converting any legacy `.pkl` to `.joblib` and creating placeholder artifacts if none exist), then launches the server:

```bash
uv run python -m app.scripts.run_backend
```

| Service | URL |
|---|---|
| FastAPI backend | http://localhost:8000 |
| Interactive API docs (Swagger) | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |

To run uvicorn directly (artifacts must already be in place):

```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 13. API Reference

### `POST /api/v1/detect`

Analyse a URL for phishing indicators.

**Request**

```json
{ "url": "https://example.com" }
```

URLs without a scheme are automatically prefixed with `http://`.

**Response**

```json
{
  "url": "https://example.com",
  "label": "legitimate",
  "confidence": 0.9314,
  "features_used": {
    "having_IP_Address": 1.0,
    "URL_Length": 1.0,
    "Shortining_Service": 1.0,
    "having_At_Symbol": 1.0,
    "double_slash_redirecting": 1.0,
    "Prefix_Suffix": 1.0,
    "having_Sub_Domain": 1.0,
    "SSLfinal_State": 1.0,
    "Domain_registeration_length": 1.0,
    "Favicon": 1.0,
    "port": 1.0,
    "HTTPS_token": 1.0,
    "Request_URL": 1.0,
    "URL_of_Anchor": 0.0,
    "Links_in_tags": 0.0,
    "SFH": 1.0,
    "Submitting_to_email": 1.0,
    "Abnormal_URL": 1.0,
    "Redirect": -1.0,
    "on_mouseover": 1.0,
    "RightClick": 1.0,
    "popUpWidnow": 1.0,
    "Iframe": -1.0,
    "age_of_domain": 1.0,
    "DNSRecord": 1.0,
    "web_traffic": 1.0,
    "Page_Rank": 1.0,
    "Google_Index": 1.0,
    "Links_pointing_to_page": 1.0,
    "Statistical_report": 1.0
  },
  "model_version": "v1",
  "latency_ms": 1842.5
}
```

**Feature values**

| Value | Meaning |
|---|---|
| `1.0` | Legitimate indicator |
| `0.0` | Suspicious / borderline |
| `−1.0` | Phishing indicator |

---

### `POST /api/v1/feedback`

Submit a correction for a model prediction. Writes to `feedback_queue` for human review and future retraining.

**Request**

```json
{
  "url": "https://suspicious-login.example.com",
  "predicted_label": "legitimate",
  "reported_label": "phishing",
  "confidence": 0.61
}
```

| Field | Allowed values |
|---|---|
| `predicted_label` | `"phishing"` · `"legitimate"` · `"uncertain"` |
| `reported_label` | `"phishing"` · `"legitimate"` |
| `confidence` | Float in `[0.0, 1.0]` |

**Response**

```json
{
  "received": true,
  "feedback_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "message": "Feedback recorded. Thank you!"
}
```

---

### `GET /api/v1/health`

Returns the current server status and whether ML artifacts are loaded.

**Response**

```json
{
  "status": "ok",
  "model_version": "v1",
  "artifact_loaded": true
}
```

---

## 14. Re-training the Model

The repository ships with a pre-trained model. To re-train from scratch:

```bash
uv run python -m ml.training.train_model
```

After training, update `app/artifacts/v1/` with the new artifacts and update `metadata.json`:

1. Save the new model: `joblib.dump(model, "app/artifacts/v1/model.joblib")`
2. Save the fitted scaler: `joblib.dump(scaler, "app/artifacts/v1/scaler.joblib")`
3. Update `metadata.json` — set `training_date`, confirm `feature_list` and `feature_order` match `FEATURE_LIST` in `feature_extractor.py`, and remove the placeholder `notes` value

To evaluate the model against the full dataset:

```bash
uv run python -m ml.evaluation.evaluate_model
```

> **Important:** `feature_extractor.py` is the single source of truth for feature ordering. Training scripts must use `from app.services.feature_extractor import FEATURE_LIST` to guarantee the column order matches what the model was trained on.

---

## 15. Database Migrations

This project uses **Alembic** for all schema changes. Never call `Base.metadata.create_all()` in production code.

**Apply all pending migrations**

```bash
uv run alembic upgrade head
```

**Create a new migration after changing a model**

```bash
uv run alembic revision --autogenerate -m "describe your change"
```

**Roll back one migration**

```bash
uv run alembic downgrade -1
```

**View migration history**

```bash
uv run alembic history --verbose
```
