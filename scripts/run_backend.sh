#!/usr/bin/env bash
# Start the FastAPI backend
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "Starting Phish.io FastAPI backend…"
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
