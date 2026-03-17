#!/usr/bin/env bash
# Start the Streamlit frontend
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "Starting Phish.io Streamlit frontend…"
streamlit run frontend/streamlit_app.py --server.port 8501
