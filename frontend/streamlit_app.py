"""
Phish.io — Streamlit frontend.

Calls the FastAPI backend at BACKEND_URL (default: http://localhost:8000).
"""
from __future__ import annotations

import os
import time

import requests
import streamlit as st

from frontend.components.header import render_header
from frontend.components.results import render_results
from frontend.components.scanner import render_scanner
from frontend.components.visualizations import render_confidence_gauge, render_feature_chart

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

st.set_page_config(
    page_title="Phish.io — Phishing Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Dark theme overrides ─────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    body, .stApp { background-color: #0d1117; color: #f1faee; }
    .stTextInput > div > input {
        background: #161b22; color: #f1faee;
        border: 1px solid #30363d; border-radius: 8px;
        font-size: 1.05rem; padding: 0.6rem 1rem;
    }
    .stButton > button {
        background: #e63946; color: white;
        border-radius: 8px; font-weight: 700;
        border: none; padding: 0.6rem 1.5rem;
        font-size: 1rem; transition: 0.2s;
    }
    .stButton > button:hover { background: #c1121f; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Page layout ───────────────────────────────────────────────────────────────
render_header()

url, submitted = render_scanner()

if submitted:
    if not url:
        st.warning("Please enter a URL before scanning.")
    else:
        with st.spinner("Analysing URL — this may take a moment…"):
            start = time.monotonic()
            try:
                response = requests.post(
                    f"{BACKEND_URL}/api/v1/detect",
                    json={"url": url},
                    timeout=60,
                )
                elapsed = time.monotonic() - start

                if response.status_code == 200:
                    data = response.json()

                    # ── Results ──────────────────────────────────────────────
                    render_results(data)

                    st.caption(f"Analysis completed in {elapsed:.1f}s")

                    # ── Visualisations ────────────────────────────────────────
                    with st.expander("📊 Feature Analysis", expanded=True):
                        col1, col2 = st.columns([2, 1])
                        with col1:
                            render_feature_chart(data["features"])
                        with col2:
                            render_confidence_gauge(
                                data["confidence"], data["prediction"]
                            )

                    # ── Raw JSON for debugging ────────────────────────────────
                    with st.expander("🔎 Raw API Response"):
                        st.json(data)

                else:
                    detail = response.json().get("detail", response.text)
                    st.error(f"API error {response.status_code}: {detail}")

            except requests.exceptions.ConnectionError:
                st.error(
                    "Cannot reach the backend API.  "
                    f"Make sure the FastAPI server is running on **{BACKEND_URL}**."
                )
            except requests.exceptions.Timeout:
                st.error("Request timed out. The URL analysis is taking too long.")
            except Exception as exc:
                st.error(f"Unexpected error: {exc}")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <hr style="border-color:#333; margin-top:3rem;">
    <p style="text-align:center; color:#555; font-size:0.85rem;">
        Phish.io · SVM-based phishing detection ·
        <a href="https://github.com" style="color:#457b9d;">GitHub</a>
    </p>
    """,
    unsafe_allow_html=True,
)
