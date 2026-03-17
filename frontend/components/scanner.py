from __future__ import annotations

import streamlit as st


def render_scanner() -> tuple[str, bool]:
    """
    Render the URL input form.

    Returns:
        (url, submitted) — url is the entered text, submitted is True when
        the user pressed the scan button.
    """
    with st.form("scan_form", clear_on_submit=False):
        url = st.text_input(
            "URL to scan",
            placeholder="https://example.com",
            label_visibility="collapsed",
        )
        submitted = st.form_submit_button(
            "🔍  Scan URL",
            use_container_width=True,
            type="primary",
        )

    return url.strip(), submitted
