import streamlit as st


def render_header() -> None:
    st.markdown(
        """
        <div style="text-align:center; padding: 2rem 0 1rem;">
            <h1 style="font-size:2.8rem; font-weight:800; color:#e63946;">
                🛡️ Phish<span style="color:#f1faee;">.</span>io
            </h1>
            <p style="font-size:1.1rem; color:#a8dadc; max-width:600px; margin:auto;">
                AI-powered phishing website detection using Support Vector Machine (SVM)
                machine learning — enter any URL to instantly assess its threat level.
            </p>
        </div>
        <hr style="border:1px solid #333; margin-bottom:1.5rem;">
        """,
        unsafe_allow_html=True,
    )
