from __future__ import annotations

import streamlit as st


def render_results(data: dict) -> None:
    prediction = data.get("prediction", "unknown")
    confidence = data.get("confidence", 0.0)
    url = data.get("url", "")
    rank = data.get("global_rank", -1)

    is_phishing = prediction == "phishing"
    color = "#e63946" if is_phishing else "#2a9d8f"
    icon = "🚨" if is_phishing else "✅"
    label = "PHISHING" if is_phishing else "LEGITIMATE"
    risk_pct = confidence * 100 if is_phishing else (1 - confidence) * 100

    st.markdown(
        f"""
        <div style="
            border:2px solid {color};
            border-radius:12px;
            padding:1.5rem;
            margin-bottom:1rem;
            background:rgba(0,0,0,0.25);
        ">
            <div style="text-align:center;">
                <span style="font-size:3rem;">{icon}</span>
                <h2 style="color:{color}; margin:0.25rem 0;">{label}</h2>
                <p style="color:#ccc; word-break:break-all;">{url}</p>
            </div>
            <hr style="border-color:#444;">
            <div style="display:flex; justify-content:space-around; text-align:center;">
                <div>
                    <p style="color:#aaa; margin:0;">Confidence</p>
                    <h3 style="color:{color}; margin:0;">{confidence * 100:.1f}%</h3>
                </div>
                <div>
                    <p style="color:#aaa; margin:0;">Risk Score</p>
                    <h3 style="color:{color}; margin:0;">{risk_pct:.1f}%</h3>
                </div>
                <div>
                    <p style="color:#aaa; margin:0;">Global Rank</p>
                    <h3 style="color:#f1faee; margin:0;">{"#" + str(rank) if rank > 0 else "N/A"}</h3>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
