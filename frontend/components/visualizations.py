from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

# Human-readable labels for each feature
FEATURE_LABELS: dict[str, str] = {
    "having_IP_Address": "IP in URL",
    "URL_Length": "URL Length",
    "Shortining_Service": "URL Shortener",
    "having_At_Symbol": "@ Symbol",
    "double_slash_redirecting": "// Redirect",
    "Prefix_Suffix": "Dash in Domain",
    "having_Sub_Domain": "Sub-domains",
    "SSLfinal_State": "SSL Certificate",
    "Domain_registeration_length": "Domain Reg. Length",
    "Favicon": "Favicon Source",
    "port": "Non-standard Port",
    "HTTPS_token": "HTTPS Token",
    "Request_URL": "External Resources",
    "URL_of_Anchor": "Anchor Destinations",
    "Links_in_tags": "Links in Tags",
    "SFH": "Form Handler",
    "Submitting_to_email": "Email Submission",
    "Abnormal_URL": "Abnormal URL",
    "Redirect": "Redirect Count",
    "on_mouseover": "Mouse-over Script",
    "RightClick": "Right-click Disabled",
    "popUpWidnow": "Pop-up Window",
    "Iframe": "IFrame Usage",
    "age_of_domain": "Domain Age",
    "DNSRecord": "DNS Record",
    "web_traffic": "Web Traffic",
    "Page_Rank": "Page Rank",
    "Google_Index": "Google Index",
    "Links_pointing_to_page": "Backlinks",
    "Statistical_report": "Statistical Report",
}


def _value_to_color(v: int) -> str:
    if v == 1:
        return "#2a9d8f"   # green → safe
    if v == 0:
        return "#e9c46a"   # yellow → suspicious
    return "#e63946"        # red → phishing indicator


def render_feature_chart(features: dict) -> None:
    """Bar chart showing per-feature assessment."""
    labels = [FEATURE_LABELS.get(k, k) for k in features]
    values = list(features.values())
    colors = [_value_to_color(v) for v in values]

    fig = go.Figure(
        go.Bar(
            x=labels,
            y=values,
            marker_color=colors,
            text=[{1: "Safe", 0: "Suspicious", -1: "Phishing"}.get(v, str(v)) for v in values],
            textposition="outside",
        )
    )
    fig.update_layout(
        title="Feature Assessment",
        xaxis_title="Feature",
        yaxis=dict(tickvals=[-1, 0, 1], ticktext=["Phishing", "Suspicious", "Safe"]),
        template="plotly_dark",
        height=480,
        margin=dict(b=160),
        xaxis_tickangle=-45,
    )
    st.plotly_chart(fig, use_container_width=True)


def render_confidence_gauge(confidence: float, prediction: str) -> None:
    """Gauge chart showing detection confidence."""
    color = "#e63946" if prediction == "phishing" else "#2a9d8f"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=round(confidence * 100, 1),
            title={"text": "Detection Confidence", "font": {"size": 18}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": color},
                "steps": [
                    {"range": [0, 40], "color": "#1a1a2e"},
                    {"range": [40, 70], "color": "#16213e"},
                    {"range": [70, 100], "color": "#0f3460"},
                ],
                "threshold": {
                    "line": {"color": "white", "width": 2},
                    "thickness": 0.75,
                    "value": 50,
                },
            },
            number={"suffix": "%", "font": {"size": 28}},
        )
    )
    fig.update_layout(template="plotly_dark", height=280)
    st.plotly_chart(fig, use_container_width=True)
