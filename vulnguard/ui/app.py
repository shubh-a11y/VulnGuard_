"""
VulnGuard AI — Streamlit Dashboard.

Provides:
  - Risk Heatmap (treemap of function risk scores)
  - Agent DAG Viewer (pipeline state visualization)
  - Battle Terminal (Red vs Blue side-by-side)
  - Metrics Dashboard (benchmark comparison charts)
"""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

# ── Page config ───────────────────────────────────────────────────────────
st.set_page_config(
    page_title="VulnGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0e1117; }
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid #0f3460;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .metric-value {
        font-size: 2.5em;
        font-weight: 700;
        color: #e94560;
    }
    .metric-label {
        font-size: 0.9em;
        color: #a0a0a0;
        margin-top: 4px;
    }
    .agent-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 16px;
        font-weight: 600;
        font-size: 0.85em;
    }
    .red-badge { background: #e94560; color: white; }
    .blue-badge { background: #0078d4; color: white; }
    .judge-badge { background: #ffa500; color: black; }
    .pass-badge { background: #00c853; color: black; }
    .fail-badge { background: #ff1744; color: white; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ VulnGuard AI")
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigation",
    ["🏠 Overview", "🗺️ Risk Heatmap", "⚔️ Battle Terminal", "📊 Metrics"],
)

# ── Mock data (replaced by API calls in production) ──────────────────────
_mock_scans = [
    {
        "id": "fn_001",
        "file": "auth/login.c",
        "risk_score": 87.5,
        "vulnerability_found": True,
        "vuln_type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "verdict": "PASS",
        "attempts": 1,
    },
    {
        "id": "fn_002",
        "file": "utils/parser.cpp",
        "risk_score": 72.3,
        "vulnerability_found": True,
        "vuln_type": "BUFFER_OVERFLOW",
        "severity": "HIGH",
        "verdict": "PASS",
        "attempts": 2,
    },
    {
        "id": "fn_003",
        "file": "network/socket.c",
        "risk_score": 45.0,
        "vulnerability_found": False,
        "vuln_type": None,
        "severity": None,
        "verdict": "SAFE",
        "attempts": 0,
    },
    {
        "id": "fn_004",
        "file": "crypto/hash.c",
        "risk_score": 91.2,
        "vulnerability_found": True,
        "vuln_type": "WEAK_CRYPTO",
        "severity": "CRITICAL",
        "verdict": "MAX_RETRIES_EXHAUSTED",
        "attempts": 3,
    },
]


# ── Pages ─────────────────────────────────────────────────────────────────

if page == "🏠 Overview":
    st.title("🛡️ VulnGuard AI — Security Command Center")
    st.markdown("*Intelligent vulnerability detection and autonomous remediation*")

    # Metric cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="metric-card"><div class="metric-value">4</div>'
                     '<div class="metric-label">Functions Scanned</div></div>',
                     unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="metric-card"><div class="metric-value">3</div>'
                     '<div class="metric-label">Vulnerabilities Found</div></div>',
                     unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="metric-card"><div class="metric-value">66%</div>'
                     '<div class="metric-label">Patch Success Rate</div></div>',
                     unsafe_allow_html=True)
    with col4:
        st.markdown('<div class="metric-card"><div class="metric-value">~90%</div>'
                     '<div class="metric-label">Token Savings (Triage)</div></div>',
                     unsafe_allow_html=True)

    st.markdown("---")

    # Pipeline DAG
    st.subheader("Pipeline Architecture")
    st.markdown("""
    ```mermaid
    graph LR
        A["📊 ML Triage"] -->|"score ≥ 65"| B["🔴 Red Agent"]
        A -->|"score < 65"| Z["✅ Safe"]
        B -->|"vuln found"| C["🔵 Blue Agent"]
        B -->|"no vuln"| Z2["✅ No Vuln"]
        C --> D["⚖️ Judge Agent"]
        D -->|"PASS"| E["🛡️ Remediated"]
        D -->|"FAIL"| C
        D -->|"max retries"| F["❌ Failed"]
    ```
    """)

    # Recent scans table
    st.subheader("Recent Scan Results")
    for scan in _mock_scans:
        cols = st.columns([3, 2, 2, 2, 1])
        cols[0].write(f"📄 `{scan['file']}`")
        cols[1].write(f"Risk: **{scan['risk_score']}**")
        if scan["vulnerability_found"]:
            cols[2].write(f"🔴 {scan['vuln_type']}")
        else:
            cols[2].write("🟢 Safe")
        verdict = scan["verdict"]
        if verdict == "PASS":
            cols[3].markdown('<span class="agent-badge pass-badge">✅ PATCHED</span>', unsafe_allow_html=True)
        elif verdict == "SAFE":
            cols[3].markdown('<span class="agent-badge pass-badge">✅ SAFE</span>', unsafe_allow_html=True)
        else:
            cols[3].markdown(f'<span class="agent-badge fail-badge">❌ {verdict}</span>', unsafe_allow_html=True)
        cols[4].write(f"×{scan['attempts']}")


elif page == "🗺️ Risk Heatmap":
    st.title("🗺️ Codebase Risk Heatmap")
    st.markdown("Function-level vulnerability risk scores across the repository.")

    # Risk distribution chart
    import random
    risk_data = {s["file"]: s["risk_score"] for s in _mock_scans}
    st.bar_chart(risk_data)

    # Threshold slider
    threshold = st.slider("Risk Threshold", 0, 100, 65)
    st.info(f"Functions above **{threshold}** will be sent to the Red Agent for analysis.")

    # Filter display
    above = [s for s in _mock_scans if s["risk_score"] >= threshold]
    below = [s for s in _mock_scans if s["risk_score"] < threshold]

    col1, col2 = st.columns(2)
    with col1:
        st.subheader(f"🔴 High Risk ({len(above)})")
        for s in above:
            st.error(f"**{s['file']}** — Risk: {s['risk_score']}")
    with col2:
        st.subheader(f"🟢 Low Risk ({len(below)})")
        for s in below:
            st.success(f"**{s['file']}** — Risk: {s['risk_score']}")


elif page == "⚔️ Battle Terminal":
    st.title("⚔️ Red vs Blue — Battle Terminal")
    st.markdown("Side-by-side view of attack analysis and defense patching.")

    selected = st.selectbox("Select Function", [s["file"] for s in _mock_scans if s["vulnerability_found"]])
    scan = next((s for s in _mock_scans if s["file"] == selected), None)

    if scan:
        col_red, col_blue = st.columns(2)

        with col_red:
            st.markdown('<span class="agent-badge red-badge">🔴 RED AGENT — Attacker</span>', unsafe_allow_html=True)
            st.markdown(f"**Vulnerability:** {scan['vuln_type']}")
            st.markdown(f"**Severity:** {scan['severity']}")
            st.code(
                "// Proof-of-Concept Exploit\n"
                f"// Target: {scan['file']}\n"
                "// [Exploit code would appear here]\n"
                'printf("Exploit triggered!\\n");',
                language="c",
            )

        with col_blue:
            st.markdown('<span class="agent-badge blue-badge">🔵 BLUE AGENT — Defender</span>', unsafe_allow_html=True)
            st.markdown(f"**Verdict:** {scan['verdict']}")
            st.markdown(f"**Attempts:** {scan['attempts']}")
            st.code(
                "// Patched Code\n"
                f"// Target: {scan['file']}\n"
                "// [Patched code would appear here]\n"
                "// Using parameterized queries instead of string concat",
                language="c",
            )

        st.markdown("---")
        st.markdown('<span class="agent-badge judge-badge">⚖️ JUDGE — Validator</span>', unsafe_allow_html=True)
        if scan["verdict"] == "PASS":
            st.success("✅ Build passed | Tests passed | Exploit blocked")
        else:
            st.error(f"❌ Validation failed: {scan['verdict']}")


elif page == "📊 Metrics":
    st.title("📊 Benchmark Comparison")
    st.markdown("VulnGuard vs SAST vs Single-LLM performance comparison.")

    # Mock benchmark data
    import pandas as pd

    df = pd.DataFrame({
        "Approach": ["VulnGuard (Multi-Agent)", "Single LLM", "Cppcheck/Semgrep"],
        "Patch Success Rate": [0.85, 0.45, 0.0],
        "Regression Rate": [0.05, 0.25, 0.0],
        "Avg Tokens/Fix": [3200, 1800, 0],
        "Avg Time (s)": [45, 12, 3],
        "Detection Rate": [0.78, 0.62, 0.35],
    })

    st.dataframe(df, use_container_width=True)

    st.subheader("Patch Success Rate Comparison")
    chart_data = df.set_index("Approach")[["Patch Success Rate", "Detection Rate"]]
    st.bar_chart(chart_data)

    st.subheader("Cost vs Quality Tradeoff")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("VulnGuard Token Cost", "3,200 tokens/fix", "+78% more than Single LLM")
    with col2:
        st.metric("VulnGuard Success Rate", "85%", "+40% vs Single LLM", delta_color="normal")
