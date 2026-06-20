import streamlit as st
import pandas as pd
import math
import random
import datetime
import logging
import hashlib
import time
from typing import List, Tuple, Optional

# ==============================================================================
# 0. CONFIGURATION (load from secrets or environment)
# ==============================================================================
try:
    TARGET_HASH = st.secrets["THREAT_AUTH_HASH"]
except (KeyError, FileNotFoundError):
    # Fallback only for development – change this!
    TARGET_HASH = "4d7d3fcc1d3ab90d07079c7ea411d89c29b8a7dc228a8eb4eabf552f28e2a312"
    logging.warning("THREAT_AUTH_HASH not set. Using insecure default.")

CRYPTO_SALT = st.secrets.get("THREAT_SALT", "AexisThreat_SecureSalt_2026##")
LOG_LEVEL = st.secrets.get("LOG_LEVEL", "INFO")
logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ==============================================================================
# 1. PAGE CONFIG & THEME (consistent dark cyber‑theme)
# ==============================================================================
st.set_page_config(
    page_title='Aexis Global Threat Matrix',
    page_icon='🌐',
    layout="wide"
)

st.markdown("""
<style>
    .stApp {
        background-color: #0a0a0a;
        color: #00ff9d;
    }
    .stButton>button {
        background-color: #00ff9d;
        color: black;
        border: none;
    }
    .stButton>button:hover {
        background-color: #00cc7a;
    }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# 2. SESSION STATE & AUTHENTICATION
# ==============================================================================
def init_session() -> None:
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "last_activity" not in st.session_state:
        st.session_state.last_activity = datetime.datetime.now()
    if "threat_data" not in st.session_state:
        st.session_state.threat_data = None  # will be cached

init_session()

def authenticate(password: str) -> bool:
    salted = password + CRYPTO_SALT
    return hashlib.sha256(salted.encode()).hexdigest() == TARGET_HASH

# Optional authentication gateway – uncomment to enable
# if not st.session_state.authenticated:
#     st.title("🔐 Aexis Threat Matrix – Secure Access")
#     with st.form("auth_form"):
#         pwd = st.text_input("Authorization Key:", type="password", help="Default: admin")
#         if st.form_submit_button("Unlock Dashboard"):
#             if authenticate(pwd):
#                 st.session_state.authenticated = True
#                 st.session_state.last_activity = datetime.datetime.now()
#                 st.success("Access granted.")
#                 st.rerun()
#             else:
#                 st.error("Invalid key.")
#     st.stop()

# Session timeout (optional)
SESSION_TIMEOUT_MINUTES = 30
if st.session_state.authenticated:
    if (datetime.datetime.now() - st.session_state.last_activity).seconds > SESSION_TIMEOUT_MINUTES * 60:
        st.session_state.authenticated = False
        st.warning("Session expired. Please re-authenticate.")
        st.rerun()
    else:
        st.session_state.last_activity = datetime.datetime.now()

# ==============================================================================
# 3. DATA GENERATION (cached)
# ==============================================================================
@st.cache_data(ttl=3600)  # refresh every hour
def generate_synthetic_threat_data() -> pd.DataFrame:
    """Autonomously compiles global threat intelligence matrices.
    Simulates malicious payload events captured across international country nodes.
    """
    countries = ['USA', 'DEU', 'FRA', 'GBR', 'BRA', 'MEX', 'JPN', 'NGA', 'IND', 'CAN']
    years = list(range(2018, 2027))
    
    data_records = []
    for country in countries:
        # Assign a baseline malicious traffic profile per country
        base_threat_multiplier = random.randint(15, 85)
        for year in years:
            yearly_variance = random.randint(-10, 25)
            attack_volume = max(5, base_threat_multiplier + (year - 2018) * 4 + yearly_variance)
            data_records.append({
                'Country Code': country,
                'Year': year,
                'Threat Level (M)': attack_volume
            })
            
    return pd.DataFrame(data_records)

# Load or refresh data
if st.session_state.threat_data is None:
    with st.spinner("Compiling global threat intelligence..."):
        st.session_state.threat_data = generate_synthetic_threat_data()
threat_df = st.session_state.threat_data.copy()

# ==============================================================================
# 4. SIDEBAR CONTROLS (optional, but add refresh option)
# ==============================================================================
st.sidebar.header("🌐 Threat Matrix Controls")
st.sidebar.markdown("---")
st.sidebar.info("🛡️ **AEXIS GLOBAL THREAT MATRIX**")
st.sidebar.caption(f"Data as of {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")

if st.sidebar.button("🔄 Refresh Intelligence", use_container_width=True):
    st.cache_data.clear()
    st.session_state.threat_data = generate_synthetic_threat_data()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.success("📡 Live threat feed: ACTIVE")

# ==============================================================================
# 5. DASHBOARD BRANDING LAYER
# ==============================================================================
st.title("🌐 Aexis Sentinel: Global Threat Matrix")
st.caption("International Cybersecurity Intelligence | Autonomous Traffic Anomaly Tracker")

st.markdown(
    """
    This control interface tracks and monitors international malicious payload vectors, database injection frequencies, 
    and systemic botnet anomalies captured by offline **Aexis Sentinel** perimeter defenses.
    """
)
st.write("---")

# ==============================================================================
# 6. INTERACTIVE CONTROL CORNER
# ==============================================================================
min_year = int(threat_df['Year'].min())
max_year = int(threat_df['Year'].max())

col_controls_1, col_controls_2 = st.columns(2)

with col_controls_1:
    from_year, to_year = st.slider(
        'Select Temporal Observation Window (Years):',
        min_value=min_year,
        max_value=max_year,
        value=[min_year, max_year],
        key="year_slider"
    )

with col_controls_2:
    all_countries = threat_df['Country Code'].unique()
    default_countries = ['USA', 'DEU', 'FRA', 'GBR', 'JPN', 'NGA']
    selected_countries = st.multiselect(
        'Isolate Specific International Infrastructure Nodes:',
        all_countries,
        default=default_countries,
        key="country_select"
    )

# Ensure at least one country is selected
if not selected_countries:
    st.warning("⚠️ Please select at least one country to display threat data.")
    st.stop()

# Filter dataset dynamically
filtered_threat_df = threat_df[
    (threat_df['Country Code'].isin(selected_countries)) &
    (threat_df['Year'] >= from_year) &
    (threat_df['Year'] <= to_year)
]

st.write("---")

# ==============================================================================
# 7. GLOBAL THREAT VISUALIZATION PIPELINE
# ==============================================================================
st.subheader('📈 Vector Density Distribution Over Time', divider='red')

if filtered_threat_df.empty:
    st.info("No data available for the selected criteria.")
else:
    st.line_chart(
        filtered_threat_df,
        x='Year',
        y='Threat Level (M)',
        color='Country Code'
    )

st.write("---")

# ==============================================================================
# 8. CYBER-VOLATILITY METRICS MATRIX
# ==============================================================================
st.subheader(f'🛡️ Live Node Threat Footprint ({to_year})', divider='red')

first_year_df = threat_df[threat_df['Year'] == from_year]
last_year_df = threat_df[threat_df['Year'] == to_year]

# Handle case where no data for selected year
if first_year_df.empty or last_year_df.empty:
    st.warning("Insufficient historical data for the selected year range. Showing current values.")
    first_year_df = threat_df[threat_df['Year'] == min_year]
    last_year_df = threat_df[threat_df['Year'] == max_year]

metric_cols = st.columns(min(4, len(selected_countries)))

for idx, country in enumerate(selected_countries):
    col = metric_cols[idx % len(metric_cols)]
    
    with col:
        try:
            first_val = first_year_df[first_year_df['Country Code'] == country]['Threat Level (M)'].iat[0]
            last_val = last_year_df[last_year_df['Country Code'] == country]['Threat Level (M)'].iat[0]
            
            if first_val > 0:
                growth_factor = f'{last_val / first_val:,.2f}x'
            else:
                growth_factor = "N/A"
            delta_label = f"Volatility Scaling vs {from_year}"
        except (IndexError, ZeroDivisionError):
            last_val = 0
            growth_factor = "N/A"
            delta_label = "Insufficient Data"

        st.metric(
            label=f'🌐 {country} Node Payload Volume',
            value=f'{last_val:,.0f}M Alerts',
            delta=growth_factor,
            delta_color="inverse"  # Red means higher threat, good for cyber UX
        )

# ==============================================================================
# 9. FOOTER
# ==============================================================================
st.caption("🔒 All threat data is synthetic and used for demonstration purposes.")
