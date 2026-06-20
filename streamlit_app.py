import streamlit as st
import pandas as pd
import random
import datetime
import logging

# =============================================================================
# CONFIGURATION
# =============================================================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

st.set_page_config(
    page_title='Aexis Global Threat Matrix',
    page_icon='🌐',
    layout='wide'
)

# =============================================================================
# STYLING
# =============================================================================
st.markdown("""
<style>
    .stApp { background-color: #0a0a0a; color: #00ff9d; }
    .stButton>button { background-color: #00ff9d; color: black; border: none; }
    .stButton>button:hover { background-color: #00cc7a; }
</style>
""", unsafe_allow_html=True)

# =============================================================================
# DATA GENERATION (cached)
# =============================================================================
@st.cache_data(ttl=3600)
def generate_data() -> pd.DataFrame:
    countries = ['USA', 'DEU', 'FRA', 'GBR', 'BRA', 'MEX', 'JPN', 'NGA', 'IND', 'CAN']
    years = list(range(2018, 2027))
    records = []
    for country in countries:
        base = random.randint(15, 85)
        for year in years:
            volume = max(5, base + (year - 2018) * 4 + random.randint(-10, 25))
            records.append({'Country': country, 'Year': year, 'Threat (M)': volume})
    return pd.DataFrame(records)

df = generate_data()

# =============================================================================
# SIDEBAR
# =============================================================================
st.sidebar.header("🌐 Threat Matrix Controls")
st.sidebar.info("🛡️ AEXIS GLOBAL THREAT MATRIX")
st.sidebar.caption(f"Data as of {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
if st.sidebar.button("🔄 Refresh Data"):
    st.cache_data.clear()
    st.rerun()
st.sidebar.success("📡 Live threat feed: ACTIVE")

# =============================================================================
# MAIN DASHBOARD
# =============================================================================
st.title("🌐 Aexis Sentinel: Global Threat Matrix")
st.caption("International Cybersecurity Intelligence | Autonomous Traffic Anomaly Tracker")
st.markdown("Tracks international malicious payload vectors, injection frequencies, and botnet anomalies.")
st.write("---")

# Filters
col1, col2 = st.columns(2)
with col1:
    years = sorted(df['Year'].unique())
    from_year, to_year = st.slider('Year Range', min(years), max(years), (min(years), max(years)))
with col2:
    countries = df['Country'].unique()
    selected = st.multiselect('Countries', countries, default=['USA', 'DEU', 'FRA', 'GBR', 'JPN', 'NGA'])

if not selected:
    st.warning("Select at least one country.")
    st.stop()

# Filter data
filtered = df[
    (df['Country'].isin(selected)) &
    (df['Year'] >= from_year) &
    (df['Year'] <= to_year)
]

# Chart
st.subheader("📈 Threat Volume Over Time")
if filtered.empty:
    st.info("No data for these criteria.")
else:
    st.line_chart(filtered, x='Year', y='Threat (M)', color='Country')

# Metrics
st.subheader(f"🛡️ Current Threat Footprint ({to_year})")
first_vals = df[df['Year'] == from_year]
last_vals = df[df['Year'] == to_year]

cols = st.columns(min(4, len(selected)))
for i, country in enumerate(selected):
    with cols[i % len(cols)]:
        try:
            first = first_vals[first_vals['Country'] == country]['Threat (M)'].iat[0]
            last = last_vals[last_vals['Country'] == country]['Threat (M)'].iat[0]
            delta = f"{last/first:.2f}x" if first > 0 else "N/A"
        except:
            last, delta = 0, "N/A"
        st.metric(
            label=f"🌐 {country}",
            value=f"{last:,.0f}M",
            delta=delta,
            delta_color="inverse"
        )

st.write("---")
st.caption("🔒 All threat data is synthetic and for demonstration only.")
