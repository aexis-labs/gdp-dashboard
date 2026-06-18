import streamlit as st
import pandas as pd
import math
import random
import datetime

# ==============================================================================
# 1. EMULATED THREAT INTELLIGENCE ENGINE CONFIGURATION
# ==============================================================================
st.set_page_config(
    page_title='Aexis Global Threat Matrix',
    page_icon='🌐',
    layout="wide"
)

@st.cache_data
def generate_synthetic_threat_data():
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
            # Generate fluctuating threat metrics (Simulated Attack Volume in Millions)
            yearly_variance = random.randint(-10, 25)
            attack_volume = max(5, base_threat_multiplier + (year - 2018) * 4 + yearly_variance)
            
            data_records.append({
                'Country Code': country,
                'Year': year,
                'Threat Level (M)': attack_volume
            })
            
    return pd.DataFrame(data_records)

threat_df = generate_synthetic_threat_data()

# ==============================================================================
# 2. DASHBOARD BRANDING LAYER
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
# 3. INTERACTIVE CONTROL CORNER
# ==============================================================================
min_year = int(threat_df['Year'].min())
max_year = int(threat_df['Year'].max())

col_controls_1, col_controls_2 = st.columns(2)

with col_controls_1:
    from_year, to_year = st.slider(
        'Select Temporal Observation Window (Years):',
        min_value=min_year,
        max_value=max_year,
        value=[min_year, max_year]
    )

with col_controls_2:
    all_countries = threat_df['Country Code'].unique()
    selected_countries = st.multiselect(
        'Isolate Specific International Infrastructure Nodes:',
        all_countries,
        ['USA', 'DEU', 'FRA', 'GBR', 'JPN', 'NGA']
    )

# Filter the dataset dynamically based on selections
filtered_threat_df = threat_df[
    (threat_df['Country Code'].isin(selected_countries))
    & (threat_df['Year'] <= to_year)
    & (from_year <= threat_df['Year'])
]

st.write("---")

# ==============================================================================
# 4. GLOBAL THREAT VISUALIZATION PIPELINE
# ==============================================================================
st.subheader('📈 Vector Density Distribution Over Time', divider='red')

if not selected_countries:
    st.warning("Please isolate at least one country node for intelligence matrix analysis.")
else:
    st.line_chart(
        filtered_threat_df,
        x='Year',
        y='Threat Level (M)',
        color='Country Code',
    )

st.write("---")

# ==============================================================================
# 5. CYBER-VOLATILITY METRICS MATRIX
# ==============================================================================
st.subheader(f'🛡️ Live Node Threat Footprint ({to_year})', divider='red')

first_year_df = threat_df[threat_df['Year'] == from_year]
last_year_df = threat_df[threat_df['Year'] == to_year]

metric_cols = st.columns(4)

for idx, country in enumerate(selected_countries):
    col = metric_cols[idx % len(metric_cols)]
    
    with col:
        # Extract threat levels safely
        try:
            first_val = first_year_df[first_year_df['Country Code'] == country]['Threat Level (M)'].iat[0]
            last_val = last_year_df[last_year_df['Country Code'] == country]['Threat Level (M)'].iat[0]
            
            growth_factor = f'{last_val / first_val:,.2f}x'
            delta_label = f"Volatility Scaling vs {from_year}"
        except IndexError:
            last_val = 0
            growth_factor = "N/A"
            delta_label = "Insufficient Data"

        st.metric(
            label=f'🌐 {country} Node Payload Volume',
            value=f'{last_val:,}M Alerts',
            delta=growth_factor,
            delta_color="inverse"  # Red means a higher threat volume scaling up, perfect for cybersecurity tool UX
        )
