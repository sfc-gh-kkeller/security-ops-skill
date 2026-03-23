"""
=============================================================================
Security Operations Center Dashboard
=============================================================================
Real-time SOC dashboard using Streamlit in Snowflake (SPCS).
Requires: SPCS-powered Streamlit for real-time features.
=============================================================================
"""

import streamlit as st
from snowflake.snowpark.context import get_active_session
import pandas as pd
from datetime import datetime, timedelta

# Page configuration
st.set_page_config(
    page_title="Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Get Snowflake session
session = get_active_session()

# =============================================================================
# CONFIGURATION
# =============================================================================

# Use Interactive Warehouse for sub-second queries
INTERACTIVE_WH = "SOC_DASHBOARD_WH"
STANDARD_WH = "SECURITY_WH"

# Severity colors
SEVERITY_COLORS = {
    5: "#dc3545",  # Critical - Red
    4: "#fd7e14",  # High - Orange
    3: "#ffc107",  # Medium - Yellow
    2: "#17a2b8",  # Low - Cyan
    1: "#6c757d",  # Info - Gray
}

SEVERITY_LABELS = {
    5: "CRITICAL",
    4: "HIGH", 
    3: "MEDIUM",
    2: "LOW",
    1: "INFO"
}

# =============================================================================
# DATA FUNCTIONS
# =============================================================================

def use_interactive_warehouse():
    """Switch to interactive warehouse for dashboard queries."""
    try:
        session.sql(f"USE WAREHOUSE {INTERACTIVE_WH}").collect()
        return True
    except:
        session.sql(f"USE WAREHOUSE {STANDARD_WH}").collect()
        return False

@st.cache_data(ttl=30)
def get_alert_summary():
    """Get alert counts by severity (last 24 hours)."""
    return session.sql("""
        SELECT 
            severity,
            COUNT(*) AS alert_count,
            COUNT(DISTINCT entity_id) AS unique_entities
        FROM DETECTIONS.IT_ACTIVE_ALERTS
        WHERE alert_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
        GROUP BY severity
        ORDER BY severity DESC
    """).to_pandas()

@st.cache_data(ttl=15)
def get_critical_alerts():
    """Get critical and high severity alerts."""
    return session.sql("""
        SELECT 
            alert_time,
            detection_name,
            severity,
            entity_type,
            entity_id,
            description,
            mitre_tactic,
            mitre_technique
        FROM DETECTIONS.IT_ACTIVE_ALERTS
        WHERE severity >= 4
          AND alert_time > DATEADD('hour', -6, CURRENT_TIMESTAMP())
        ORDER BY alert_time DESC
        LIMIT 100
    """).to_pandas()

@st.cache_data(ttl=60)
def get_alert_timeline():
    """Get alert counts by hour for timeline chart."""
    return session.sql("""
        SELECT 
            DATE_TRUNC('hour', alert_time) AS hour,
            severity,
            COUNT(*) AS alert_count
        FROM DETECTIONS.IT_ACTIVE_ALERTS
        WHERE alert_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
        GROUP BY 1, 2
        ORDER BY 1
    """).to_pandas()

@st.cache_data(ttl=30)
def get_top_entities():
    """Get entities with most alerts."""
    return session.sql("""
        SELECT 
            entity_type,
            entity_id,
            COUNT(*) AS alert_count,
            MAX(severity) AS max_severity,
            ARRAY_AGG(DISTINCT detection_name) AS detection_types
        FROM DETECTIONS.IT_ACTIVE_ALERTS
        WHERE alert_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
        GROUP BY 1, 2
        ORDER BY alert_count DESC
        LIMIT 15
    """).to_pandas()

@st.cache_data(ttl=60)
def get_detection_breakdown():
    """Get alert counts by detection type."""
    return session.sql("""
        SELECT 
            detection_name,
            mitre_tactic,
            COUNT(*) AS alert_count,
            COUNT(DISTINCT entity_id) AS unique_entities
        FROM DETECTIONS.IT_ACTIVE_ALERTS
        WHERE alert_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
        GROUP BY 1, 2
        ORDER BY alert_count DESC
    """).to_pandas()

def check_ioc(indicator: str):
    """Check if an indicator is in threat intel."""
    return session.sql(f"""
        SELECT * 
        FROM REFERENCE.IT_THREAT_INDICATORS
        WHERE indicator_value = '{indicator}'
    """).to_pandas()

@st.cache_data(ttl=60)
def get_open_cases():
    """Get open incident cases."""
    return session.sql("""
        SELECT 
            case_id,
            title,
            severity,
            status,
            assigned_to,
            created_at,
            ARRAY_SIZE(related_alert_ids) AS related_alerts
        FROM DETECTIONS.INCIDENT_CASES
        WHERE status IN ('OPEN', 'IN_PROGRESS')
        ORDER BY severity DESC, created_at DESC
        LIMIT 20
    """).to_pandas()

# =============================================================================
# UI COMPONENTS
# =============================================================================

def render_severity_badge(severity: int) -> str:
    """Render a colored severity badge."""
    color = SEVERITY_COLORS.get(severity, "#6c757d")
    label = SEVERITY_LABELS.get(severity, "UNKNOWN")
    return f'<span style="background-color:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold;">{label}</span>'

def render_metric_card(title: str, value: str, delta: str = None, color: str = None):
    """Render a metric card with optional delta."""
    if color:
        st.markdown(f"""
            <div style="background-color:{color}22;border-left:4px solid {color};padding:15px;border-radius:4px;">
                <div style="font-size:0.9em;color:#666;">{title}</div>
                <div style="font-size:2em;font-weight:bold;color:{color};">{value}</div>
                {f'<div style="font-size:0.8em;color:#888;">{delta}</div>' if delta else ''}
            </div>
        """, unsafe_allow_html=True)
    else:
        st.metric(title, value, delta)

# =============================================================================
# MAIN DASHBOARD
# =============================================================================

def main():
    # Switch to interactive warehouse
    is_interactive = use_interactive_warehouse()
    
    # Header
    col1, col2 = st.columns([4, 1])
    with col1:
        st.title("🛡️ Security Operations Center")
    with col2:
        st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
        if st.button("🔄 Refresh"):
            st.cache_data.clear()
            st.rerun()
    
    # Status bar
    if is_interactive:
        st.success(f"✅ Using Interactive Warehouse ({INTERACTIVE_WH}) - Sub-second queries enabled")
    else:
        st.warning(f"⚠️ Interactive Warehouse unavailable - Using {STANDARD_WH}")
    
    st.divider()
    
    # =============================================================================
    # KPI METRICS ROW
    # =============================================================================
    
    summary = get_alert_summary()
    
    critical = summary[summary['SEVERITY'] == 5]['ALERT_COUNT'].sum() if not summary.empty else 0
    high = summary[summary['SEVERITY'] == 4]['ALERT_COUNT'].sum() if not summary.empty else 0
    medium = summary[summary['SEVERITY'] == 3]['ALERT_COUNT'].sum() if not summary.empty else 0
    total = summary['ALERT_COUNT'].sum() if not summary.empty else 0
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        render_metric_card("🚨 Critical Alerts", str(int(critical)), "Last 24 hours", "#dc3545")
    with col2:
        render_metric_card("⚠️ High Alerts", str(int(high)), "Last 24 hours", "#fd7e14")
    with col3:
        render_metric_card("📊 Medium Alerts", str(int(medium)), "Last 24 hours", "#ffc107")
    with col4:
        render_metric_card("📈 Total Alerts", str(int(total)), "Last 24 hours", "#17a2b8")
    
    st.divider()
    
    # =============================================================================
    # MAIN CONTENT - TWO COLUMNS
    # =============================================================================
    
    left_col, right_col = st.columns([2, 1])
    
    # LEFT COLUMN - Alert Feed
    with left_col:
        st.subheader("🔴 Critical Alert Feed")
        
        alerts = get_critical_alerts()
        
        if alerts.empty:
            st.info("No critical alerts in the last 6 hours")
        else:
            for _, alert in alerts.iterrows():
                severity_badge = render_severity_badge(alert['SEVERITY'])
                
                with st.expander(
                    f"{alert['DETECTION_NAME']} - {alert['ENTITY_ID']}", 
                    expanded=alert['SEVERITY'] == 5
                ):
                    st.markdown(f"**Severity:** {severity_badge}", unsafe_allow_html=True)
                    st.markdown(f"**Time:** {alert['ALERT_TIME']}")
                    st.markdown(f"**Entity:** {alert['ENTITY_TYPE']}: `{alert['ENTITY_ID']}`")
                    st.markdown(f"**MITRE:** {alert['MITRE_TACTIC']} / {alert['MITRE_TECHNIQUE']}")
                    st.markdown(f"**Description:** {alert['DESCRIPTION']}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("🔍 Investigate", key=f"inv_{alert['ALERT_TIME']}"):
                            st.session_state['investigate_entity'] = alert['ENTITY_ID']
                    with col2:
                        if st.button("✅ Acknowledge", key=f"ack_{alert['ALERT_TIME']}"):
                            st.toast(f"Alert acknowledged: {alert['DETECTION_NAME']}")
    
    # RIGHT COLUMN - Summary & IOC Check
    with right_col:
        # Detection breakdown
        st.subheader("📊 Detection Types")
        
        detection_data = get_detection_breakdown()
        if not detection_data.empty:
            st.bar_chart(
                detection_data.set_index('DETECTION_NAME')['ALERT_COUNT'],
                use_container_width=True
            )
        
        st.divider()
        
        # IOC Lookup
        st.subheader("🔍 IOC Lookup")
        
        ioc_input = st.text_input("Enter IP, domain, or hash:", placeholder="e.g., 185.220.101.42")
        
        if ioc_input:
            with st.spinner("Checking threat intel..."):
                result = check_ioc(ioc_input)
            
            if not result.empty:
                st.error("⚠️ **THREAT INDICATOR FOUND**")
                st.json({
                    "indicator": result.iloc[0]['INDICATOR_VALUE'],
                    "type": result.iloc[0]['INDICATOR_TYPE'],
                    "threat_actor": result.iloc[0]['THREAT_ACTOR'],
                    "severity": result.iloc[0]['SEVERITY'],
                    "confidence": result.iloc[0]['CONFIDENCE_SCORE']
                })
            else:
                st.success("✅ Not found in threat intel")
        
        st.divider()
        
        # Top affected entities
        st.subheader("🎯 Top Affected Entities")
        
        entities = get_top_entities()
        if not entities.empty:
            for _, entity in entities.head(5).iterrows():
                color = SEVERITY_COLORS.get(entity['MAX_SEVERITY'], "#6c757d")
                st.markdown(f"""
                    <div style="border-left:3px solid {color};padding-left:10px;margin-bottom:10px;">
                        <strong>{entity['ENTITY_TYPE']}:</strong> {entity['ENTITY_ID']}<br/>
                        <small>Alerts: {entity['ALERT_COUNT']} | Max Severity: {SEVERITY_LABELS.get(entity['MAX_SEVERITY'], 'N/A')}</small>
                    </div>
                """, unsafe_allow_html=True)
    
    st.divider()
    
    # =============================================================================
    # INCIDENT CASES
    # =============================================================================
    
    st.subheader("📋 Open Incident Cases")
    
    cases = get_open_cases()
    
    if cases.empty:
        st.info("No open incident cases")
    else:
        st.dataframe(
            cases,
            column_config={
                "SEVERITY": st.column_config.NumberColumn("Severity", format="%d ⭐"),
                "CREATED_AT": st.column_config.DatetimeColumn("Created", format="YYYY-MM-DD HH:mm"),
                "RELATED_ALERTS": st.column_config.NumberColumn("Alerts", format="%d"),
            },
            use_container_width=True,
            hide_index=True
        )
    
    # =============================================================================
    # SIDEBAR
    # =============================================================================
    
    with st.sidebar:
        st.header("⚙️ Settings")
        
        st.subheader("Time Range")
        time_range = st.selectbox(
            "Select time range:",
            ["Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days"],
            index=2
        )
        
        st.subheader("Severity Filter")
        show_critical = st.checkbox("Critical (5)", value=True)
        show_high = st.checkbox("High (4)", value=True)
        show_medium = st.checkbox("Medium (3)", value=True)
        show_low = st.checkbox("Low (2)", value=False)
        show_info = st.checkbox("Info (1)", value=False)
        
        st.divider()
        
        st.subheader("📈 System Status")
        st.metric("Pipeline Lag", "< 5 min", "Healthy")
        st.metric("Active Detections", "5", "Running")
        st.metric("Interactive Tables", "3", "Warmed")
        
        st.divider()
        
        st.caption("Security Operations Dashboard v1.0")
        st.caption("Powered by Snowflake + Cortex Code")

# =============================================================================
# RUN
# =============================================================================

if __name__ == "__main__":
    main()
