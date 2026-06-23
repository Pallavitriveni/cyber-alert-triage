import sqlite3
import uuid
import datetime
import pandas as pd
import streamlit as st

# Set page configuration first before any other Streamlit commands
st.set_page_config(page_title="Enterprise SOC Hub", page_icon="🛡️", layout="wide")

# --- 0. SECURITY & AUTHENTICATION BARRIER ---
def login_screen():
    """Renders a secure login overlay. Returns True if authenticated."""
    # Custom enterprise styling for the login card
    st.markdown("""
        <style>
        .login-box {
            padding: 2rem;
            border-radius: 10px;
            background-color: #1E1E1E;
            border: 1px solid #333333;
        }
        </style>
    """, unsafe_allow_html=True)
    
    st.write("## 🛡️ Enterprise Security Operations Gate")
    st.caption("Authorized Personnel Access Only — Activity is Logged and Audited")
    
    with st.container():
        username = st.text_input("Analyst ID / Username")
        password = st.text_input("Security Passphrase / Token", type="password")
        login_btn = st.button("🔐 Authenticate Session", use_container_width=True)
        
        if login_btn:
            # Corporate Hardcoded Credentials (In production, these would be hashed or tied to LDAP/SSO)
            if username == "pallavi_secures" and password == "SOC_Analyst_2026":
                st.session_state['authenticated'] = True
                st.success("Session Verified. Initializing environment...")
                st.rerun()
            else:
                st.error("Authentication Failure: Invalid Username or Passphrase.")
                st.session_state['authenticated'] = False

# Manage session state for login persistence
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False

if not st.session_state['authenticated']:
    login_screen()
    st.stop() # CRITICAL: Freezes the execution of the rest of the file until authenticated

# --- THE REST OF YOUR EXISTING CODE CONTINUES BELOW ---
# (Your original init_db(), inject_mock_alerts(), layouts, and charts stay exactly where they are!)

# --- 1. DATABASE SETUP ---
def init_db():
    """Initializes the SQLite database and creates the alerts table if it doesn't exist."""
    conn = sqlite3.connect("triage_workspace.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            rule_name TEXT,
            source_ip TEXT,
            severity TEXT,
            status TEXT DEFAULT 'New',
            analyst TEXT DEFAULT 'Unassigned',
            notes TEXT DEFAULT ''
        )
    ''')
    conn.commit()
    conn.close()

def update_alert_in_db(alert_id, status, analyst, notes):
    """Updates a specific alert's triage details in the database."""
    conn = sqlite3.connect("triage_workspace.db")
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE alerts 
        SET status = ?, analyst = ?, notes = ? 
        WHERE id = ?
    ''', (status, analyst, notes, alert_id))
    conn.commit()
    conn.close()

def inject_mock_alerts():
    """Seeds the database with mock data if it's completely empty."""
    conn = sqlite3.connect("triage_workspace.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    if cursor.fetchone()[0] == 0:
        mock_data = [
            (str(uuid.uuid4())[:8], '2026-06-23 10:14:22', 'Brute Force Attempt', '192.168.1.45', 'High'),
            (str(uuid.uuid4())[:8], '2026-06-23 11:02:15', 'SQL Injection Detected', '10.0.0.12', 'Critical'),
            (str(uuid.uuid4())[:8], '2026-06-23 11:45:00', 'Phishing Domain Accessed', '172.16.5.89', 'Medium')
        ]
        cursor.executemany('''
            INSERT INTO alerts (id, timestamp, rule_name, source_ip, severity, status, analyst, notes)
            VALUES (?, ?, ?, ?, ?, 'New', 'Unassigned', '')
        ''', mock_data)
        conn.commit()
    conn.close()

# Initialize Database
init_db()
inject_mock_alerts()

# --- 2. UI LAYOUT & SIEM INGESTION ---
st.title("🛡️ Enterprise SOC Triage Workspace")
st.caption("Real-time collaborative incident management dashboard")

# Sidebar for controls and integrations
with st.sidebar:
    st.header("⚡ SIEM Integrations")
    st.caption("Connect live security telemetry pipelines")
    
    # Active Connection Indicator
    st.success("🟢 Connected to Wazuh API")
    
    # The Ingestion Trigger Button
    if st.button("📥 Fetch Latest SIEM Alerts"):
        import datetime
        import random
        
        # Simulated live incoming SIEM alerts
        live_siem_feed = [
            ('Brute Force - Admin Account', '10.0.4.55', 'High'),
            ('Unusual PowerShell Execution', '192.168.10.11', 'Critical'),
            ('AWS IAM Policy Modification', '172.16.44.3', 'Medium'),
            ('Malware Telemetry - Command & Control', '10.100.2.14', 'Critical')
        ]
        
        # Pick a random event to simulate real-time log ingestion
        chosen_alert = random.choice(live_siem_feed)
        new_id = str(uuid.uuid4())[:8]
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Inject the live alert into our real database tracking system
        conn = sqlite3.connect("triage_workspace.db")
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (id, timestamp, rule_name, source_ip, severity, status, analyst, notes)
            VALUES (?, ?, ?, ?, ?, 'New', 'Unassigned', '')
        ''', (new_id, current_time, chosen_alert[0], chosen_alert[1], chosen_alert[2]))
        conn.commit()
        conn.close()
        
        st.toast(f"New alert {new_id} ingested from SIEM pipeline!", icon="🔥")
        st.rerun()

    st.markdown("---")
    st.header("Workspace Controls")
    if st.button("🔄 Refresh Dashboard"):
        st.rerun()
    
    if st.button("⚠️ Reset/Clear Queue Data"):
        conn = sqlite3.connect("triage_workspace.db")
        conn.cursor().execute("DROP TABLE IF EXISTS alerts")
        conn.commit()
        conn.close()
        init_db()
        inject_mock_alerts()
        st.sidebar.success("Queue reset to mock defaults!")
        st.rerun()

# Fetch latest data from local DB
conn = sqlite3.connect("triage_workspace.db")
df_alerts = pd.read_sql_query("SELECT * FROM alerts", conn)
conn.close()

# --- 2.5 REAL-TIME THREAT INTEL VISUALS ---
st.markdown("---")
st.subheader("📊 Real-Time Threat Intelligence Metrics")

if not df_alerts.empty:
    # Create two parallel columns for our visual charts
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        st.markdown("##### 🚨 Incident Severity Distribution")
        # Count occurrences of each severity level
        severity_counts = df_alerts['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        
        # Display a clean bar chart mapping the severity metrics
        st.bar_chart(data=severity_counts, x='Severity', y='Count', use_container_width=True)
        
    with chart_col2:
        st.markdown("##### ⚔️ Top Attack Vectors (Rule Triggers)")
        # Count occurrences of each triggered rule
        rule_counts = df_alerts['rule_name'].value_counts().reset_index()
        rule_counts.columns = ['Detection Rule', 'Alert Count']
        
        # Display a horizontal or vertical area/bar chart for attack vectors
        st.line_chart(data=rule_counts, x='Detection Rule', y='Alert Count', use_container_width=True)
else:
    st.info("No threat data available to generate metrics. Ingest alerts from the SIEM pipeline panel.")

# --- 3. THE LIVE QUEUE VIEW ---
st.subheader("📥 Active Incident Queue")

# Display a clean, high-level summary table of the alerts
st.dataframe(
    df_alerts[['id', 'timestamp', 'rule_name', 'source_ip', 'severity', 'status', 'analyst']],
    use_container_width=True,
    hide_index=True
)

# --- 4. THE TRIAGE WORKBENCH ---
st.markdown("---")
st.subheader("🕵️‍♂️ Analyst Investigation Pane")

# Let the analyst pick which Alert ID they want to investigate
alert_options = df_alerts['id'].tolist()
selected_id = st.selectbox("Select an Incident ID to investigate/triage:", alert_options)

if selected_id:
    # Get details of the selected alert
    alert_details = df_alerts[df_alerts['id'] == selected_id].iloc[0]
    
    # Visual metrics layout
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Triggered Rule", alert_details['rule_name'])
    with col2:
        st.metric("Source IP", alert_details['source_ip'])
    with col3:
        st.metric("Current Status", alert_details['status'])
        
    # Interactive Triage Form
    st.markdown("### Update Incident Lifecycle")
    
    # We use a form so components don't refresh the page until the user hits "Save"
    with st.form("triage_form", clear_on_submit=False):
        status_options = ['New', 'In Progress', 'True Positive (Escalated)', 'False Positive (Closed)']
        current_status_idx = status_options.index(alert_details['status']) if alert_details['status'] in status_options else 0
        
        updated_status = st.selectbox("Incident Status", status_options, index=current_status_idx)
        updated_analyst = st.text_input("Assigned Analyst Name", value=alert_details['analyst'])
        updated_notes = st.text_area("Analyst Investigation Notes / Root Cause Analysis", value=alert_details['notes'])
        
        submit_btn = st.form_submit_button("💾 Save & Commit Changes")
        
        if submit_btn:
            update_alert_in_db(selected_id, updated_status, updated_analyst, updated_notes)
            st.success(f"Incident {selected_id} successfully updated inside the database!")
            st.rerun()
            # --- 5. AUTOMATED INCIDENT REPORT GENERATION ---
    st.markdown("### 📄 Incident Documentation")
    st.caption("Generate an audit-ready compliance report for this incident archive.")
    
    # Construct a clean Markdown report string using the current alert's live database values
    report_content = f"""# INCIDENT TRIAGE REPORT: REQ-{alert_details['id']}
==================================================
**Generated On:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Incident Status:** {alert_details['status']}
**Assigned Investigator:** {alert_details['analyst']}

## 1. Incident Overview
-----------------------
* **Incident ID:** {alert_details['id']}
* **Timestamp:** {alert_details['timestamp']}
* **Triggered Detection Rule:** {alert_details['rule_name']}
* **Severity Level:** {alert_details['severity']}

## 2. Network Telemetry Context
-------------------------------
* **Source/Attacker IP:** {alert_details['source_ip']}
* **Target Environment:** Enterprise Internal Network Segment

## 3. Analyst Investigation & Root Cause Notes
----------------------------------------------
{alert_details['notes'] if alert_details['notes'] else 'No investigation notes provided by the analyst.'}

==================================================
*Confidentiality Notice: This document contains proprietary security telemetry and is intended solely for internal SOC operations.*
"""

    # Streamlit native download button handles file generation instantly on click
    st.download_button(
        label="📥 Export Full Incident Package (.md)",
        data=report_content,
        file_name=f"Incident_Report_{alert_details['id']}.md",
        mime="text/markdown",
        use_container_width=True
    )