import streamlit as st
import json
import requests

# Set up the web page
st.set_page_config(page_title="Next-Gen SOC Triage Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Next-Gen Security Alert Triage Center")
st.markdown("This system utilizes rule-based logic, **AbuseIPDB IP Reputation**, and **VirusTotal Malware Hash Intelligence**.")
st.markdown("---")

# 🔴 PLUG IN YOUR API KEYS HERE
ABUSEIPDB_KEY = st.secrets["ABUSEIPDB_KEY"]
VIRUSTOTAL_KEY = st.secrets["VIRUSTOTAL_KEY"]

# Initialize session state for tracking resolved alerts
if 'resolved_alerts' not in st.session_state:
    st.session_state.resolved_alerts = []

# Automated alerting simulation function
def send_incident_alert(alert_id, hostname, threat_name, confidence, source="API Matrix"):
    email_body = f"""
    ======================================================================
    🚨 URGENT: CRITICAL SECURITY INCIDENT CONFIRMED BY TRIAGE ENGINE 🚨
    ======================================================================
    Alert ID: {alert_id}
    Target Host: {hostname}
    Threat Type: {threat_name}
    Verdict Source: {source}
    Live Intel Status: confirmed malicious malicious activity detected.
    Action Required: Isolate host machine from network immediately.
    ======================================================================
    """
    print(email_body)
    return True

# Function 1: Check IP reputation via AbuseIPDB
def check_ip_reputation(ip_address):
    if ip_address.startswith("192.168.") or ip_address.startswith("10."):
        return {"confidence_score": 0, "total_reports": 0, "country": "Internal Network"}
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_KEY}
    
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                "confidence_score": data['abuseConfidenceScore'],
                "total_reports": data['totalReports'],
                "country": data['countryCode']
            }
    except Exception:
        pass
    return {"confidence_score": "Error/No Key", "total_reports": "N/A", "country": "Unknown"}

# Function 2: Check File Hash via VirusTotal V3 API
def check_file_hash(file_hash):
    if not file_hash:
        return None
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-api-key": VIRUSTOTAL_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            attributes = response.json()['data']['attributes']
            stats = attributes['last_analysis_stats']
            return {
                "malicious_count": stats['malicious'],
                "harmless_count": stats['harmless'],
                "undetected_count": stats['undetected'],
                "file_type": attributes.get('type_description', 'Unknown File Type')
            }
        elif response.status_code == 404:
            return {"malicious_count": 0, "harmless_count": 0, "undetected_count": 0, "file_type": "Clean/Unknown Hash"}
    except Exception:
        pass
    return {"malicious_count": "Error", "harmless_count": "Error", "undetected_count": "Error", "file_type": "API Error"}


# Load data
with open('alerts.json', 'r') as file:
    alerts = json.load(file)

true_positives = []
false_positives = []

for alert in alerts:
    if alert['alert_id'] in st.session_state.resolved_alerts:
        continue

    if "PRINTER" in alert['hostname'].upper():
        alert['reason'] = "Automatically filtered: Known harmless printer broadcast."
        false_positives.append(alert)
    elif alert['severity'] in ["High", "Critical"]:
        # Run IP Checks
        intel_ip = check_ip_reputation(alert['source_ip'])
        alert['intel_ip'] = intel_ip
        
        # Run File Hash Checks if present
        hash_present = alert.get('file_hash', None)
        intel_hash = check_file_hash(hash_present) if hash_present else None
        alert['intel_hash'] = intel_hash
        
        alert['reason'] = "Escalated: Validated via automated multiple-intelligence lookup."
        true_positives.append(alert)
        
        # Email notification automation triggers
        if isinstance(intel_ip['confidence_score'], int) and intel_ip['confidence_score'] >= 80:
            send_incident_alert(alert['alert_id'], alert['hostname'], alert['rule_name'], f"IP {intel_ip['confidence_score']}%", "AbuseIPDB")
        if intel_hash and isinstance(intel_hash['malicious_count'], int) and intel_hash['malicious_count'] > 0:
            send_incident_alert(alert['alert_id'], alert['hostname'], alert['rule_name'], f"Hash flag count: {intel_hash['malicious_count']}", "VirusTotal")
            
    else:
        alert['reason'] = "Unclassified low priority noise."
        false_positives.append(alert)

# Layout Setup
col1, col2 = st.columns(2)

with col1:
    st.error(f"🚨 True Positives Requiring Action ({len(true_positives)})")
    for tp in true_positives:
        with st.expander(f"⚠️ {tp['rule_name']} on {tp['hostname']}"):
            st.write(f"**Alert ID:** {tp['alert_id']} | **Severity:** {tp['severity']}")
            st.write(f"**Source IP:** `{tp['source_ip']}` ➡️ **Destination IP:** `{tp['destination_ip']}`")
            
            # Sub-Section A: Display IP Data
            st.markdown("🌐 **Network Intelligence (AbuseIPDB):**")
            st.code(f"• Confidence Score: {tp['intel_ip']['confidence_score']}%\n"
                    f"• Total Reports: {tp['intel_ip']['total_reports']}\n"
                    f"• Country: {tp['intel_ip']['country']}")
            
            # Sub-Section B: Display File Hash Data if available
            if tp.get('intel_hash'):
                st.markdown("🪲 **File Payload Intelligence (VirusTotal):**")
                m_count = tp['intel_hash']['malicious_count']
                
                # Color code based on danger level
                if isinstance(m_count, int) and m_count > 0:
                    st.error(f"🚨 MALWARE DETECTED! Flags: {m_count} Antivirus Engines marked this file as dangerous.")
                else:
                    st.success("✅ File Hash not flagged by Antivirus Engines.")
                    
                st.code(f"• File Classification: {tp['intel_hash']['file_type']}\n"
                        f"• Hash String: {tp['file_hash']}\n"
                        f"• Clean/Undetected Eng: {tp['intel_hash']['undetected_count']}")
                
                if isinstance(m_count, int) and m_count > 5:
                    st.toast(f"🪲 Severe malware detection alert for {tp['alert_id']}!", icon="🚨")

            if st.button(f"✅ Mark Alert {tp['alert_id']} as Remediated", key=tp['alert_id']):
                st.session_state.resolved_alerts.append(tp['alert_id'])
                st.rerun()

with col2:
    st.success(f"✅ Automatically Filtered False Positives ({len(false_positives)})")
    for fp in false_positives:
        with st.expander(f"🟢 {fp['rule_name']} (Dropped)"):
            st.write(f"**Alert ID:** {fp['alert_id']} | **Host:** {fp['hostname']}")
            st.write(f"**Reason:** {fp['reason']}")
