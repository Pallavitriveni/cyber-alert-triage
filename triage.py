import json

# 1. Load the security alerts from our JSON file
with open('alerts.json', 'r') as file:
    alerts = json.load(file)

# 2. Create blank containers for our sorted results
true_positives = []
false_positives = []

print("🔍 Starting Security Alert Triage Engine...\n")

# 3. Loop through every single alert and apply security logic
for alert in alerts:
    alert_id = alert['alert_id']
    hostname = alert['hostname']
    rule = alert['rule_name']
    severity = alert['severity']
    
    # RULE 1: Check if the alert is just a noisy office printer
    if "PRINTER" in hostname.upper():
        alert['reason'] = "Automatically filtered: Known harmless printer broadcast."
        false_positives.append(alert)
        
    # RULE 2: Check if it's a high or critical risk alert needing human eyes
    elif severity in ["High", "Critical"]:
        alert['reason'] = f"Escalated: High severity threat ({rule}) detected on {hostname}."
        true_positives.append(alert)
        
    # DEFAULT: If it doesn't match our rules, group it for low-priority review
    else:
        alert['reason'] = "Unclassified low priority noise."
        false_positives.append(alert)

# 4. Display the results clearly in the terminal
print("==================================================")
print(f"🚨 TRUE POSITIVES DETECTED ({len(true_positives)}) - INVESTIGATE IMMEDIATELY:")
print("==================================================")
for tp in true_positives:
    print(f"   [-] Alert ID: {tp['alert_id']} | Host: {tp['hostname']} | Threat: {tp['rule_name']}")
    print(f"       Reason: {tp['reason']}\n")

print("==================================================")
print(f"✅ FALSE POSITIVES FILTERED ({len(false_positives)}) - SAVED TIME:")
print("==================================================")
for fp in false_positives:
    print(f"   [+] Alert ID: {fp['alert_id']} | Host: {fp['hostname']} | Automatically Dropped")
    print(f"       Reason: {fp['reason']}\n")