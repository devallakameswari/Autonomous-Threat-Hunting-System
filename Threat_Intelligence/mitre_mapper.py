"""
Threat_Intelligence/mitre_mapper.py
Maps internal threat_type labels to MITRE ATT&CK technique IDs so
reports and dashboards can reference an industry-standard framework.
"""

MITRE_MAP = {
    "brute_force": {
        "techniques": ["T1110"],
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    "port_scan": {
        "techniques": ["T1046"],
        "name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "sql_injection": {
        "techniques": ["T1190"],
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "web_recon": {
        "techniques": ["T1595"],
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "data_exfiltration": {
        "techniques": ["T1041"],
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    "known_malicious_ip": {
        "techniques": ["T1071"],
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "suspicious_login": {
        "techniques": ["T1078"],
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
    },
    "anomalous_behavior": {
        "techniques": ["T1078", "T1071"],
        "name": "Anomalous Activity",
        "tactic": "Multiple",
    },
    "ml_flagged": {
        "techniques": ["T1071"],
        "name": "ML-Flagged Suspicious Traffic",
        "tactic": "Multiple",
    },
}


def map_threat(threat_type: str) -> dict:
    """Returns MITRE technique info for a given threat_type, with a safe default."""
    return MITRE_MAP.get(
        threat_type,
        {"techniques": ["T1499"], "name": "Unclassified Activity", "tactic": "Unknown"},
    )


def technique_ids_as_string(threat_type: str) -> str:
    info = map_threat(threat_type)
    return ", ".join(info["techniques"])
