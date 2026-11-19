"""
Threat_Detection/rule_engine.py
Deterministic, explainable signature-based detection rules that run
over per-IP aggregated features and raw normalized records. These
catch well-known attack patterns with high confidence and don't
depend on the ML models being trained.
"""

import re
from config import Config

SQLI_PATTERN = re.compile(
    r"(\bunion\b.*\bselect\b)|('.*or.*'.*=.*')|(--\s*$)|(\bdrop\s+table\b)|(\bor\s+1=1\b)",
    re.IGNORECASE,
)


def check_brute_force(ip: str, feature_dict: dict) -> dict:
    if feature_dict.get("failed_login_count", 0) >= Config.BRUTE_FORCE_FAILED_LOGIN_THRESHOLD:
        return {
            "threat_type": "brute_force",
            "title": f"Brute-force login attempts from {ip}",
            "description": (
                f"Observed {feature_dict['failed_login_count']} failed login attempts "
                f"from {ip} against {feature_dict.get('unique_users', 0)} distinct usernames."
            ),
            "severity": "HIGH" if feature_dict["failed_login_count"] >= 15 else "MEDIUM",
            "confidence": 0.9,
            "detection_source": "rule_engine",
        }
    return None


def check_port_scan(ip: str, feature_dict: dict) -> dict:
    if feature_dict.get("unique_dest_ports", 0) >= Config.PORT_SCAN_UNIQUE_PORT_THRESHOLD:
        return {
            "threat_type": "port_scan",
            "title": f"Port scanning activity from {ip}",
            "description": (
                f"{ip} probed {feature_dict['unique_dest_ports']} distinct destination ports "
                f"in a short window, consistent with network reconnaissance."
            ),
            "severity": "MEDIUM",
            "confidence": 0.85,
            "detection_source": "rule_engine",
        }
    return None


def check_web_attack_volume(ip: str, feature_dict: dict) -> dict:
    if feature_dict.get("http_error_count", 0) >= 5 and feature_dict.get("distinct_paths", 0) >= 5:
        return {
            "threat_type": "web_recon",
            "title": f"Web application reconnaissance from {ip}",
            "description": (
                f"{ip} generated {feature_dict['http_error_count']} HTTP error responses across "
                f"{feature_dict['distinct_paths']} distinct paths, indicating path/endpoint fuzzing."
            ),
            "severity": "MEDIUM",
            "confidence": 0.75,
            "detection_source": "rule_engine",
        }
    return None


def check_data_exfiltration(ip: str, feature_dict: dict) -> dict:
    if feature_dict.get("http_request_count", 0) >= 100:
        return {
            "threat_type": "data_exfiltration",
            "title": f"Potential data exfiltration pattern from {ip}",
            "description": (
                f"{ip} generated an unusually high volume of requests "
                f"({feature_dict['http_request_count']}), which may indicate bulk data transfer."
            ),
            "severity": "HIGH",
            "confidence": 0.7,
            "detection_source": "rule_engine",
        }
    return None


def check_sql_injection_in_record(record: dict) -> dict:
    extra = record.get("extra") or {}
    path = extra.get("path", "")
    if path and SQLI_PATTERN.search(path):
        ip = record.get("source_ip")
        return {
            "threat_type": "sql_injection",
            "title": f"SQL injection attempt from {ip}",
            "description": f"Suspicious SQL injection pattern detected in request path: {path}",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "detection_source": "rule_engine",
            "source_ip": ip,
        }
    return None


def run_ip_level_rules(ip: str, feature_dict: dict) -> list:
    """Runs all per-IP aggregate rules and returns any triggered findings."""
    checks = [
        check_brute_force,
        check_port_scan,
        check_web_attack_volume,
        check_data_exfiltration,
    ]
    findings = []
    for check in checks:
        result = check(ip, feature_dict)
        if result:
            result["source_ip"] = ip
            findings.append(result)
    return findings


def run_record_level_rules(normalized_records: list) -> list:
    """Runs per-record rules (e.g. SQLi pattern matching) across all records."""
    findings = []
    for record in normalized_records:
        result = check_sql_injection_in_record(record)
        if result:
            findings.append(result)
    return findings
