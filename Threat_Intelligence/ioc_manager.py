"""
Threat_Intelligence/ioc_manager.py
Manages a local list of Indicators of Compromise (malicious IPs, domains,
file hashes, and suspicious user-agent strings) and checks log records
against them. Ships with a small static seed list; in production this
would sync from feeds like AbuseIPDB, AlienVault OTX, or MISP.
"""

import json
import os

IOC_FILE = os.path.join(os.path.dirname(__file__), "ioc_feed.json")

# Seed IOC data (illustrative examples commonly used in security training material)
DEFAULT_IOCS = {
    "malicious_ips": [
        "185.220.101.7",
        "45.146.164.110",
        "89.248.165.52",
        "194.26.29.156",
    ],
    "malicious_domains": [
        "evil-c2.example",
        "phishing-portal.example",
    ],
    "suspicious_user_agents": [
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "curl/7.0",
        "python-requests/2.0",
    ],
}


def _load_iocs() -> dict:
    if os.path.exists(IOC_FILE):
        with open(IOC_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_IOCS


def _save_iocs(data: dict):
    with open(IOC_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


class IOCManager:
    def __init__(self):
        self.data = _load_iocs()

    def reload(self):
        self.data = _load_iocs()

    def add_ip(self, ip: str):
        if ip not in self.data["malicious_ips"]:
            self.data["malicious_ips"].append(ip)
            _save_iocs(self.data)

    def check_ip(self, ip: str) -> bool:
        return ip in self.data.get("malicious_ips", [])

    def check_user_agent(self, user_agent: str) -> bool:
        if not user_agent:
            return False
        ua_lower = user_agent.lower()
        return any(sig in ua_lower for sig in self.data.get("suspicious_user_agents", []))

    def check_domain(self, domain: str) -> bool:
        return domain in self.data.get("malicious_domains", [])

    def match_record(self, normalized_record: dict) -> list:
        """Returns a list of matched IOC descriptions for a single normalized log record."""
        matches = []
        src_ip = normalized_record.get("source_ip")
        if src_ip and self.check_ip(src_ip):
            matches.append(f"Source IP {src_ip} matches known-malicious IOC feed")

        extra = normalized_record.get("extra") or {}
        agent = extra.get("agent")
        if agent and self.check_user_agent(agent):
            matches.append(f"Suspicious user agent detected: {agent}")

        return matches
