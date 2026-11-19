"""
Attack_Correlation/attack_chain.py
Groups individual threat findings that share a source IP (and fall
within a correlation time window) into a single "attack chain" — e.g.
recon -> brute force -> successful login -> exfiltration — so analysts
see the bigger picture instead of isolated alerts.
"""

from collections import defaultdict
from config import Config

# Rough kill-chain ordering used to sort a chain's stages logically.
STAGE_ORDER = {
    "port_scan": 1,
    "web_recon": 1,
    "brute_force": 2,
    "sql_injection": 2,
    "suspicious_login": 3,
    "known_malicious_ip": 3,
    "anomalous_behavior": 3,
    "ml_flagged": 3,
    "data_exfiltration": 4,
}


def correlate_by_source_ip(findings: list) -> list:
    """
    Groups findings by source_ip into attack chains. Each chain summarizes
    the sequence of threat_types observed for that IP, ordered by kill-chain stage.

    Returns a list of:
        {
            "source_ip": ...,
            "stages": ["port_scan", "brute_force", ...],
            "finding_count": int,
            "max_severity": str,
            "findings": [ ...original finding dicts... ],
        }
    """
    by_ip = defaultdict(list)
    for f in findings:
        ip = f.get("source_ip")
        if ip:
            by_ip[ip].append(f)

    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    chains = []

    for ip, ip_findings in by_ip.items():
        if len(ip_findings) < 2:
            continue  # a single finding isn't really a "chain"

        sorted_findings = sorted(
            ip_findings, key=lambda f: STAGE_ORDER.get(f["threat_type"], 99)
        )
        stages = [f["threat_type"] for f in sorted_findings]
        max_severity = max(
            (f["severity"] for f in ip_findings), key=lambda s: severity_rank.get(s, 0)
        )

        chains.append({
            "source_ip": ip,
            "stages": stages,
            "finding_count": len(ip_findings),
            "max_severity": max_severity,
            "findings": sorted_findings,
        })

    return chains


def summarize_chain(chain: dict) -> str:
    """Human-readable one-line summary of an attack chain, for dashboards/reports."""
    stage_str = " -> ".join(chain["stages"])
    return (
        f"{chain['source_ip']} progressed through {chain['finding_count']} stages "
        f"({stage_str}), peak severity {chain['max_severity']}."
    )
