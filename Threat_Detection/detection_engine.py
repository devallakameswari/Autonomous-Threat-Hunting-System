"""
detection_engine.py

Autonomous Threat Detection Engine
-----------------------------------

Responsibilities:
    - Parse uploaded log data
    - Normalize log records
    - Extract features
    - Run rule-based detection
    - Run machine-learning detection
    - Run anomaly detection
    - Run IOC / threat-intelligence detection
    - Detect privilege escalation
    - Detect suspicious IPs
    - Detect threats directly from raw log text
    - Classify threats
    - Enrich findings
    - Generate evidence and explanations
    - Generate attack patterns
    - Generate recommendations
    - Correlate attacks
    - Deduplicate findings only within the current analysis
    - Preserve different IP addresses
    - Preserve multiple threats per IP
    - Preserve detection source information
    - Never create "Unknown Threat"

IMPORTANT DATABASE BEHAVIOR
----------------------------

This file intentionally does NOT perform database/global deduplication.

Every call to:

    detect_threats(log_data, source_name)

is treated as a NEW analysis.

Therefore:

    File 1:
        192.168.1.10 -> brute_force

    File 2:
        192.168.1.10 -> brute_force

produces a finding in BOTH analyses.

The Flask/database layer is responsible for creating a new
ThreatEvent for each finding from each upload.

Within ONE analysis, duplicate detector outputs are consolidated
using:

    threat_type + source_ip + destination_ip

Therefore:

    IP A + brute_force
    IP A + powershell_execution

remain two findings.

And:

    IP A + brute_force
    IP B + brute_force

also remain two findings.

DETECTION SOURCE CLASSIFICATION
-------------------------------

DetectionEngine is the orchestrator. It is NOT itself the
specific detector displayed to the user.

Detection sources are classified as:

    suspicious_ip
        -> suspicious IP analysis

    brute_force
        -> authentication_analysis

    network_scan
        -> network_event_analysis

    rule-based threats
        -> threat_detection_rules

    machine-learning findings
        -> machine_learning

    anomaly findings
        -> anomaly_detector

    IOC findings
        -> ioc_manager

    LLM analysis
        -> llm_analysis

A finding may contain multiple detection sources.
For example:

    malware_execution
        detection_sources:
            ["threat_detection_rules", "llm_analysis"]
"""

import re
from collections import defaultdict
from datetime import datetime


# ================================================================
# PROJECT IMPORTS
# ================================================================

from Log_Processing.log_parser import parse_lines
from Log_Processing.log_normalizer import normalize_records

from Log_Processing.feature_extractor import (
    extract_features_per_ip,
    feature_dict_to_vector,
)

from Threat_Detection.rule_engine import (
    run_ip_level_rules,
    run_record_level_rules,
)

from Threat_Detection.threat_classifier import (
    classify_ip,
)

from Threat_Detection.threat_enhancer import (
    detect_privilege_escalation,
    detect_suspicious_ip,
    enrich_threat,
    generate_evidence,
    generate_attack_pattern,
    generate_recommendation,
    generate_explanation,
)

from Machine_learning.model_manager import ModelManager
from Anomaly_Detection.anomaly_detector import AnomalyDetector

from Threat_Intelligence.ioc_manager import IOCManager
from Threat_Intelligence.mitre_mapper import technique_ids_as_string

from Attack_Correlation.attack_chain import (
    correlate_by_source_ip,
    summarize_chain,
)

from LLMs.llm_manager import LLMManager


class DetectionEngine:

    # ============================================================
    # THREAT DEFINITIONS
    # ============================================================

    THREAT_DEFINITIONS = {

        # --------------------------------------------------------
        # Authentication analysis
        # --------------------------------------------------------

        "brute_force": {
            "title": "Brute Force Attack",
            "severity": "CRITICAL",
            "mitre": "T1110",
            "confidence": 0.95,
        },

        # --------------------------------------------------------
        # Rule-based execution
        # --------------------------------------------------------

        "powershell_execution": {
            "title": "PowerShell Execution",
            "severity": "HIGH",
            "mitre": "T1059.001",
            "confidence": 0.94,
        },

        "privilege_escalation": {
            "title": "Privilege Escalation",
            "severity": "HIGH",
            "mitre": "T1548",
            "confidence": 0.92,
        },

        # --------------------------------------------------------
        # Network-event analysis
        # --------------------------------------------------------

        "network_scan": {
            "title": "Network Scanning",
            "severity": "HIGH",
            "mitre": "T1046",
            "confidence": 0.88,
        },

        # --------------------------------------------------------
        # Rule-based threats
        # --------------------------------------------------------

        "reverse_shell": {
            "title": "Reverse Shell",
            "severity": "CRITICAL",
            "mitre": "T1059",
            "confidence": 0.97,
        },

        "malware_execution": {
            "title": "Suspicious File Execution",
            "severity": "HIGH",
            "mitre": "T1204",
            "confidence": 0.90,
        },

        "data_exfiltration": {
            "title": "Data Exfiltration",
            "severity": "HIGH",
            "mitre": "T1041",
            "confidence": 0.91,
        },

        "registry_persistence": {
            "title": "Registry Persistence",
            "severity": "HIGH",
            "mitre": "T1547.001",
            "confidence": 0.93,
        },

        "scheduled_task_persistence": {
            "title": "Scheduled Task Persistence",
            "severity": "HIGH",
            "mitre": "T1053.005",
            "confidence": 0.91,
        },

        "c2_beaconing": {
            "title": "Command and Control Beaconing",
            "severity": "CRITICAL",
            "mitre": "T1071",
            "confidence": 0.96,
        },

        "mass_file_deletion": {
            "title": "Mass File Deletion",
            "severity": "HIGH",
            "mitre": "T1070.004",
            "confidence": 0.89,
        },

        "firewall_tampering": {
            "title": "Firewall Rule Tampering",
            "severity": "HIGH",
            "mitre": "T1562.004",
            "confidence": 0.94,
        },

        # --------------------------------------------------------
        # Suspicious IP analysis
        # --------------------------------------------------------

        "suspicious_ip": {
            "title": "Suspicious IP Activity",
            "severity": "MEDIUM",
            "mitre": "",
            "confidence": 0.69,
        },

        # --------------------------------------------------------
        # ML / anomaly / IOC generic finding
        # --------------------------------------------------------

        "suspicious_activity": {
            "title": "Suspicious Activity",
            "severity": "MEDIUM",
            "mitre": "",
            "confidence": 0.70,
        },
    }

    SEVERITY_ORDER = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    UNKNOWN_TYPES = {
        "",
        "unknown",
        "unknown_threat",
        "unknown threat",
        "none",
        "null",
        "n/a",
        "na",
    }

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(self):

        self.model_manager = ModelManager()
        self.anomaly_detector = AnomalyDetector()
        self.ioc_manager = IOCManager()
        self.llm_manager = LLMManager()

        self.diagnostics = []

    # ============================================================
    # BASIC HELPERS
    # ============================================================

    def _record_diagnostic(self, module, error):

        try:
            self.diagnostics.append({
                "module": str(module),
                "error": str(error),
            })
        except Exception:
            pass

    def _normalize_score(self, value, default=0.0):

        try:

            if value is None:
                return float(default)

            if isinstance(value, str):
                value = value.strip().replace("%", "")

            score = float(value)

            if score > 1:
                score /= 100.0

            return max(
                0.0,
                min(1.0, score),
            )

        except Exception:
            return float(default)

    def _to_bool(self, value, default=False):

        if isinstance(value, bool):
            return value

        if value is None:
            return default

        if isinstance(value, str):

            value = value.strip().lower()

            if value in {
                "true",
                "yes",
                "1",
                "detected",
                "malicious",
                "threat",
            }:
                return True

            if value in {
                "false",
                "no",
                "0",
                "none",
                "normal",
                "benign",
            }:
                return False

        try:
            return bool(value)
        except Exception:
            return default

    def _safe_text(self, value, default=""):

        if value is None:
            return default

        try:
            return str(value)
        except Exception:
            return default

    def _safe_list(self, value):

        if value is None:
            return []

        if isinstance(value, list):
            return value

        if isinstance(value, tuple):
            return list(value)

        if isinstance(value, set):
            return list(value)

        return [value]

    # ============================================================
    # IP HELPERS
    # ============================================================

    def _is_ipv4(self, value):

        if not value:
            return False

        value = self._safe_text(value).strip()

        pattern = (
            r"^(?:"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
            r"){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
        )

        return bool(
            re.match(
                pattern,
                value,
            )
        )

    def _extract_ips_from_text(self, text):

        if not text:
            return []

        pattern = (
            r"\b"
            r"(?:\d{1,3}\.){3}"
            r"\d{1,3}"
            r"\b"
        )

        result = []

        for value in re.findall(
            pattern,
            self._safe_text(text),
        ):

            if (
                self._is_ipv4(value)
                and value not in result
            ):
                result.append(value)

        return result

    def _get_source_ip(self, record):

        if not isinstance(record, dict):
            return None

        keys = (
            "source_ip",
            "src_ip",
            "src",
            "source",
            "client_ip",
            "client",
            "remote_ip",
            "remote",
            "ip",
            "host_ip",
        )

        for key in keys:

            value = record.get(key)

            if value:

                value = self._safe_text(
                    value
                ).strip()

                if self._is_ipv4(value):
                    return value

        return None

    def _get_destination_ip(self, record):

        if not isinstance(record, dict):
            return None

        keys = (
            "dest_ip",
            "dst_ip",
            "destination_ip",
            "destination",
            "dest",
            "target_ip",
        )

        for key in keys:

            value = record.get(key)

            if value:

                value = self._safe_text(
                    value
                ).strip()

                if self._is_ipv4(value):
                    return value

        return None

    def _extract_source_ip_from_line(self, line):

        if not line:
            return None

        text = self._safe_text(line)

        patterns = [

            r"\bsource[_\s-]?ip\s*[:=]\s*"
            r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

            r"\bsrc[_\s-]?ip\s*[:=]\s*"
            r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

            r"\bsrc\s*[:=]\s*"
            r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

            r"\bsource\s*[:=]\s*"
            r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

            r"\bclient[_\s-]?ip\s*[:=]\s*"
            r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

            r"\bclient\s*[:=]\s*"
            r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

            r"\bremote[_\s-]?ip\s*[:=]\s*"
            r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

            r"\bremote\s*[:=]\s*"
            r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        ]

        for pattern in patterns:

            match = re.search(
                pattern,
                text,
                re.IGNORECASE,
            )

            if match:

                ip = match.group(1)

                if self._is_ipv4(ip):
                    return ip

        return None

    # ============================================================
    # THREAT NAME NORMALIZATION
    # ============================================================

    def _normalize_threat_name(self, finding):

        if not isinstance(finding, dict):
            return None

        value = (
            finding.get("threat_type")
            or finding.get("type")
            or finding.get("category")
            or finding.get("rule")
        )

        if not value:
            return None

        text = (
            self._safe_text(value)
            .strip()
            .lower()
            .replace("-", "_")
        )

        aliases = {

            # ----------------------------------------------------
            # Brute force
            # ----------------------------------------------------

            "brute force":
                "brute_force",

            "brute_force_attack":
                "brute_force",

            "bruteforce":
                "brute_force",

            # ----------------------------------------------------
            # PowerShell
            # ----------------------------------------------------

            "powershell":
                "powershell_execution",

            "powershell execution":
                "powershell_execution",

            # ----------------------------------------------------
            # Privilege escalation
            # ----------------------------------------------------

            "privilege escalation":
                "privilege_escalation",

            "privilege-escalation":
                "privilege_escalation",

            # ----------------------------------------------------
            # Network scanning
            # ----------------------------------------------------

            "network scanning":
                "network_scan",

            "network scanning attack":
                "network_scan",

            "port scan":
                "network_scan",

            "port scanning":
                "network_scan",

            # ----------------------------------------------------
            # Reverse shell
            # ----------------------------------------------------

            "reverse shell":
                "reverse_shell",

            "reverse-shell":
                "reverse_shell",

            # ----------------------------------------------------
            # Malware
            # ----------------------------------------------------

            "malware execution":
                "malware_execution",

            "suspicious file execution":
                "malware_execution",

            "malware":
                "malware_execution",

            # ----------------------------------------------------
            # Data exfiltration
            # ----------------------------------------------------

            "data exfiltration":
                "data_exfiltration",

            "data exfil":
                "data_exfiltration",

            # ----------------------------------------------------
            # Registry persistence
            # ----------------------------------------------------

            "registry persistence":
                "registry_persistence",

            # ----------------------------------------------------
            # Scheduled task
            # ----------------------------------------------------

            "scheduled task":
                "scheduled_task_persistence",

            "scheduled task persistence":
                "scheduled_task_persistence",

            # ----------------------------------------------------
            # C2
            # ----------------------------------------------------

            "command and control beaconing":
                "c2_beaconing",

            "c2 beaconing":
                "c2_beaconing",

            "beaconing":
                "c2_beaconing",

            "command_and_control":
                "c2_beaconing",

            # ----------------------------------------------------
            # File deletion
            # ----------------------------------------------------

            "mass file deletion":
                "mass_file_deletion",

            "mass deletion":
                "mass_file_deletion",

            # ----------------------------------------------------
            # Firewall
            # ----------------------------------------------------

            "firewall rule tampering":
                "firewall_tampering",

            "firewall tampering":
                "firewall_tampering",

            # ----------------------------------------------------
            # Suspicious IP
            # ----------------------------------------------------

            "suspicious ip":
                "suspicious_ip",

            "suspicious ip activity":
                "suspicious_ip",

            "suspicious_ip_activity":
                "suspicious_ip",

            # ----------------------------------------------------
            # Suspicious activity
            # ----------------------------------------------------

            "suspicious activity":
                "suspicious_activity",

            "anomalous activity":
                "suspicious_activity",

            "anomaly":
                "suspicious_activity",

            "ioc match":
                "suspicious_activity",
        }

        return aliases.get(
            text,
            text,
        )

    # ============================================================
    # DETECTION SOURCE CLASSIFICATION
    # ============================================================

    def _get_detection_source(self, threat_type):
        """
        Return the actual detector/category responsible for
        identifying the threat.

        DetectionEngine itself is only the orchestrator.

        Mapping:

            suspicious_ip
                -> suspicious_ip

            brute_force
                -> authentication_analysis

            network_scan
                -> network_event_analysis

            rule-based threats
                -> threat_detection_rules
        """

        threat_type = self._safe_text(
            threat_type
        ).strip().lower()

        source_map = {

            # ----------------------------------------------------
            # Suspicious IP analysis
            # ----------------------------------------------------

            "suspicious_ip":
                "suspicious_ip",

            # ----------------------------------------------------
            # Authentication analysis
            # ----------------------------------------------------

            "brute_force":
                "authentication_analysis",

            # ----------------------------------------------------
            # Network-event analysis
            # ----------------------------------------------------

            "network_scan":
                "network_event_analysis",

            # ----------------------------------------------------
            # Rule-based threat detection
            # ----------------------------------------------------

            "powershell_execution":
                "threat_detection_rules",

            "privilege_escalation":
                "threat_detection_rules",

            "reverse_shell":
                "threat_detection_rules",

            "malware_execution":
                "threat_detection_rules",

            "data_exfiltration":
                "threat_detection_rules",

            "registry_persistence":
                "threat_detection_rules",

            "scheduled_task_persistence":
                "threat_detection_rules",

            "c2_beaconing":
                "threat_detection_rules",

            "mass_file_deletion":
                "threat_detection_rules",

            "firewall_tampering":
                "threat_detection_rules",

            # ----------------------------------------------------
            # Generic suspicious activity
            # ----------------------------------------------------

            "suspicious_activity":
                "threat_detection_rules",
        }

        return source_map.get(
            threat_type,
            "threat_detection_rules",
        )

    # ============================================================
    # CURRENT-ANALYSIS DEDUPLICATION KEY
    # ============================================================

    def _finding_key(self, finding):

        if not isinstance(finding, dict):
            return None

        threat_type = self._normalize_threat_name(
            finding
        )

        if not threat_type:
            return None

        source_ip = (
            finding.get("source_ip")
            or finding.get("src_ip")
            or finding.get("ip")
            or ""
        )

        destination_ip = (
            finding.get("dest_ip")
            or finding.get("destination_ip")
            or finding.get("dst_ip")
            or ""
        )

        return (
            str(threat_type).strip().lower(),
            str(source_ip).strip(),
            str(destination_ip).strip(),
        )

    # ============================================================
    # DIRECT FINDING
    # ============================================================

    def _direct_finding(
        self,
        threat_type,
        source_ip=None,
        destination_ip=None,
        evidence=None,
        confidence=None,
    ):

        definition = self.THREAT_DEFINITIONS.get(
            threat_type
        )

        if not definition:
            return None

        if source_ip and not self._is_ipv4(
            source_ip
        ):
            source_ip = None

        if (
            destination_ip
            and not self._is_ipv4(
                destination_ip
            )
        ):
            destination_ip = None

        if confidence is None:
            confidence = definition["confidence"]

        confidence = self._normalize_score(
            confidence,
            definition["confidence"],
        )

        # --------------------------------------------------------
        # Determine actual detector.
        # --------------------------------------------------------

        detection_source = (
            self._get_detection_source(
                threat_type
            )
        )

        return {

            "title":
                definition["title"],

            "threat_type":
                threat_type,

            "severity":
                definition["severity"],

            "mitre":
                definition["mitre"],

            "source_ip":
                source_ip,

            "dest_ip":
                destination_ip,

            "destination_ip":
                destination_ip,

            # ----------------------------------------------------
            # Confidence is ALWAYS stored internally as 0.0-1.0.
            # ----------------------------------------------------

            "confidence":
                confidence,

            # ----------------------------------------------------
            # Primary detection source.
            # ----------------------------------------------------

            "detected_by":
                detection_source,

            "detector":
                detection_source,

            # ----------------------------------------------------
            # Preserve detector history.
            # ----------------------------------------------------

            "detection_sources": [
                detection_source
            ],

            "detectors": [
                detection_source
            ],

            # ----------------------------------------------------
            # Rule detection metadata.
            # ----------------------------------------------------

            "rule_detected":
                True,

            "rule_score":
                confidence,

            "status":
                "OPEN",

            "evidence":
                self._safe_list(
                    evidence
                ),

            "description": (
                f"{definition['title']} "
                "detected in uploaded log data."
            ),

            "explanation": (
                "The uploaded log contains indicators "
                f"associated with "
                f"{definition['title'].lower()}."
            ),

            "recommendation": (
                "Investigate the affected host "
                "and related activity."
            ),
        }

    # ============================================================
    # DIRECT RAW LOG DETECTION
    # ============================================================

    def _direct_threat_detection(self, log_data):

        findings = []

        if log_data is None:
            return findings

        if isinstance(log_data, bytes):

            try:

                log_data = log_data.decode(
                    "utf-8",
                    errors="replace",
                )

            except Exception as exc:

                self._record_diagnostic(
                    "raw_decode",
                    exc,
                )

                return findings

        text = self._safe_text(
            log_data
        )

        if not text.strip():
            return findings

        lines = text.splitlines()

        # --------------------------------------------------------
        # Group lines by explicit SOURCE IP.
        # --------------------------------------------------------

        ip_lines = defaultdict(list)

        for line in lines:

            if not line.strip():
                continue

            source_ip = (
                self._extract_source_ip_from_line(
                    line
                )
            )

            if source_ip:
                ip_lines[source_ip].append(
                    line
                )

        # --------------------------------------------------------
        # If no explicit source IP exists, analyze the whole file.
        # --------------------------------------------------------

        if not ip_lines:

            ip_lines[""] = [
                line
                for line in lines
                if line.strip()
            ]

        # --------------------------------------------------------
        # Detection patterns
        # --------------------------------------------------------

        failed_patterns = [
            r"failed\s+login",
            r"login\s+failed",
            r"failed\s+password",
            r"password\s+failed",
            r"invalid[_\s-]?password",
            r"authentication\s+failed",
            r"ssh[_\s-]?login.*failed",
            r"authentication.*failure",
            r"login.*failure",
            r"failed\s+authentication",
        ]

        privilege_patterns = [
            r"\bprivilege[_\s-]?escalation\b",
            r"\bprivilege\s+escalated\b",
            r"\bsudo\s+su\b",
            r"\bsudo\s+-i\b",
            r"\bsudo\s+root\b",
            r"\brunas\b",
            r"\buser\s*=\s*root\b",
            r"\buser\s*=\s*administrator\b",
            r"\belevated\s+privilege",
            r"\broot\s+privilege",
            r"\badmin(?:istrator)?\s+privilege",
        ]

        scan_patterns = [
            r"\bport[_\s-]?scan\b",
            r"\bport[_\s-]?scanning\b",
            r"\bnetwork[_\s-]?scan\b",
            r"\bnetwork[_\s-]?scanning\b",
            r"\btargets\s*=",
            r"\bscan\s+detected\b",
            r"\bnmap\b",
        ]

        reverse_shell_patterns = [
            r"\breverse[_\s-]?shell\b",
            r"\breverse[_\s-]?connection\b",
            r"\breverse[_\s-]?tcp\b",
        ]

        malware_patterns = [
            r"\bmalware[_\s-]?detected\b",
            r"\bmalware\s+detected\b",
            r"\bmalware\b",
            r"\binvoice\.scr\b",
            r"\bpayload\.exe\b",
            r"\bsuspicious\.payload\b",
            r"\bexecution\s+file\s*=",
            r"\baction\s*=\s*execution\b",
            r"\bfile\s+execution\b",
            r"\bexecutable\s+executed\b",
            r"\brundll32\b",
        ]

        exfil_patterns = [
            r"\bdata[_\s-]?transfer\b",
            r"\blarge[_\s-]?upload\b",
            r"\bexfiltration\b",
            r"\bdata\s+exfiltration\b",
            r"\blarge\s+upload\b",
            r"\bdata\s+uploaded\b",
            r"\bbytes\s+transferred\b",
            r"\b\d+\s*(?:mb|gb|tb)\b.*"
            r"\b(upload|transfer)\b",
        ]

        registry_patterns = [
            r"\bregistry[_\s-]?change\b",
            r"\bregistry[_\s-]?modified\b",
            r"\bregistry[_\s-]?modification\b",
            r"currentversion[\\/]+run",
            r"\bregistry\s+run\s+key\b",
            r"\bautorun\b",
            r"\bautostart\b",
        ]

        scheduled_patterns = [
            r"\bscheduled[_\s-]?task\b",
            r"\bscheduled[_\s-]?task[_\s-]?created\b",
            r"\btask\s+created\b",
            r"\btask\s*=\s*windowsupdate\b",
            r"\bschtasks\b",
            r"\bscheduled\s+job\b",
        ]

        c2_patterns = [
            r"\bbeacon\b",
            r"\bbeaconing\b",
            r"\bc2\b",
            r"\bcommand[_\s-]?and[_\s-]?control\b",
            r"\bcommand-and-control\b",
            r"\bcallback\b",
        ]

        deletion_patterns = [
            r"\bmass[_\s-]?delete\b",
            r"\bmass[_\s-]?deletion\b",
            r"\bmass\s+file\s+deletion\b",
            r"\bfiles?\s+deleted\s*[:=]\s*\d+",
            r"\bdeleted\s+\d+\s+files?\b",
            r"\bdelete\s+count\s*=\s*\d+",
        ]

        firewall_patterns = [
            r"\bfirewall[_\s-]?change\b",
            r"\bfirewall[_\s-]?modified\b",
            r"\bfirewall\s+rule\b",
            r"\ballow[_\s-]?any\b",
            r"\ballow\s+any\b",
            r"0\.0\.0\.0/0",
            r"\bdestination\s*=\s*any\b",
            r"\bsource\s*=\s*0\.0\.0\.0/0\b",
            r"\bfirewall\s+disabled\b",
            r"\bfirewall\s+off\b",
        ]

        # --------------------------------------------------------
        # Helper for pattern matching
        # --------------------------------------------------------

        def matched_lines(
            grouped,
            patterns,
        ):

            return [
                line
                for line in grouped
                if any(
                    re.search(
                        pattern,
                        line,
                        re.IGNORECASE,
                    )
                    for pattern in patterns
                )
            ]

        # --------------------------------------------------------
        # Analyze EVERY IP independently.
        # --------------------------------------------------------

        for source_ip, grouped_lines in ip_lines.items():

            joined = "\n".join(
                grouped_lines
            )

            source = (
                source_ip
                or None
            )

            # ====================================================
            # BRUTE FORCE
            # ====================================================

            failed_count = sum(
                len(
                    re.findall(
                        pattern,
                        joined,
                        re.IGNORECASE,
                    )
                )
                for pattern in failed_patterns
            )

            explicit_bruteforce = bool(
                re.search(
                    r"\bbrute[_\s-]?force\b",
                    joined,
                    re.IGNORECASE,
                )
            )

            if (
                failed_count >= 3
                or explicit_bruteforce
            ):

                evidence = matched_lines(
                    grouped_lines,
                    failed_patterns,
                )

                if (
                    explicit_bruteforce
                    and not evidence
                ):

                    evidence = [
                        line
                        for line in grouped_lines
                        if re.search(
                            r"\bbrute[_\s-]?force\b",
                            line,
                            re.IGNORECASE,
                        )
                    ]

                finding = self._direct_finding(
                    "brute_force",
                    source_ip=source,
                    evidence=evidence,
                    confidence=0.95,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # POWERSHELL
            # ====================================================

            powershell_patterns = [
                r"\bpowershell(?:\.exe)?\b",
                r"[-/]enc(?:odedcommand)?\b",
                r"\bencodedcommand\b",
            ]

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in powershell_patterns
            ):

                finding = self._direct_finding(
                    "powershell_execution",
                    source_ip=source,
                    evidence=matched_lines(
                        grouped_lines,
                        powershell_patterns,
                    ),
                    confidence=0.94,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # PRIVILEGE ESCALATION
            # ====================================================

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in privilege_patterns
            ):

                finding = self._direct_finding(
                    "privilege_escalation",
                    source_ip=source,
                    evidence=matched_lines(
                        grouped_lines,
                        privilege_patterns,
                    ),
                    confidence=0.92,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # NETWORK SCANNING
            # ====================================================

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in scan_patterns
            ):

                finding = self._direct_finding(
                    "network_scan",
                    source_ip=source,
                    evidence=matched_lines(
                        grouped_lines,
                        scan_patterns,
                    ),
                    confidence=0.88,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # REVERSE SHELL
            # ====================================================

            reverse_detected = any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in reverse_shell_patterns
            )

            if not reverse_detected:

                reverse_detected = bool(
                    re.search(
                        r"\bnetwork[_\s-]?connection\b",
                        joined,
                        re.IGNORECASE,
                    )
                    and re.search(
                        r"\bshell\b",
                        joined,
                        re.IGNORECASE,
                    )
                )

            if reverse_detected:

                evidence = matched_lines(
                    grouped_lines,
                    reverse_shell_patterns,
                )

                if not evidence:

                    evidence = [
                        line
                        for line in grouped_lines
                        if (
                            re.search(
                                r"\bnetwork[_\s-]?connection\b",
                                line,
                                re.IGNORECASE,
                            )
                            and re.search(
                                r"\bshell\b",
                                line,
                                re.IGNORECASE,
                            )
                        )
                    ]

                finding = self._direct_finding(
                    "reverse_shell",
                    source_ip=source,
                    evidence=evidence,
                    confidence=0.97,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # MALWARE EXECUTION
            # ====================================================

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in malware_patterns
            ):

                finding = self._direct_finding(
                    "malware_execution",
                    source_ip=source,
                    evidence=matched_lines(
                        grouped_lines,
                        malware_patterns,
                    ),
                    confidence=0.90,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # DATA EXFILTRATION
            # ====================================================

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in exfil_patterns
            ):

                evidence = matched_lines(
                    grouped_lines,
                    exfil_patterns,
                )

                destination_ip = None

                for line in evidence:

                    for ip in self._extract_ips_from_text(
                        line
                    ):

                        if ip != source:
                            destination_ip = ip
                            break

                    if destination_ip:
                        break

                finding = self._direct_finding(
                    "data_exfiltration",
                    source_ip=source,
                    destination_ip=destination_ip,
                    evidence=evidence,
                    confidence=0.91,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # REGISTRY PERSISTENCE
            # ====================================================

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in registry_patterns
            ):

                finding = self._direct_finding(
                    "registry_persistence",
                    source_ip=source,
                    evidence=matched_lines(
                        grouped_lines,
                        registry_patterns,
                    ),
                    confidence=0.93,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # SCHEDULED TASK PERSISTENCE
            # ====================================================

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in scheduled_patterns
            ):

                finding = self._direct_finding(
                    "scheduled_task_persistence",
                    source_ip=source,
                    evidence=matched_lines(
                        grouped_lines,
                        scheduled_patterns,
                    ),
                    confidence=0.91,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # C2 BEACONING
            # ====================================================

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in c2_patterns
            ):

                evidence = matched_lines(
                    grouped_lines,
                    c2_patterns,
                )

                destination_ip = None

                for line in evidence:

                    for ip in self._extract_ips_from_text(
                        line
                    ):

                        if ip != source:
                            destination_ip = ip
                            break

                    if destination_ip:
                        break

                finding = self._direct_finding(
                    "c2_beaconing",
                    source_ip=source,
                    destination_ip=destination_ip,
                    evidence=evidence,
                    confidence=0.96,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # MASS FILE DELETION
            # ====================================================

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in deletion_patterns
            ):

                finding = self._direct_finding(
                    "mass_file_deletion",
                    source_ip=source,
                    evidence=matched_lines(
                        grouped_lines,
                        deletion_patterns,
                    ),
                    confidence=0.89,
                )

                if finding:
                    findings.append(
                        finding
                    )

            # ====================================================
            # FIREWALL TAMPERING
            # ====================================================

            if any(
                re.search(
                    pattern,
                    joined,
                    re.IGNORECASE,
                )
                for pattern in firewall_patterns
            ):

                finding = self._direct_finding(
                    "firewall_tampering",
                    source_ip=source,
                    evidence=matched_lines(
                        grouped_lines,
                        firewall_patterns,
                    ),
                    confidence=0.94,
                )

                if finding:
                    findings.append(
                        finding
                    )

        return findings

    # ============================================================
    # CONFIDENCE
    # ============================================================

    def _calculate_confidence(self, finding):
        """Calculate the final finding confidence as a 0.0-1.0 value."""
        if not isinstance(finding, dict):
            return 0.0

        # A detector can legitimately return confidence=0 while still
        # providing another useful detector score. Treat zero as
        # "not supplied" so valid threats do not become 0%.
        explicit = finding.get("confidence")
        if explicit is not None:
            explicit_score = self._normalize_score(explicit, 0.0)
            if explicit_score > 0.0:
                return explicit_score

        scores = []
        detector_keys = (
            "rule_score", "rule_confidence",
            "ml_score", "ml_confidence",
            "rf_probability", "rf_confidence",
            "anomaly_score", "anomaly_confidence",
            "ioc_score", "ti_score",
            "threat_intelligence_score",
            "correlation_score",
            "llm_score", "llm_confidence",
        )

        for key in detector_keys:
            value = finding.get(key)
            if value is None:
                continue
            score = self._normalize_score(value, 0.0)
            if score > 0.0:
                scores.append(score)

        # Support the normalized detector_scores dictionary used by the
        # dashboard/application layer.
        detector_scores = finding.get("detector_scores")
        if isinstance(detector_scores, dict):
            for value in detector_scores.values():
                score = self._normalize_score(value, 0.0)
                if score > 0.0:
                    scores.append(score)

        # Use the strongest actual detector evidence.
        if scores:
            return max(scores)

        # Last fallback for a known threat type. This prevents a known
        # detected threat from being displayed as 0% only because a
        # detector omitted its confidence field.
        threat_type = self._normalize_threat_name(finding)
        definition = self.THREAT_DEFINITIONS.get(threat_type, {})
        return self._normalize_score(
            definition.get("confidence", 0.0),
            0.0,
        )

    def _classify_detection_algorithm(self, finding):
        """Classify a finding into the dashboard's detector labels.

        Labels are based on detector scores and explicit detector/source
        metadata, not on the threat name and never on the upload channel.
        Multiple contributing detectors become ``Hybrid``.
        """
        if not isinstance(finding, dict):
            return "Rule-Based"

        def score(*keys):
            for key in keys:
                value = finding.get(key)
                if value is None:
                    continue
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    continue
                if value > 1.0 and value <= 100.0:
                    value /= 100.0
                if value > 0:
                    return value
            return 0.0

        sources=[]
        for key in ("detection_sources", "detectors"):
            value=finding.get(key)
            if isinstance(value, (list, tuple, set)):
                sources.extend(str(x).strip().lower() for x in value if str(x).strip())
            elif value:
                sources.append(str(value).strip().lower())

        active=[]
        if score("rule_score", "rule_confidence") > 0:
            active.append("Rule-Based")
        if score("ml_score", "ml_confidence", "rf_probability", "rf_confidence") > 0:
            active.append("ML Model")
        if score("anomaly_score", "anomaly_confidence") > 0:
            active.append("Anomaly Detection")
        if score("correlation_score") > 0:
            active.append("Correlation Engine")
        if score("llm_score") > 0 or self._to_bool(finding.get("llm_analyzed")) or any(s in {"llm_analysis", "llm", "large_language_model"} for s in sources):
            active.append("LLM")

        rule_sources={
            "threat_detection_rules", "authentication_analysis",
            "network_event_analysis", "suspicious_ip", "ioc_manager",
            "rule", "rules", "rule_based", "signature", "signature_match",
        }
        if any(s in rule_sources for s in sources):
            active.append("Rule-Based")

        if any(s in {"correlation", "correlation_engine", "attack_correlation", "attack_chain", "correlator"} for s in sources):
            active.append("Correlation Engine")

        active=list(dict.fromkeys(active))
        if len(active) > 1:
            return "Hybrid"
        if active:
            return active[0]

        source=self._safe_text(finding.get("detected_by") or finding.get("detector"), "").strip().lower()
        if "machine_learning" in source or source in {"ml", "ml_model", "classifier"}:
            return "ML Model"
        if "anomaly" in source:
            return "Anomaly Detection"
        if "llm" in source:
            return "LLM"
        if "correl" in source or "attack_chain" in source:
            return "Correlation Engine"
        return "Rule-Based"


    # ============================================================
    # SEVERITY
    # ============================================================

    def _severity_rank(self, severity):

        return self.SEVERITY_ORDER.get(
            self._safe_text(
                severity,
                "LOW",
            ).upper(),
            1,
        )

    def _best_severity(
        self,
        first,
        second,
    ):

        first = self._safe_text(
            first,
            "LOW",
        ).upper()

        second = self._safe_text(
            second,
            "LOW",
        ).upper()

        if (
            self._severity_rank(second)
            > self._severity_rank(first)
        ):
            return second

        return first

    # ============================================================
    # LIST MERGE
    # ============================================================

    def _merge_lists(
        self,
        first,
        second,
    ):

        result = []

        for value in self._safe_list(
            first
        ):

            if value not in result:
                result.append(value)

        for value in self._safe_list(
            second
        ):

            if value not in result:
                result.append(value)

        return result

    # ============================================================
    # FINDING MERGE
    # ============================================================

    def _merge_findings(
        self,
        existing,
        incoming,
    ):

        if not isinstance(
            existing,
            dict,
        ):
            return incoming

        if not isinstance(
            incoming,
            dict,
        ):
            return existing

        merged = dict(
            existing
        )

        list_keys = {
            "evidence",
            "mitre_techniques",
            "techniques",
            "detectors",
            "detected_by",
            "detection_sources",
            "sources",
            "attack_patterns",
            "recommendations",
        }

        for key, value in incoming.items():

            if value is None:
                continue

            if key in list_keys:

                merged[key] = (
                    self._merge_lists(
                        merged.get(key),
                        value,
                    )
                )

                continue

            if key == "confidence":

                merged[key] = max(
                    self._normalize_score(
                        merged.get(key),
                        0.0,
                    ),
                    self._normalize_score(
                        value,
                        0.0,
                    ),
                )

                continue

            if key == "severity":

                merged[key] = (
                    self._best_severity(
                        merged.get(key),
                        value,
                    )
                )

                continue

            if (
                key not in merged
                or merged.get(key)
                in (None, "")
            ):

                merged[key] = value

        # --------------------------------------------------------
        # Always keep detector/source lists synchronized.
        # --------------------------------------------------------

        primary_detector = (
            merged.get("detected_by")
            or merged.get("detector")
        )

        if primary_detector:

            merged["detected_by"] = (
                self._safe_text(
                    primary_detector
                )
            )

            merged["detector"] = (
                merged["detected_by"]
            )

        merged["detection_sources"] = (
            self._merge_lists(
                merged.get(
                    "detection_sources"
                ),
                merged.get(
                    "detectors"
                ),
            )
        )

        if merged.get("detected_by"):

            merged["detection_sources"] = (
                self._merge_lists(
                    merged.get(
                        "detection_sources"
                    ),
                    [
                        merged[
                            "detected_by"
                        ]
                    ],
                )
            )

        merged["detectors"] = (
            self._merge_lists(
                merged.get(
                    "detectors"
                ),
                merged.get(
                    "detection_sources"
                ),
            )
        )

        # Recalculate the high-level detector after merging all detector
        # contributions. This is what makes combined findings show Hybrid.
        merged["detected_by"] = (
            self._classify_detection_algorithm(merged)
        )
        merged["detector"] = merged["detected_by"]

        return merged

    # ============================================================
    # CURRENT ANALYSIS CONSOLIDATION
    # ============================================================

    def _consolidate_findings(
        self,
        findings,
    ):
        """
        Deduplicate ONLY findings generated during this single
        DetectionEngine.run() call.

        There is intentionally NO database/global deduplication.

        Key:

            threat_type + source_ip + destination_ip
        """

        consolidated = {}

        for original in findings or []:

            if not isinstance(
                original,
                dict,
            ):
                continue

            finding = dict(
                original
            )

            threat_type = (
                self._normalize_threat_name(
                    finding
                )
            )

            if not threat_type:
                continue

            if threat_type in self.UNKNOWN_TYPES:
                continue

            definition = (
                self.THREAT_DEFINITIONS.get(
                    threat_type
                )
            )

            # Only retain known project threat types.
            if definition is None:
                continue

            finding["threat_type"] = (
                threat_type
            )

            if not finding.get("title"):
                finding["title"] = (
                    definition["title"]
                )

            if not finding.get("severity"):
                finding["severity"] = (
                    definition["severity"]
                )

            if not finding.get("mitre"):
                finding["mitre"] = (
                    definition["mitre"]
                )

            source_ip = (
                finding.get("source_ip")
                or finding.get("src_ip")
                or finding.get("ip")
            )

            destination_ip = (
                finding.get("dest_ip")
                or finding.get(
                    "destination_ip"
                )
                or finding.get("dst_ip")
            )

            if source_ip:

                source_ip = (
                    self._safe_text(
                        source_ip
                    ).strip()
                )

                if not self._is_ipv4(
                    source_ip
                ):
                    source_ip = None

            if destination_ip:

                destination_ip = (
                    self._safe_text(
                        destination_ip
                    ).strip()
                )

                if not self._is_ipv4(
                    destination_ip
                ):
                    destination_ip = None

            finding["source_ip"] = (
                source_ip
            )

            finding["dest_ip"] = (
                destination_ip
            )

            finding["destination_ip"] = (
                destination_ip
            )

            finding["confidence"] = (
                self._calculate_confidence(
                    finding
                )
            )

            finding["evidence"] = (
                self._safe_list(
                    finding.get(
                        "evidence"
                    )
                )
            )

            finding["status"] = (
                finding.get("status")
                or "OPEN"
            )

            # ----------------------------------------------------
            # Detection source.
            # ----------------------------------------------------

            existing_source = (
                finding.get(
                    "detected_by"
                )
                or finding.get(
                    "detector"
                )
            )

            threat_source = (
                self._get_detection_source(
                    threat_type
                )
            )

            if not existing_source:
                existing_source = (
                    threat_source
                )

            finding["detected_by"] = (
                self._safe_text(
                    existing_source
                )
            )

            finding["detector"] = (
                finding["detected_by"]
            )

            # ----------------------------------------------------
            # Preserve all detection sources.
            # ----------------------------------------------------

            existing_sources = (
                finding.get(
                    "detection_sources"
                )
            )

            if not isinstance(
                existing_sources,
                list,
            ):

                existing_sources = (
                    self._safe_list(
                        existing_sources
                    )
                )

            finding["detection_sources"] = (
                self._merge_lists(
                    existing_sources,
                    [
                        finding[
                            "detected_by"
                        ],
                        threat_source,
                    ],
                )
            )

            finding["detectors"] = (
                self._merge_lists(
                    finding.get(
                        "detectors"
                    ),
                    finding[
                        "detection_sources"
                    ],
                )
            )

            key = self._finding_key(
                finding
            )

            if key is None:
                continue

            if key in consolidated:

                consolidated[key] = (
                    self._merge_findings(
                        consolidated[key],
                        finding,
                    )
                )

            else:

                consolidated[key] = (
                    finding
                )

        return list(
            consolidated.values()
        )

    # ============================================================
    # NORMALIZE FINDING
    # ============================================================

    def _normalize_finding(
        self,
        finding,
    ):

        if not isinstance(
            finding,
            dict,
        ):
            return None

        finding = dict(
            finding
        )

        threat_type = (
            self._normalize_threat_name(
                finding
            )
        )

        if not threat_type:
            return None

        if threat_type in self.UNKNOWN_TYPES:
            return None

        definition = (
            self.THREAT_DEFINITIONS.get(
                threat_type
            )
        )

        # Do not allow arbitrary detector output
        # to become a database ThreatEvent.
        if definition is None:
            return None

        title = (
            finding.get("title")
            or definition["title"]
        )

        severity = (
            finding.get("severity")
            or definition["severity"]
            or "LOW"
        )

        finding["title"] = (
            self._safe_text(
                title
            )
        )

        finding["threat_type"] = (
            threat_type
        )

        finding["severity"] = (
            self._safe_text(
                severity,
                "LOW",
            ).upper()
        )

        finding["confidence"] = (
            self._calculate_confidence(
                finding
            )
        )

        if not finding.get("mitre"):

            finding["mitre"] = (
                definition.get(
                    "mitre",
                    "",
                )
            )

        source_ip = (
            finding.get("source_ip")
            or finding.get("src_ip")
            or finding.get("ip")
        )

        if source_ip:

            source_ip = (
                self._safe_text(
                    source_ip
                ).strip()
            )

            if not self._is_ipv4(
                source_ip
            ):
                source_ip = None

        destination_ip = (
            finding.get("dest_ip")
            or finding.get(
                "destination_ip"
            )
            or finding.get("dst_ip")
        )

        if destination_ip:

            destination_ip = (
                self._safe_text(
                    destination_ip
                ).strip()
            )

            if not self._is_ipv4(
                destination_ip
            ):
                destination_ip = None

        finding["source_ip"] = (
            source_ip
        )

        finding["dest_ip"] = (
            destination_ip
        )

        finding["destination_ip"] = (
            destination_ip
        )

        finding["evidence"] = (
            self._safe_list(
                finding.get(
                    "evidence"
                )
            )
        )

        finding["status"] = (
            finding.get("status")
            or "OPEN"
        )

        # --------------------------------------------------------
        # Detection source
        # --------------------------------------------------------

        existing_source = (
            finding.get(
                "detected_by"
            )
            or finding.get(
                "detector"
            )
        )

        threat_source = (
            self._get_detection_source(
                threat_type
            )
        )

        if not existing_source:
            existing_source = (
                threat_source
            )

        finding["detected_by"] = (
            self._safe_text(
                existing_source
            )
        )

        finding["detector"] = (
            finding["detected_by"]
        )

        # --------------------------------------------------------
        # Preserve all detector/source information.
        # --------------------------------------------------------

        existing_sources = (
            finding.get(
                "detection_sources"
            )
        )

        if not isinstance(
            existing_sources,
            list,
        ):

            existing_sources = (
                self._safe_list(
                    existing_sources
                )
            )

        finding["detection_sources"] = (
            self._merge_lists(
                existing_sources,
                [
                    finding[
                        "detected_by"
                    ],
                    threat_source,
                ],
            )
        )

        finding["detectors"] = (
            self._merge_lists(
                finding.get(
                    "detectors"
                ),
                finding[
                    "detection_sources"
                ],
            )
        )

        # ``detected_by`` is the dashboard label; raw detector names remain
        # available in detection_sources/detectors.
        finding["detected_by"] = (
            self._classify_detection_algorithm(finding)
        )
        finding["detector"] = finding["detected_by"]

        return finding

    # ============================================================
    # APPEND FINDINGS
    # ============================================================

    def _append_findings(
        self,
        target,
        findings,
    ):

        if not isinstance(
            target,
            list,
        ):
            return

        if findings is None:
            return

        if isinstance(
            findings,
            dict,
        ):
            findings = [
                findings
            ]

        for finding in findings:

            if isinstance(
                finding,
                dict,
            ):
                target.append(
                    finding
                )

    # ============================================================
    # SAFE ENRICHMENT
    # ============================================================

    def _safe_enrich(
        self,
        finding,
    ):

        try:

            result = enrich_threat(
                finding
            )

            if isinstance(
                result,
                dict,
            ):

                return result

            return finding

        except Exception as exc:

            self._record_diagnostic(
                "enrich_threat",
                exc,
            )

            return finding

    # ============================================================
    # LLM
    # ============================================================

    def _analyze_with_llm(
        self,
        finding,
    ):

        if not isinstance(
            finding,
            dict,
        ):
            return finding

        try:

            manager = (
                self.llm_manager
            )

            if manager is None:
                return finding

            result = None

            if hasattr(
                manager,
                "analyze_threat",
            ):

                result = (
                    manager.analyze_threat(
                        finding
                    )
                )

            elif hasattr(
                manager,
                "analyze",
            ):

                result = (
                    manager.analyze(
                        finding
                    )
                )

            elif hasattr(
                manager,
                "analyze_finding",
            ):

                result = (
                    manager.analyze_finding(
                        finding
                    )
                )

            if isinstance(
                result,
                dict,
            ):

                # ------------------------------------------------
                # Copy LLM results.
                # ------------------------------------------------

                for key, value in result.items():

                    if value is not None:
                        finding[key] = value

                # ------------------------------------------------
                # LLM is an additional analysis layer.
                #
                # Do NOT replace the original detector.
                # ------------------------------------------------

                sources = (
                    finding.get(
                        "detection_sources"
                    )
                )

                if not isinstance(
                    sources,
                    list,
                ):

                    sources = (
                        self._safe_list(
                            sources
                        )
                    )

                if (
                    "llm_analysis"
                    not in sources
                ):

                    sources.append(
                        "llm_analysis"
                    )

                finding[
                    "detection_sources"
                ] = sources

                finding["detectors"] = (
                    self._merge_lists(
                        finding.get(
                            "detectors"
                        ),
                        sources,
                    )
                )

                finding[
                    "llm_analyzed"
                ] = True

            return finding

        except Exception as exc:

            self._record_diagnostic(
                "llm",
                exc,
            )

            return finding

    # ============================================================
    # EXPLANATION
    # ============================================================

    def _ensure_explanation(
        self,
        finding,
    ):

        if not isinstance(
            finding,
            dict,
        ):
            return finding

        if finding.get(
            "explanation"
        ):
            return finding

        try:

            result = (
                generate_explanation(
                    finding
                )
            )

            if result:
                finding[
                    "explanation"
                ] = result

        except Exception as exc:

            self._record_diagnostic(
                "generate_explanation",
                exc,
            )

        if not finding.get(
            "explanation"
        ):

            title = finding.get(
                "title",
                "Threat",
            )

            finding[
                "explanation"
            ] = (
                f"{title} was detected based on "
                "evidence present in the uploaded log."
            )

        return finding

    # ============================================================
    # SAFE MODULE CALL
    # ============================================================

    def _safe_detector_call(
        self,
        module_name,
        function,
        *args,
        **kwargs,
    ):

        try:

            return function(
                *args,
                **kwargs,
            )

        except Exception as exc:

            self._record_diagnostic(
                module_name,
                exc,
            )

            return None

    # ============================================================
    # MAIN RUN
    # ============================================================

    def run(
        self,
        log_data,
        source_name=None,
    ):
        """
        Run one completely independent analysis.

        IMPORTANT:

        Every invocation of this method represents one uploaded
        file / analysis.

        No result from a previous invocation is used to suppress
        findings in this invocation.
        """

        self.diagnostics = []

        # ========================================================
        # INPUT
        # ========================================================

        if isinstance(
            log_data,
            bytes,
        ):

            try:

                text = log_data.decode(
                    "utf-8",
                    errors="replace",
                )

            except Exception as exc:

                self._record_diagnostic(
                    "input_decode",
                    exc,
                )

                text = ""

        elif isinstance(
            log_data,
            (list, tuple),
        ):

            # Flask upload helpers return a list of raw log lines. Preserve
            # line boundaries so each record/source IP is parsed independently.
            text = "\n".join(
                self._safe_text(line)
                for line in log_data
                if self._safe_text(line).strip()
            )

        else:

            text = self._safe_text(
                log_data
            )

        if not text.strip():

            return {
                "findings": [],

                "severity_counts": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0,
                },

                "total_threats": 0,

                "processed_records": 0,

                "normalized_records": [],

                "llm_analyzed_count": 0,

                "attack_chain": [],

                "source_name":
                    source_name,

                "timestamp":
                    datetime.utcnow().isoformat(),

                "diagnostics":
                    self.diagnostics,
            }

        # ========================================================
        # ALL RAW FINDINGS FOR THIS UPLOAD
        # ========================================================

        findings = []

        # ========================================================
        # 1. DIRECT RAW LOG DETECTION
        # ========================================================

        direct_findings = (
            self._safe_detector_call(
                "direct_detection",
                self._direct_threat_detection,
                text,
            )
        )

        self._append_findings(
            findings,
            direct_findings,
        )

        # ========================================================
        # 2. PARSER
        # ========================================================

        records = []

        try:

            parsed = parse_lines(
                text.splitlines()
            )

            if parsed is not None:

                if isinstance(
                    parsed,
                    list,
                ):

                    records = parsed

                else:

                    records = list(
                        parsed
                    )

        except Exception as exc:

            self._record_diagnostic(
                "parse_lines",
                exc,
            )

        # ========================================================
        # 3. NORMALIZER
        # ========================================================

        normalized_records = []

        if records:

            try:

                normalized = (
                    normalize_records(
                        records
                    )
                )

                if normalized is not None:

                    if isinstance(
                        normalized,
                        list,
                    ):

                        normalized_records = (
                            normalized
                        )

                    else:

                        normalized_records = list(
                            normalized
                        )

            except Exception as exc:

                self._record_diagnostic(
                    "normalize_records",
                    exc,
                )

        if not normalized_records:

            normalized_records = records

        # ========================================================
        # 4. RECORD-LEVEL RULES
        # ========================================================

        if normalized_records:

            record_findings = (
                self._safe_detector_call(
                    "record_level_rules",
                    run_record_level_rules,
                    normalized_records,
                )
            )

            self._append_findings(
                findings,
                record_findings,
            )

        # ========================================================
        # 5. FEATURES
        # ========================================================

        features_by_ip = {}

        if normalized_records:

            try:

                features_by_ip = (
                    extract_features_per_ip(
                        normalized_records
                    )
                )

                if not isinstance(
                    features_by_ip,
                    dict,
                ):

                    features_by_ip = {}

            except Exception as exc:

                self._record_diagnostic(
                    "feature_extraction",
                    exc,
                )

        # ========================================================
        # 6. PROCESS EVERY IP
        # ========================================================

        if isinstance(
            features_by_ip,
            dict,
        ):

            for ip, ip_features in (
                features_by_ip.items()
            ):

                # ------------------------------------------------
                # IP LEVEL RULES
                # ------------------------------------------------

                ip_findings = (
                    self._safe_detector_call(
                        "ip_level_rules",
                        run_ip_level_rules,
                        ip_features,
                    )
                )

                self._append_findings(
                    findings,
                    ip_findings,
                )

                # ------------------------------------------------
                # CLASSIFIER
                # ------------------------------------------------

                classified = (
                    self._safe_detector_call(
                        "classify_ip",
                        classify_ip,
                        ip_features,
                    )
                )

                self._append_findings(
                    findings,
                    classified,
                )

                # ------------------------------------------------
                # FEATURE VECTOR
                # ------------------------------------------------

                vector = None

                try:

                    vector = (
                        feature_dict_to_vector(
                            ip_features
                        )
                    )

                except Exception as exc:

                    self._record_diagnostic(
                        "feature_vector",
                        exc,
                    )

                # ------------------------------------------------
                # MACHINE LEARNING
                # ------------------------------------------------

                if vector is not None:

                    try:

                        prediction = None

                        if hasattr(
                            self.model_manager,
                            "predict",
                        ):

                            prediction = (
                                self.model_manager.predict(
                                    vector
                                )
                            )

                        elif hasattr(
                            self.model_manager,
                            "predict_threat",
                        ):

                            prediction = (
                                self.model_manager.predict_threat(
                                    vector
                                )
                            )

                        if isinstance(
                            prediction,
                            dict,
                        ):

                            is_threat = (
                                prediction.get(
                                    "is_threat"
                                )
                                or prediction.get(
                                    "threat"
                                )
                            )

                            confidence = (
                                self._normalize_score(
                                    prediction.get(
                                        "confidence"
                                    ),
                                    0.0,
                                )
                            )

                            if (
                                self._to_bool(
                                    is_threat
                                )
                                and confidence > 0
                            ):

                                ml_finding = {

                                    "title":
                                        prediction.get(
                                            "title",
                                            "Suspicious Activity",
                                        ),

                                    "threat_type":
                                        prediction.get(
                                            "threat_type",
                                            "suspicious_activity",
                                        ),

                                    "source_ip":
                                        ip,

                                    "severity":
                                        prediction.get(
                                            "severity",
                                            "MEDIUM",
                                        ),

                                    "confidence":
                                        confidence,

                                    "ml_score":
                                        confidence,

                                    "detected_by":
                                        "machine_learning",

                                    "detector":
                                        "machine_learning",

                                    "detection_sources": [
                                        "machine_learning"
                                    ],

                                    "detectors": [
                                        "machine_learning"
                                    ],

                                    "evidence": [
                                        (
                                            "Machine-learning "
                                            "detector flagged "
                                            "the IP."
                                        )
                                    ],

                                    "status":
                                        "OPEN",
                                }

                                self._append_findings(
                                    findings,
                                    ml_finding,
                                )

                    except Exception as exc:

                        self._record_diagnostic(
                            "machine_learning",
                            exc,
                        )

                # ------------------------------------------------
                # ANOMALY DETECTION
                # ------------------------------------------------

                if vector is not None:

                    try:

                        anomaly_result = None

                        if hasattr(
                            self.anomaly_detector,
                            "predict",
                        ):

                            anomaly_result = (
                                self.anomaly_detector.predict(
                                    vector
                                )
                            )

                        elif hasattr(
                            self.anomaly_detector,
                            "detect",
                        ):

                            anomaly_result = (
                                self.anomaly_detector.detect(
                                    vector
                                )
                            )

                        if isinstance(
                            anomaly_result,
                            dict,
                        ):

                            anomaly_flag = (
                                anomaly_result.get(
                                    "is_anomaly"
                                )
                                or anomaly_result.get(
                                    "anomaly"
                                )
                            )

                            anomaly_score = (
                                anomaly_result.get(
                                    "score"
                                )
                            )

                            if anomaly_score is None:

                                anomaly_score = (
                                    anomaly_result.get(
                                        "anomaly_score"
                                    )
                                )

                            anomaly_score = (
                                self._normalize_score(
                                    anomaly_score,
                                    0.0,
                                )
                            )

                            if (
                                self._to_bool(
                                    anomaly_flag
                                )
                                and anomaly_score > 0
                            ):

                                self._append_findings(
                                    findings,
                                    {

                                        "title":
                                            "Anomalous Activity",

                                        "threat_type":
                                            "suspicious_activity",

                                        "source_ip":
                                            ip,

                                        "severity":
                                            "MEDIUM",

                                        "confidence":
                                            anomaly_score,

                                        "anomaly_score":
                                            anomaly_score,

                                        "detected_by":
                                            "anomaly_detector",

                                        "detector":
                                            "anomaly_detector",

                                        "detection_sources": [
                                            "anomaly_detector"
                                        ],

                                        "detectors": [
                                            "anomaly_detector"
                                        ],

                                        "evidence": [
                                            (
                                                "Anomaly detector "
                                                "flagged unusual "
                                                "activity."
                                            )
                                        ],

                                        "status":
                                            "OPEN",
                                    },
                                )

                    except Exception as exc:

                        self._record_diagnostic(
                            "anomaly_detection",
                            exc,
                        )

                # ------------------------------------------------
                # IOC / THREAT INTELLIGENCE
                # ------------------------------------------------

                try:

                    ioc_result = None

                    if hasattr(
                        self.ioc_manager,
                        "check_ip",
                    ):

                        ioc_result = (
                            self.ioc_manager.check_ip(
                                ip
                            )
                        )

                    elif hasattr(
                        self.ioc_manager,
                        "lookup_ip",
                    ):

                        ioc_result = (
                            self.ioc_manager.lookup_ip(
                                ip
                            )
                        )

                    if isinstance(
                        ioc_result,
                        dict,
                    ):

                        malicious = (
                            ioc_result.get(
                                "malicious"
                            )
                            or ioc_result.get(
                                "is_malicious"
                            )
                            or ioc_result.get(
                                "found"
                            )
                        )

                        if self._to_bool(
                            malicious
                        ):

                            raw_confidence = (
                                ioc_result.get(
                                    "confidence"
                                )
                            )

                            if raw_confidence is None:

                                raw_confidence = (
                                    ioc_result.get(
                                        "score",
                                        0.85,
                                    )
                                )

                            ioc_confidence = (
                                self._normalize_score(
                                    raw_confidence,
                                    0.85,
                                )
                            )

                            self._append_findings(
                                findings,
                                {

                                    "title":
                                        "IOC Match",

                                    "threat_type":
                                        "suspicious_activity",

                                    "source_ip":
                                        ip,

                                    "severity":
                                        "HIGH",

                                    "confidence":
                                        ioc_confidence,

                                    "ioc_score":
                                        ioc_confidence,

                                    "detected_by":
                                        "ioc_manager",

                                    "detector":
                                        "ioc_manager",

                                    "detection_sources": [
                                        "ioc_manager"
                                    ],

                                    "detectors": [
                                        "ioc_manager"
                                    ],

                                    "evidence": [
                                        (
                                            "IP matched "
                                            "threat-intelligence "
                                            "data."
                                        )
                                    ],

                                    "status":
                                        "OPEN",
                                },
                            )

                except Exception as exc:

                    self._record_diagnostic(
                        "ioc_detection",
                        exc,
                    )

        # ========================================================
        # 7. PRIVILEGE ESCALATION
        # ========================================================

        if normalized_records:

            privilege_findings = (
                self._safe_detector_call(
                    "privilege_escalation",
                    detect_privilege_escalation,
                    normalized_records,
                )
            )

            self._append_findings(
                findings,
                privilege_findings,
            )

        # ========================================================
        # 8. SUSPICIOUS IP
        # ========================================================

        if normalized_records:

            suspicious_findings = (
                self._safe_detector_call(
                    "suspicious_ip",
                    detect_suspicious_ip,
                    normalized_records,
                )
            )

            self._append_findings(
                findings,
                suspicious_findings,
            )

        # ========================================================
        # 9. NORMALIZE
        # ========================================================

        normalized_findings = []

        for finding in findings:

            normalized = (
                self._normalize_finding(
                    finding
                )
            )

            if normalized:

                normalized_findings.append(
                    normalized
                )

        findings = (
            normalized_findings
        )

        # ========================================================
        # 10. ENRICH
        # ========================================================

        enriched_findings = []

        for finding in findings:

            enriched = (
                self._safe_enrich(
                    finding
                )
            )

            normalized = (
                self._normalize_finding(
                    enriched
                )
            )

            if normalized:

                enriched_findings.append(
                    normalized
                )

        findings = (
            enriched_findings
        )

        # ========================================================
        # 11. CURRENT-ANALYSIS CONSOLIDATION
        # ========================================================

        findings = (
            self._consolidate_findings(
                findings
            )
        )

        # ========================================================
        # 12. MITRE
        # ========================================================

        for finding in findings:

            try:

                mapped = (
                    technique_ids_as_string(
                        finding
                    )
                )

                if mapped:

                    finding["mitre"] = (
                        mapped
                    )

            except Exception as exc:

                self._record_diagnostic(
                    "mitre_mapping",
                    exc,
                )

        # ========================================================
        # 13. EVIDENCE
        # ========================================================

        for finding in findings:

            try:

                evidence = (
                    generate_evidence(
                        finding
                    )
                )

                if evidence:

                    finding["evidence"] = (
                        self._merge_lists(
                            finding.get(
                                "evidence"
                            ),
                            evidence,
                        )
                    )

            except Exception as exc:

                self._record_diagnostic(
                    "evidence_generation",
                    exc,
                )

        # ========================================================
        # 14. ATTACK PATTERN
        # ========================================================

        for finding in findings:

            try:

                pattern = (
                    generate_attack_pattern(
                        finding
                    )
                )

                if pattern:

                    finding[
                        "attack_pattern"
                    ] = pattern

            except Exception as exc:

                self._record_diagnostic(
                    "attack_pattern",
                    exc,
                )

        # ========================================================
        # 15. RECOMMENDATION
        # ========================================================

        for finding in findings:

            try:

                recommendation = (
                    generate_recommendation(
                        finding
                    )
                )

                if recommendation:

                    finding[
                        "recommendation"
                    ] = recommendation

            except Exception as exc:

                self._record_diagnostic(
                    "recommendation",
                    exc,
                )

        # ========================================================
        # 16. LLM
        # ========================================================

        llm_analyzed_count = 0

        for finding in findings:

            before = (
                self._to_bool(
                    finding.get(
                        "llm_analyzed"
                    )
                )
            )

            self._analyze_with_llm(
                finding
            )

            after = (
                self._to_bool(
                    finding.get(
                        "llm_analyzed"
                    )
                )
            )

            if (
                not before
                and after
            ):

                llm_analyzed_count += 1

        # ========================================================
        # 17. CORRELATION
        # ========================================================

        try:

            correlated = (
                correlate_by_source_ip(
                    findings
                )
            )

            if isinstance(
                correlated,
                list,
            ):

                # Correlation output is treated as additional
                # evidence for this SAME upload.
                #
                # It is NOT compared with previous uploads.

                findings = (
                    self._consolidate_findings(
                        findings
                        + correlated
                    )
                )

        except Exception as exc:

            self._record_diagnostic(
                "attack_correlation",
                exc,
            )

        # ========================================================
        # 18. FINAL NORMALIZATION
        # ========================================================

        final_findings = []

        for finding in findings:

            normalized = (
                self._normalize_finding(
                    finding
                )
            )

            if not normalized:
                continue

            normalized["confidence"] = (
                self._calculate_confidence(
                    normalized
                )
            )

            normalized = (
                self._ensure_explanation(
                    normalized
                )
            )

            normalized["evidence"] = (
                self._safe_list(
                    normalized.get(
                        "evidence"
                    )
                )
            )

            # ----------------------------------------------------
            # Make sure LLM source is retained after all
            # normalization/enrichment steps.
            # ----------------------------------------------------

            if self._to_bool(
                normalized.get(
                    "llm_analyzed"
                )
            ):

                normalized[
                    "detection_sources"
                ] = self._merge_lists(
                    normalized.get(
                        "detection_sources"
                    ),
                    [
                        "llm_analysis"
                    ],
                )

                normalized[
                    "detectors"
                ] = self._merge_lists(
                    normalized.get(
                        "detectors"
                    ),
                    [
                        "llm_analysis"
                    ],
                )

            final_findings.append(
                normalized
            )

        # ========================================================
        # 19. FINAL CURRENT-ANALYSIS CONSOLIDATION
        # ========================================================

        findings = (
            self._consolidate_findings(
                final_findings
            )
        )

        # ========================================================
        # Re-add LLM source after final consolidation.
        # ========================================================

        for finding in findings:

            if self._to_bool(
                finding.get(
                    "llm_analyzed"
                )
            ):

                finding[
                    "detection_sources"
                ] = self._merge_lists(
                    finding.get(
                        "detection_sources"
                    ),
                    [
                        "llm_analysis"
                    ],
                )

                finding[
                    "detectors"
                ] = self._merge_lists(
                    finding.get(
                        "detectors"
                    ),
                    [
                        "llm_analysis"
                    ],
                )

        # ========================================================
        # 20. ATTACK CHAIN
        # ========================================================

        attack_chain = []

        try:

            result = (
                summarize_chain(
                    findings
                )
            )

            if result:
                attack_chain = result

        except Exception as exc:

            self._record_diagnostic(
                "attack_chain",
                exc,
            )

        # ========================================================
        # 21. SEVERITY COUNTS
        # ========================================================

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for finding in findings:

            severity = (
                self._safe_text(
                    finding.get(
                        "severity",
                        "LOW",
                    ),
                    "LOW",
                ).upper()
            )

            if severity not in severity_counts:
                severity = "LOW"

            severity_counts[
                severity
            ] += 1

        # ========================================================
        # 22. SORT
        # ========================================================

        findings.sort(
            key=lambda item: (
                self._severity_rank(
                    item.get(
                        "severity"
                    )
                ),
                self._normalize_score(
                    item.get(
                        "confidence"
                    ),
                    0.0,
                ),
            ),
            reverse=True,
        )

        # ========================================================
        # 23. RETURN
        # ========================================================

        return {

            "findings":
                findings,

            "severity_counts":
                severity_counts,

            "total_threats":
                len(findings),

            "processed_records":
                len(
                    normalized_records
                ),

            "normalized_records":
                normalized_records,

            "llm_analyzed_count":
                llm_analyzed_count,

            "attack_chain":
                attack_chain,

            "source_name":
                source_name,

            "timestamp":
                datetime.utcnow().isoformat(),

            "diagnostics":
                self.diagnostics,
        }


# =================================================================
# CONVENIENCE FUNCTION
# =================================================================

def detect_threats(
    log_data,
    source_name=None,
):
    """
    Convenience wrapper around DetectionEngine.

    Each call is an independent analysis.

    Example:

        result = detect_threats(
            uploaded_file.read(),
            "threats.log"
        )
    """

    engine = DetectionEngine()

    return engine.run(
        log_data,
        source_name=source_name,
    )