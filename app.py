"""
app.py

Main Flask application entry point for the
Autonomous Threat Hunting System Using LLMs.

Responsibilities:
    - Flask application initialization
    - Authentication
    - Dashboard
    - Log upload
    - Autonomous threat detection
    - ThreatEvent database persistence
    - Within-analysis duplicate consolidation
    - Single-threat and multi-threat processing
    - Dashboard statistics API
    - Admin login activity API
    - Threat APIs
    - IP-based threat investigation
    - PDF reporting
    - Email alerting
    - Live append-only log threat detection
    - Live monitor control/status APIs
"""

import warnings

# Suppress non-fatal third-party library warnings during normal application startup.
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
try:
    from requests.exceptions import RequestsDependencyWarning
    warnings.filterwarnings("ignore", category=RequestsDependencyWarning)
except Exception:
    pass
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except Exception:
    pass

import os
import json
import logging
import re
import threading
import time
import hashlib
from pathlib import Path
from collections import deque

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from ipaddress import ip_address

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_from_directory,
    jsonify,
)

from flask_login import (
    login_required,
    current_user,
)

from sqlalchemy import or_, inspect, text

from config import Config

from Database.database import (
    db,
    init_app as init_db,
)

from Database.models import (
    LogEntry,
    ThreatEvent,
    Alert,
    Report,
    LoginActivity,
)

from Authentication.auth import (
    auth_bp,
    init_login_manager,
)

from Authentication.forgot_password import (
    forgot_password_bp,
)

from Backend_support.api_response import (
    success_response,
    error_response,
)

from Backend_support.file_handler import (
    save_uploaded_file,
    read_text_file,
)

from Backend_support.validators import (
    validate_upload_request,
)

from Threat_Detection.detection_engine import (
    DetectionEngine,
)

from PDF_Generation.pdf_report import (
    generate_threat_report,
)

from Email_Alerts.email_alert import (
    send_threat_alert_email,
)



# ================================================================
# LIVE LOG MONITOR
# ================================================================

class LiveLogMonitor:
    """
    Background append-only log monitor.

    Watches Config.LIVE_LOG_FILE, processes only newly appended lines,
    runs the existing DetectionEngine, and persists live findings through
    the same ThreatEvent/Alert pipeline used by uploads.

    The monitor is intentionally self-contained so app.py can be replaced
    without requiring a second live-monitor module. A separate
    live_log_monitor.py is therefore optional, not required by this version.
    """

    def __init__(self, flask_app, process_callback):
        self.app = flask_app
        self.process_callback = process_callback
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.thread = None
        self.file_position = 0
        self.file_inode = None
        self.running = False
        self.lines_processed = 0
        self.threats_detected = 0
        self.batches_processed = 0
        self.last_poll_at = None
        self.last_processed_at = None
        self.last_error = None
        self.recent_threats = deque(maxlen=25)
        self.seen_fingerprints = {}

        self.log_file = os.path.abspath(
            getattr(
                Config,
                "LIVE_LOG_FILE",
                os.path.join(Config.UPLOAD_FOLDER, "live.log"),
            )
        )
        self.poll_interval = max(
            0.2,
            float(getattr(Config, "LIVE_POLL_INTERVAL", 1.0)),
        )
        self.batch_size = max(
            1,
            int(getattr(Config, "LIVE_BATCH_SIZE", 50)),
        )
        self.dedup_seconds = max(
            5,
            int(getattr(Config, "LIVE_DEDUP_SECONDS", 60)),
        )

    def _ensure_file(self):
        directory = os.path.dirname(self.log_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        if not os.path.exists(self.log_file):
            Path(self.log_file).touch()

    def _reset_position(self):
        self.file_position = 0
        self.file_inode = None

    def _read_new_lines(self):
        self._ensure_file()

        try:
            stat = os.stat(self.log_file)
        except OSError:
            return []

        inode = getattr(stat, "st_ino", None)
        size = stat.st_size

        # Rotation/replacement or truncation.
        if self.file_inode is not None and inode != self.file_inode:
            self._reset_position()
        elif size < self.file_position:
            self._reset_position()

        self.file_inode = inode

        if size <= self.file_position:
            return []

        with open(
            self.log_file,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:
            handle.seek(self.file_position)
            data = handle.read()
            self.file_position = handle.tell()

        if not data:
            return []

        # If the writer has not completed the final line yet, keep it for
        # the next poll by rewinding that incomplete fragment.
        if not data.endswith(("\n", "\r")):
            parts = data.splitlines(True)
            if parts and not parts[-1].endswith(("\n", "\r")):
                incomplete = parts.pop()
                self.file_position -= len(incomplete.encode("utf-8", errors="ignore"))
                # Character/byte offsets can differ for Unicode. Recalculate
                # safely from the file end of the incomplete text.
                try:
                    with open(self.log_file, "rb") as raw:
                        raw.seek(0, os.SEEK_END)
                        end = raw.tell()
                        raw.seek(max(0, end - len(incomplete.encode("utf-8"))))
                        self.file_position = raw.tell()
                except Exception:
                    self.file_position = max(0, self.file_position - len(incomplete))
                data = "".join(parts)

        return [line.rstrip("\r\n") for line in data.splitlines() if line.strip()]

    @staticmethod
    def _finding_fingerprint(finding):
        if not isinstance(finding, dict):
            return ""
        threat_type = safe_text(
            finding.get("threat_type") or finding.get("type") or ""
        ).strip().lower()
        source_ip = safe_text(
            finding.get("source_ip") or finding.get("src_ip") or ""
        ).strip()
        dest_ip = safe_text(
            finding.get("dest_ip") or finding.get("dst_ip") or finding.get("destination_ip") or ""
        ).strip()
        evidence = safe_text(finding.get("evidence") or "")
        title = safe_text(finding.get("title") or "")
        material = "|".join((threat_type, source_ip, dest_ip, title, evidence))
        return hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()

    def should_persist(self, finding):
        fingerprint = self._finding_fingerprint(finding)
        if not fingerprint:
            return True
        now = time.time()
        expired = [
            key for key, timestamp in self.seen_fingerprints.items()
            if now - timestamp > self.dedup_seconds
        ]
        for key in expired:
            self.seen_fingerprints.pop(key, None)
        previous = self.seen_fingerprints.get(fingerprint)
        if previous is not None and now - previous <= self.dedup_seconds:
            return False
        self.seen_fingerprints[fingerprint] = now
        return True

    def record_result(self, finding, owner_id=None):
        with self.lock:
            self.threats_detected += 1
            self.recent_threats.appendleft({
                "threat_type": normalize_threat_type(
                    finding.get("threat_type") or finding.get("type")
                ),
                "title": safe_text(finding.get("title") or "Threat Detected"),
                "severity": safe_text(finding.get("severity") or "MEDIUM").upper(),
                "source_ip": safe_text(
                    finding.get("source_ip") or finding.get("src_ip") or ""
                ),
                "destination_ip": safe_text(
                    finding.get("dest_ip") or finding.get("dst_ip") or finding.get("destination_ip") or ""
                ),
                "detected_at": datetime.now(IST).isoformat(timespec="seconds"),
                "detected_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "owner_user_id": owner_id if owner_id is not None else getattr(self, "owner_user_id", None),
            })

    def _worker(self):
        self.app.logger.info(
            "LIVE MONITOR STARTED: file=%s interval=%ss batch=%s",
            self.log_file,
            self.poll_interval,
            self.batch_size,
        )

        while not self.stop_event.is_set():
            try:
                with self.lock:
                    self.last_poll_at = datetime.now(IST).isoformat(timespec="seconds")
                lines = self._read_new_lines()

                if lines:
                    # Preserve the upload engine's batch semantics while
                    # preventing unbounded memory usage.
                    for start in range(0, len(lines), self.batch_size):
                        batch = lines[start:start + self.batch_size]
                        if not batch:
                            continue
                        result = self.process_callback(batch, self.log_file)
                        with self.lock:
                            self.lines_processed += len(batch)
                            self.batches_processed += 1
                            self.last_processed_at = datetime.now(IST).isoformat(timespec="seconds")
                            self.last_error = None
                        for finding in result or []:
                            if self.should_persist(finding):
                                self.record_result(finding, getattr(self, "owner_user_id", None))
                else:
                    time.sleep(self.poll_interval)

            except Exception as exc:
                with self.lock:
                    self.last_error = str(exc)
                self.app.logger.exception("LIVE MONITOR ERROR")
                time.sleep(self.poll_interval)

        with self.lock:
            self.running = False
        self.app.logger.info("LIVE MONITOR STOPPED")

    def start(self):
        with self.lock:
            if self.running and self.thread and self.thread.is_alive():
                return False
            self.stop_event.clear()
            self._ensure_file()
            # Start at EOF so existing historical content is not reprocessed.
            try:
                self.file_position = os.path.getsize(self.log_file)
                self.file_inode = os.stat(self.log_file).st_ino
            except OSError:
                self.file_position = 0
                self.file_inode = None
            self.thread = threading.Thread(
                target=self._worker,
                name="LiveThreatMonitor",
                daemon=True,
            )
            self.running = True
            self.thread.start()
            return True

    def stop(self):
        with self.lock:
            if not self.running:
                return False
            self.stop_event.set()
            thread = self.thread
        if thread and thread.is_alive():
            thread.join(timeout=max(2.0, self.poll_interval + 1.0))
        with self.lock:
            self.running = False
        return True

    def status(self):
        with self.lock:
            return {
                "enabled": bool(getattr(Config, "LIVE_MONITOR_ENABLED", True)),
                "running": bool(self.running and self.thread and self.thread.is_alive()),
                "file": self.log_file,
                "poll_interval": self.poll_interval,
                "batch_size": self.batch_size,
                "dedup_seconds": self.dedup_seconds,
                "lines_processed": self.lines_processed,
                "batches_processed": self.batches_processed,
                "threats_detected": self.threats_detected,
                "last_poll_at": self.last_poll_at,
                "last_poll_at_ist": self.last_poll_at,
                "last_processed_at": self.last_processed_at,
                "last_processed_at_ist": self.last_processed_at,
                "timezone": "Asia/Kolkata",
                "timezone_label": "IST (UTC+05:30)",
                "last_error": self.last_error,
                "recent_threats": list(self.recent_threats),
            }


# ================================================================
# CONSTANTS
# ================================================================

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


THREAT_TYPE_ALIASES = {
    # ------------------------------------------------------------
    # Brute force
    # ------------------------------------------------------------
    "brute_force_attack": "brute_force",
    "brute-force": "brute_force",
    "brute_force": "brute_force",
    "password_spray": "brute_force",
    "password_spraying": "brute_force",

    # ------------------------------------------------------------
    # PowerShell
    # ------------------------------------------------------------
    "powershell": "powershell_execution",
    "powershell_attack": "powershell_execution",
    "powershell_execution": "powershell_execution",
    "powershell_command": "powershell_execution",

    # ------------------------------------------------------------
    # Privilege escalation
    # ------------------------------------------------------------
    "privilege_escalation": "privilege_escalation",
    "privilege-escalation": "privilege_escalation",
    "privilege_escalation_attack": "privilege_escalation",

    # ------------------------------------------------------------
    # Network scanning
    # ------------------------------------------------------------
    "network_scanning": "network_scan",
    "network_scan": "network_scan",
    "network_scanner": "network_scan",
    "port_scan": "network_scan",
    "port_scanning": "network_scan",

    # ------------------------------------------------------------
    # Reverse shell
    # ------------------------------------------------------------
    "reverse_shell": "reverse_shell",
    "reverse-shell": "reverse_shell",

    # ------------------------------------------------------------
    # Malware
    # ------------------------------------------------------------
    "malware": "malware_execution",
    "malware_detected": "malware_execution",
    "malware_execution": "malware_execution",
    "suspicious_file_execution": "malware_execution",
    "suspicious_file": "malware_execution",
    "payload_execution": "malware_execution",

    # ------------------------------------------------------------
    # Data exfiltration
    # ------------------------------------------------------------
    "data_exfiltration": "data_exfiltration",
    "data_exfil": "data_exfiltration",
    "data_exfiltration_attack": "data_exfiltration",

    # ------------------------------------------------------------
    # Registry persistence
    # ------------------------------------------------------------
    "registry_persistence": "registry_persistence",
    "registry_change": "registry_persistence",
    "registry_modification": "registry_persistence",

    # ------------------------------------------------------------
    # Scheduled task persistence
    # ------------------------------------------------------------
    "scheduled_task": "scheduled_task_persistence",
    "scheduled_task_persistence": "scheduled_task_persistence",
    "scheduled_task_creation": "scheduled_task_persistence",

    # ------------------------------------------------------------
    # C2
    # ------------------------------------------------------------
    "c2": "c2_beaconing",
    "c2_beacon": "c2_beaconing",
    "c2_beaconing": "c2_beaconing",
    "command_and_control": "c2_beaconing",

    # ------------------------------------------------------------
    # File deletion
    # ------------------------------------------------------------
    "mass_delete": "mass_file_deletion",
    "mass_file_deletion": "mass_file_deletion",
    "mass_file_deletion_attack": "mass_file_deletion",

    # ------------------------------------------------------------
    # Firewall
    # ------------------------------------------------------------
    "firewall_change": "firewall_tampering",
    "firewall_tampering": "firewall_tampering",
    "firewall_rule_change": "firewall_tampering",
    "firewall_modification": "firewall_tampering",

    # ------------------------------------------------------------
    # Existing/general categories
    # ------------------------------------------------------------
    "sql_injection": "sql_injection",
    "sql-injection": "sql_injection",

    "command_injection": "command_injection",
    "command-injection": "command_injection",

    "suspicious_ip": "suspicious_ip",
    "suspicious-ip": "suspicious_ip",

    # ------------------------------------------------------------
    # Invalid/fallback
    # ------------------------------------------------------------
    "unknown": "unknown",
    "unknown_threat": "unknown_threat",
    "unknown-threat": "unknown_threat",
}


KNOWN_THREAT_TYPES = {
    "brute_force",
    "powershell_execution",
    "privilege_escalation",
    "network_scan",
    "reverse_shell",
    "malware_execution",
    "data_exfiltration",
    "registry_persistence",
    "scheduled_task_persistence",
    "c2_beaconing",
    "mass_file_deletion",
    "firewall_tampering",
    "sql_injection",
    "command_injection",
    "suspicious_ip",
}


# ================================================================
# HELPER FUNCTIONS
# ================================================================


def normalize_percentage(value, default=0.0):
    """
    Convert detector score/confidence to 0-100 percentage.
    """

    if value is None:
        return float(default)

    try:
        value = float(value)

    except (TypeError, ValueError):
        return float(default)

    # Scores may arrive in one of three forms:
    #   0.69  -> 69%
    #   69    -> 69%
    #   6900  -> 69% (legacy value that was already multiplied by 100)
    # Keep the public representation strictly in the 0-100 range.
    if 0.0 <= value <= 1.0:
        value *= 100.0
    elif value > 100.0 and value <= 10000.0:
        value /= 100.0

    return round(
        max(0.0, min(100.0, value)),
        2,
    )


def serialize_json(value, default=None):
    """
    Convert dictionaries/lists to JSON text.
    """

    if value is None:
        return default

    if isinstance(value, str):
        return value

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )

    except (TypeError, ValueError):
        return str(value)


def safe_text(value, default=""):
    """
    Safely convert a value to text.
    """

    if value is None:
        return default

    if isinstance(value, str):
        return value

    try:
        return str(value)

    except Exception:
        return default



def extract_ip_addresses_from_text(value):
    """
    Extract valid IPv4/IPv6 addresses from arbitrary finding/log text.
    Invalid regex matches are ignored.
    """
    text_value = safe_text(value)
    if not text_value:
        return []

    # Candidate tokens intentionally include common punctuation around IPs.
    candidates = re.findall(
        r"(?<![A-Za-z0-9_])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}|"
        r"(?<![A-Za-z0-9_])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_])",
        text_value,
    )

    found = []
    for candidate in candidates:
        candidate = candidate.strip("[](){}<>,;\"'`")
        if not candidate:
            continue
        try:
            normalized = str(ip_address(candidate))
        except ValueError:
            continue
        if normalized not in found:
            found.append(normalized)

    return found


def _finding_text_blob(finding):
    """Build searchable text from the fields detectors commonly populate."""
    if not isinstance(finding, dict):
        return ""

    values = []
    for key in (
        "title",
        "name",
        "description",
        "evidence",
        "anomaly_evidence",
        "matched_indicators",
        "indicators",
        "explanation",
        "llm_summary",
        "raw_line",
        "log_line",
        "message",
        "event",
        "source_file",
    ):
        value = finding.get(key)
        if isinstance(value, (dict, list, tuple)):
            value = serialize_json(value, default="")
        if value:
            values.append(safe_text(value))

    return " ".join(values)


def enrich_findings_with_log_records(findings, normalized_records):
    """
    Enrich detector findings with source/destination IPs from the normalized
    upload records before within-upload deduplication.

    Important:
      - An explicit finding IP always wins.
      - A single IP is assigned only when the finding text/record gives us a
        defensible match, or when the entire upload contains exactly one IP.
      - When multiple IPs exist, never arbitrarily assign the first IP to every
        threat.
    """
    normalized_records = [
        record for record in (normalized_records or [])
        if isinstance(record, dict)
    ]
    if not normalized_records:
        return findings

    def record_source_ip(record):
        value = (
            record.get("source_ip")
            or record.get("src_ip")
            or ""
        )
        try:
            return str(ip_address(safe_text(value).strip()))
        except ValueError:
            return ""

    def record_dest_ip(record):
        value = (
            record.get("dest_ip")
            or record.get("dst_ip")
            or record.get("destination_ip")
            or ""
        )
        try:
            return str(ip_address(safe_text(value).strip()))
        except ValueError:
            return ""

    # Unique source/destination IPs present in this upload.
    upload_source_ips = []
    upload_dest_ips = []
    for record in normalized_records:
        src = record_source_ip(record)
        dst = record_dest_ip(record)
        if src and src not in upload_source_ips:
            upload_source_ips.append(src)
        if dst and dst not in upload_dest_ips:
            upload_dest_ips.append(dst)

    def record_text(record):
        values = []
        for key in (
            "raw_line",
            "event",
            "message",
            "source_file",
            "user",
            "log_type",
        ):
            value = record.get(key)
            if value:
                values.append(safe_text(value))
        return " ".join(values)

    for finding in normalize_findings(findings):
        if not isinstance(finding, dict):
            continue

        # Preserve any detector-supplied valid IP.
        existing_src = safe_text(
            finding.get("source_ip") or finding.get("src_ip") or ""
        ).strip()
        existing_dst = safe_text(
            finding.get("dest_ip")
            or finding.get("dst_ip")
            or finding.get("destination_ip")
            or ""
        ).strip()

        finding_text = _finding_text_blob(finding).lower()
        finding_ips = extract_ip_addresses_from_text(finding_text)

        # If the detector text itself contains exactly one IP, it is a strong
        # source-IP candidate for a finding that has no explicit source IP.
        if not existing_src and len(finding_ips) == 1:
            try:
                finding["source_ip"] = str(ip_address(finding_ips[0]))
                existing_src = finding["source_ip"]
            except ValueError:
                pass

        # Score normalized records against the finding. Exact/contained
        # evidence/raw-line matches are deliberately stronger than generic
        # type/title matches.
        scored = []
        finding_user = safe_text(
            finding.get("user") or finding.get("username") or ""
        ).strip().lower()
        finding_source_file = safe_text(
            finding.get("source_file") or ""
        ).strip().lower()

        finding_raw_values = []
        for key in ("raw_line", "log_line", "message", "event", "evidence"):
            value = finding.get(key)
            if value:
                finding_raw_values.append(safe_text(value).strip().lower())

        for record in normalized_records:
            rtext = record_text(record)
            rtext_lower = rtext.lower()
            score = 0

            # Strongest: finding evidence/raw log line is contained in the
            # normalized record, or vice versa.
            for raw_value in finding_raw_values:
                if raw_value and (
                    raw_value in rtext_lower or rtext_lower in raw_value
                ):
                    score += 100
                    break

            if finding_source_file:
                rfile = safe_text(record.get("source_file") or "").strip().lower()
                if rfile and finding_source_file == rfile:
                    score += 20

            if finding_user:
                ruser = safe_text(record.get("user") or "").strip().lower()
                if ruser and finding_user == ruser:
                    score += 25

            record_ips = set(
                extract_ip_addresses_from_text(rtext)
                + ([record_source_ip(record)] if record_source_ip(record) else [])
                + ([record_dest_ip(record)] if record_dest_ip(record) else [])
            )
            if finding_ips and record_ips.intersection(finding_ips):
                score += 80

            # A detector finding whose text names the record event is useful,
            # but not strong enough by itself to select among many records.
            finding_event = safe_text(
                finding.get("event") or ""
            ).strip().lower()
            record_event = safe_text(
                record.get("event") or ""
            ).strip().lower()
            if finding_event and record_event and finding_event == record_event:
                score += 50

            if score > 0:
                scored.append((score, record))

        # Use only the best matching records. A tie between different source
        # IPs is ambiguous, so leave source_ip empty rather than guessing.
        if not existing_src and scored:
            best_score = max(score for score, _ in scored)
            best_records = [
                record for score, record in scored
                if score == best_score
            ]
            best_sources = []
            for record in best_records:
                src = record_source_ip(record)
                if src and src not in best_sources:
                    best_sources.append(src)

            if len(best_sources) == 1:
                finding["source_ip"] = best_sources[0]
                existing_src = best_sources[0]

        if not existing_dst and scored:
            best_score = max(score for score, _ in scored)
            best_records = [
                record for score, record in scored
                if score == best_score
            ]
            best_dests = []
            for record in best_records:
                dst = record_dest_ip(record)
                if dst and dst not in best_dests:
                    best_dests.append(dst)

            if len(best_dests) == 1:
                finding["dest_ip"] = best_dests[0]
                existing_dst = best_dests[0]

        # Safe fallback: if this upload has exactly one source IP, it is
        # reasonable to associate a finding with it. Never do this when the
        # upload contains multiple source IPs.
        if not existing_src and len(upload_source_ips) == 1:
            finding["source_ip"] = upload_source_ips[0]

        if not existing_dst and len(upload_dest_ips) == 1:
            finding["dest_ip"] = upload_dest_ips[0]

    return findings


def get_finding_score(
    finding,
    *keys,
    default=0.0,
):
    """
    Return the first available score from a finding.
    """

    if not isinstance(finding, dict):
        return float(default)

    for key in keys:

        if key not in finding:
            continue

        value = finding.get(key)

        if value is None:
            continue

        return normalize_percentage(
            value,
            default=default,
        )

    return float(default)


# ================================================================
# THREAT TYPE NORMALIZATION
# ================================================================


def normalize_threat_type(value):
    """
    Normalize threat names to one canonical value.
    """

    text = safe_text(
        value
    ).strip().lower()

    if not text:
        return ""

    text = (
        text
        .replace("-", "_")
        .replace(" ", "_")
    )

    while "__" in text:
        text = text.replace(
            "__",
            "_",
        )

    return THREAT_TYPE_ALIASES.get(
        text,
        text,
    )


def is_unknown_finding(finding):
    """
    Return True when a finding is only a fallback/placeholder.

    Unknown findings must NEVER become ThreatEvent records.
    """

    if not isinstance(finding, dict):
        return True

    raw_type = (
        finding.get("threat_type")
        or finding.get("type")
        or finding.get("classification")
        or ""
    )

    raw_title = (
        finding.get("title")
        or finding.get("name")
        or ""
    )

    threat_type = normalize_threat_type(
        raw_type
    )

    title = safe_text(
        raw_title
    ).strip().lower()

    confidence = get_finding_score(
        finding,
        "confidence",
        "score",
        "risk_score",
        default=0.0,
    )

    invalid_types = {
        "",
        "unknown",
        "unknown_threat",
        "none",
        "null",
    }

    invalid_titles = {
        "",
        "unknown threat",
        "security threat",
        "unknown",
    }

    if threat_type in invalid_types:
        return True

    if (
        title in invalid_titles
        and confidence <= 0
    ):
        return True

    return False


def classify_threat_type(threat):
    """
    Return a normalized dashboard threat category.

    Supports both ThreatEvent objects and dictionaries.
    """

    if isinstance(threat, dict):

        raw_type = (
            threat.get("threat_type")
            or threat.get("type")
            or threat.get("classification")
            or ""
        )

        raw_title = (
            threat.get("title")
            or threat.get("name")
            or ""
        )

    else:

        raw_type = getattr(
            threat,
            "threat_type",
            "",
        )

        raw_title = getattr(
            threat,
            "title",
            "",
        )

    threat_type = normalize_threat_type(
        raw_type
    )

    title = normalize_threat_type(
        raw_title
    )

    combined = (
        f"{threat_type} {title}"
    )

    # ------------------------------------------------------------
    # Exact/normalized categories first
    # ------------------------------------------------------------

    if threat_type in KNOWN_THREAT_TYPES:
        return threat_type

    # ------------------------------------------------------------
    # Semantic matching
    # ------------------------------------------------------------

    if (
        "brute" in combined
        or "password_spray" in combined
    ):
        return "brute_force"

    if (
        "powershell" in combined
    ):
        return "powershell_execution"

    if (
        "privilege" in combined
        and "escalation" in combined
    ):
        return "privilege_escalation"

    if (
        "network" in combined
        and "scan" in combined
    ):
        return "network_scan"

    if (
        "port" in combined
        and "scan" in combined
    ):
        return "network_scan"

    if "reverse_shell" in combined:
        return "reverse_shell"

    if (
        "malware" in combined
        or "virus" in combined
        or "ransomware" in combined
        or "payload" in combined
        or (
            "suspicious" in combined
            and "file" in combined
        )
    ):
        return "malware_execution"

    if (
        "data" in combined
        and "exfil" in combined
    ):
        return "data_exfiltration"

    if (
        "registry" in combined
        and (
            "persist" in combined
            or "change" in combined
            or "modif" in combined
        )
    ):
        return "registry_persistence"

    if (
        "scheduled" in combined
        and "task" in combined
    ):
        return "scheduled_task_persistence"

    if (
        "c2" in combined
        or "beacon" in combined
        or "command_and_control" in combined
    ):
        return "c2_beaconing"

    if (
        "mass" in combined
        and "delete" in combined
    ):
        return "mass_file_deletion"

    if (
        "firewall" in combined
        and (
            "tamper" in combined
            or "change" in combined
            or "modif" in combined
        )
    ):
        return "firewall_tampering"

    if (
        "sql" in combined
        and "injection" in combined
    ):
        return "sql_injection"

    if (
        "command" in combined
        and "injection" in combined
    ):
        return "command_injection"

    if (
        "suspicious" in combined
        and "ip" in combined
    ):
        return "suspicious_ip"

    return threat_type or "unknown"


# ================================================================
# EXPLANATION
# ================================================================


def build_mandatory_explanation(finding):
    """
    Guarantee that every genuine ThreatEvent has an explanation.
    """

    if not isinstance(finding, dict):
        finding = {}

    explanation = finding.get(
        "explanation"
    )

    if explanation:

        explanation = safe_text(
            explanation
        ).strip()

        if explanation:
            return explanation

    llm_summary = finding.get(
        "llm_summary"
    )

    if llm_summary:

        llm_summary = safe_text(
            llm_summary
        ).strip()

        if llm_summary:
            return llm_summary

    threat_type = (
        finding.get("threat_type")
        or "security"
    )

    source_ip = (
        finding.get("source_ip")
        or "unknown source"
    )

    severity = (
        finding.get("severity")
        or "LOW"
    )

    confidence = normalize_percentage(
        finding.get("confidence", 0)
    )

    return (
        "The autonomous threat detection system "
        f"identified a potential {threat_type} threat "
        f"from {source_ip}. "
        f"The detected threat has a severity of "
        f"{severity} with a confidence of "
        f"{confidence:.2f}%. "
        "The finding was generated from the available "
        "security detection evidence."
    )


# ================================================================
# DETECTOR SCORES
# ================================================================


def normalize_detector_scores(finding):
    """
    Build a consistent detector score dictionary.
    """

    if not isinstance(finding, dict):
        return {}

    scores = {}

    existing = finding.get(
        "detector_scores"
    )

    if isinstance(existing, dict):

        for key, value in existing.items():

            scores[str(key)] = (
                normalize_percentage(value)
            )

    mapping = {

        "rule": (
            "rule_score",
            "rule_confidence",
        ),

        "ml": (
            "ml_score",
            "ml_confidence",
            "rf_probability",
            "rf_confidence",
        ),

        "anomaly": (
            "anomaly_score",
            "anomaly_confidence",
        ),

        "threat_intelligence": (
            "threat_intelligence_score",
            "ioc_score",
            "ti_score",
        ),

        "correlation": (
            "correlation_score",
        ),

        "llm": (
            "llm_score",
        ),
    }

    for detector, keys in mapping.items():

        score = get_finding_score(
            finding,
            *keys,
            default=0.0,
        )

        if score > 0:

            scores[detector] = max(
                scores.get(detector, 0.0),
                score,
            )

    return scores


# ================================================================
# FINDING NORMALIZATION
# ================================================================


def normalize_findings(raw_findings):
    """
    Normalize DetectionEngine output.

    Supports:
        []
        [finding1, finding2]
        finding
    """

    if raw_findings is None:
        return []

    if isinstance(
        raw_findings,
        dict,
    ):

        return [
            raw_findings
        ]

    if isinstance(
        raw_findings,
        list,
    ):

        return [
            item
            for item in raw_findings
            if isinstance(item, dict)
        ]

    try:

        values = list(
            raw_findings
        )

        return [
            item
            for item in values
            if isinstance(item, dict)
        ]

    except Exception:

        return []


def threat_finding_key(finding):
    """
    Stable identity for one underlying threat.

    Detector source, title and username are intentionally
    NOT part of the identity.

    Identity:

        threat_type
        source_ip
        destination_ip
    """

    if not isinstance(finding, dict):
        return None

    if is_unknown_finding(finding):
        return None

    threat_type = normalize_threat_type(
        finding.get("threat_type")
        or finding.get("type")
        or finding.get("classification")
    )

    source_ip = safe_text(
        finding.get("source_ip")
        or finding.get("src_ip")
        or ""
    ).strip()

    dest_ip = safe_text(
        finding.get("dest_ip")
        or finding.get("dst_ip")
        or finding.get("destination_ip")
        or ""
    ).strip()

    if not threat_type:
        return None

    return (
        threat_type,
        source_ip,
        dest_ip,
    )


def merge_finding_values(
    existing,
    incoming,
):
    """
    Merge useful information when multiple detectors
    report the same underlying threat.
    """

    if not isinstance(existing, dict):
        return incoming

    if not isinstance(incoming, dict):
        return existing

    # ------------------------------------------------------------
    # Keep strongest confidence.
    # ------------------------------------------------------------

    existing_confidence = get_finding_score(
        existing,
        "confidence",
        default=0.0,
    )

    incoming_confidence = get_finding_score(
        incoming,
        "confidence",
        default=0.0,
    )

    if incoming_confidence > existing_confidence:

        existing["confidence"] = (
            incoming_confidence / 100.0
        )

    # ------------------------------------------------------------
    # Keep strongest severity.
    # ------------------------------------------------------------

    existing_severity = safe_text(
        existing.get("severity")
        or "LOW"
    ).upper()

    incoming_severity = safe_text(
        incoming.get("severity")
        or "LOW"
    ).upper()

    if (
        SEVERITY_ORDER.get(
            incoming_severity,
            1,
        )
        >
        SEVERITY_ORDER.get(
            existing_severity,
            1,
        )
    ):

        existing["severity"] = incoming_severity

    # ------------------------------------------------------------
    # Fill useful scalar values.
    # ------------------------------------------------------------

    fields = (
        "title",
        "description",
        "source_ip",
        "dest_ip",
        "user",
        "username",
        "mitre_techniques",
        "attack_pattern",
        "recommendation",
        "explanation",
        "llm_summary",
        "detection_source",
        "analysis_status",
        "analyzed_at",
    )

    for field in fields:

        current = existing.get(field)
        new_value = incoming.get(field)

        if (
            (
                current is None
                or safe_text(current).strip() == ""
            )
            and new_value is not None
            and safe_text(new_value).strip() != ""
        ):

            existing[field] = new_value

    # ------------------------------------------------------------
    # Merge evidence.
    # ------------------------------------------------------------

    existing_evidence = existing.get(
        "evidence"
    )

    incoming_evidence = incoming.get(
        "evidence"
    )

    if incoming_evidence:

        if not existing_evidence:

            existing["evidence"] = (
                incoming_evidence
            )

        else:

            existing_evidence_text = safe_text(
                existing_evidence
            )

            incoming_evidence_text = safe_text(
                incoming_evidence
            )

            if (
                incoming_evidence_text
                not in existing_evidence_text
            ):

                existing["evidence"] = (
                    existing_evidence_text
                    + "\n"
                    + incoming_evidence_text
                )

    # ------------------------------------------------------------
    # Merge detector scores.
    # ------------------------------------------------------------

    existing_scores = normalize_detector_scores(
        existing
    )

    incoming_scores = normalize_detector_scores(
        incoming
    )

    for detector, score in incoming_scores.items():

        existing_scores[detector] = max(
            existing_scores.get(
                detector,
                0.0,
            ),
            score,
        )

    existing["detector_scores"] = (
        existing_scores
    )

    # ------------------------------------------------------------
    # Merge detection sources.
    # ------------------------------------------------------------

    sources = []

    for source_value in (
        existing.get("detection_sources"),
        existing.get("detection_source"),
        incoming.get("detection_sources"),
        incoming.get("detection_source"),
    ):

        if isinstance(
            source_value,
            list,
        ):

            sources.extend(
                safe_text(x).strip()
                for x in source_value
                if safe_text(x).strip()
            )

        else:

            source_text = safe_text(
                source_value
            ).strip()

            if source_text:
                sources.append(
                    source_text
                )

    unique_sources = []

    for source in sources:

        if source not in unique_sources:

            unique_sources.append(
                source
            )

    if unique_sources:

        existing["detection_sources"] = (
            unique_sources
        )

        existing["detection_source"] = (
            unique_sources[0]
        )

    return existing


def deduplicate_findings(findings):
    """
    Deduplicate findings from one analysis.

    Multiple detectors reporting the same:

        threat_type + source_ip + destination_ip

    are treated as one underlying threat.

    Unknown/placeholder findings are discarded.
    """

    unique_findings = {}

    for finding in normalize_findings(
        findings
    ):

        if not isinstance(
            finding,
            dict,
        ):
            continue

        if is_unknown_finding(
            finding
        ):

            app.logger.warning(
                "Ignoring invalid/unknown finding: %s",
                finding,
            )

            continue

        threat_type = normalize_threat_type(
            finding.get("threat_type")
            or finding.get("type")
            or finding.get("classification")
        )

        if not threat_type:
            continue

        finding["threat_type"] = (
            threat_type
        )

        if not finding.get(
            "detection_source"
        ):

            finding["detection_source"] = (
                "detection_engine"
            )

        key = threat_finding_key(
            finding
        )

        if key is None:
            continue

        if key not in unique_findings:

            unique_findings[key] = dict(
                finding
            )

        else:

            unique_findings[key] = (
                merge_finding_values(
                    unique_findings[key],
                    finding,
                )
            )

    return list(
        unique_findings.values()
    )


# ================================================================
# EXISTING DATABASE DUPLICATE CHECK
# ================================================================


def existing_threat_matches(finding):
    """
    Check whether the same underlying threat already exists.

    Identity:

        normalized threat type
        + source IP
        + destination IP

    Detector source, title and username are intentionally ignored.
    """

    if not isinstance(
        finding,
        dict,
    ):
        return None

    if is_unknown_finding(
        finding
    ):
        return None

    threat_type = normalize_threat_type(
        finding.get("threat_type")
        or finding.get("type")
        or finding.get("classification")
    )

    source_ip = safe_text(
        finding.get("source_ip")
        or finding.get("src_ip")
        or ""
    ).strip()

    dest_ip = safe_text(
        finding.get("dest_ip")
        or finding.get("dst_ip")
        or finding.get("destination_ip")
        or ""
    ).strip()

    if not threat_type:
        return None

    query = scoped_threat_query().filter(
        ThreatEvent.threat_type == threat_type
    )

    if source_ip:

        query = query.filter(
            ThreatEvent.source_ip == source_ip
        )

    else:

        query = query.filter(
            ThreatEvent.source_ip.is_(None)
        )

    if dest_ip:

        query = query.filter(
            ThreatEvent.dest_ip == dest_ip
        )

    else:

        query = query.filter(
            ThreatEvent.dest_ip.is_(None)
        )

    return (
        query
        .order_by(
            ThreatEvent.created_at.desc()
        )
        .first()
    )


# ================================================================
# THREAT EVENT CREATION
# ================================================================


def classify_detection_algorithm(finding):
    """Return the high-level algorithm responsible for the finding.

    The upload channel (for example ``file_upload``) is deliberately
    ignored here.  Detector scores and explicit detector/source metadata
    are used instead.
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
    if score("llm_score") > 0 or finding.get("llm_analyzed") or any(s in {"llm_analysis", "llm", "large_language_model"} for s in sources):
        active.append("LLM")

    # Existing engine source names that represent signature/rule-style
    # detection are grouped under the requested Rule-Based label.
    rule_sources={
        "threat_detection_rules", "authentication_analysis",
        "network_event_analysis", "suspicious_ip", "ioc_manager",
        "rule", "rules", "rule_based", "signature", "signature_match",
    }
    if any(s in rule_sources for s in sources):
        active.append("Rule-Based")

    # Correlation source names are accepted even if the producer does not
    # currently populate correlation_score.
    if any(s in {"correlation", "correlation_engine", "attack_correlation", "attack_chain", "correlator"} for s in sources):
        active.append("Correlation Engine")

    # Preserve order while removing duplicates.
    active=list(dict.fromkeys(active))
    if len(active) > 1:
        return "Hybrid"
    if active:
        return active[0]

    # Last-resort fallback for legacy findings.
    source=str(finding.get("detected_by") or finding.get("detector") or "").strip().lower()
    if "machine_learning" in source or source in {"ml", "ml_model", "classifier"}:
        return "ML Model"
    if "anomaly" in source:
        return "Anomaly Detection"
    if "llm" in source:
        return "LLM"
    if "correl" in source or "attack_chain" in source:
        return "Correlation Engine"
    return "Rule-Based"


def build_threat_event(finding):
    """
    Convert a genuine DetectionEngine finding into ThreatEvent.

    Unknown/placeholder findings are rejected.
    """

    if not isinstance(
        finding,
        dict,
    ):

        raise ValueError(
            "Threat finding must be a dictionary."
        )

    if is_unknown_finding(
        finding
    ):

        raise ValueError(
            "Unknown/empty threat finding rejected."
        )

    threat_type = normalize_threat_type(
        finding.get("threat_type")
        or finding.get("type")
        or finding.get("classification")
    )

    if not threat_type:

        raise ValueError(
            "Threat type is required."
        )

    title = safe_text(
        finding.get("title")
        or threat_type
    ).strip()

    if not title:

        raise ValueError(
            "Threat title is required."
        )

    description = safe_text(
        finding.get("description")
        or ""
    )

    severity = safe_text(
        finding.get("severity")
        or "MEDIUM"
    ).upper()

    if severity not in (
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ):

        severity = "MEDIUM"

    confidence = normalize_percentage(
        finding.get(
            "confidence",
            0,
        )
    )

    source_ip = safe_text(
        finding.get("source_ip")
        or finding.get("src_ip")
        or ""
    ).strip() or None

    dest_ip = safe_text(
        finding.get("dest_ip")
        or finding.get("dst_ip")
        or finding.get("destination_ip")
        or ""
    ).strip() or None

    username = safe_text(
        finding.get("user")
        or finding.get("username")
        or ""
    ).strip() or None

    # Accept MITRE mappings from all detector output formats.
    # DetectionEngine uses ``mitre`` while some detectors may provide
    # ``mitre_techniques``/``techniques``/``attack_pattern``.
    mitre_value = finding.get("mitre_techniques")
    if mitre_value in (None, "", [], {}):
        mitre_value = (
            finding.get("mitre")
            or finding.get("techniques")
            or finding.get("attack_pattern")
        )

    if isinstance(mitre_value, (dict, list, tuple, set)):
        mitre_techniques = serialize_json(mitre_value)
    else:
        mitre_techniques = safe_text(mitre_value).strip() or None

    # ``file_upload`` is the input channel, not the detector.
    # Persist the high-level algorithm that actually contributed.
    detection_source = classify_detection_algorithm(finding)

    # ------------------------------------------------------------
    # Detector scores
    # ------------------------------------------------------------

    rule_score = get_finding_score(
        finding,
        "rule_score",
        "rule_confidence",
    )

    ml_score = get_finding_score(
        finding,
        "ml_score",
        "ml_confidence",
        "rf_probability",
        "rf_confidence",
    )

    anomaly_score = get_finding_score(
        finding,
        "anomaly_score",
        "anomaly_confidence",
    )

    threat_intelligence_score = (
        get_finding_score(
            finding,
            "threat_intelligence_score",
            "ioc_score",
            "ti_score",
        )
    )

    correlation_score = get_finding_score(
        finding,
        "correlation_score",
    )

    llm_score = get_finding_score(
        finding,
        "llm_score",
    )

    detector_scores = normalize_detector_scores(
        finding
    )

    if rule_score > 0:

        detector_scores["rule"] = (
            rule_score
        )

    if ml_score > 0:

        detector_scores["ml"] = (
            ml_score
        )

    if anomaly_score > 0:

        detector_scores["anomaly"] = (
            anomaly_score
        )

    if threat_intelligence_score > 0:

        detector_scores[
            "threat_intelligence"
        ] = threat_intelligence_score

    if correlation_score > 0:

        detector_scores[
            "correlation"
        ] = correlation_score

    if llm_score > 0:

        detector_scores["llm"] = (
            llm_score
        )

    # ------------------------------------------------------------
    # LLM
    # ------------------------------------------------------------

    llm_summary = finding.get(
        "llm_summary"
    )

    if llm_summary:

        llm_summary = safe_text(
            llm_summary
        ).strip()

    else:

        llm_summary = None

    explanation = build_mandatory_explanation(
        finding
    )

    # ------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------

    evidence_value = (
        finding.get("evidence")
        or finding.get("anomaly_evidence")
        or finding.get("matched_indicators")
        or finding.get("indicators")
    )

    evidence = serialize_json(
        evidence_value
    )

    # ------------------------------------------------------------
    # Attack pattern
    # ------------------------------------------------------------

    attack_pattern = finding.get(
        "attack_pattern"
    )

    if isinstance(
        attack_pattern,
        (dict, list),
    ):

        attack_pattern = serialize_json(
            attack_pattern
        )

    else:

        attack_pattern = safe_text(
            attack_pattern
            or ""
        )

    # ------------------------------------------------------------
    # Recommendation
    # ------------------------------------------------------------

    recommendation = finding.get(
        "recommendation"
    )

    if isinstance(
        recommendation,
        (dict, list),
    ):

        recommendation = serialize_json(
            recommendation
        )

    else:

        recommendation = safe_text(
            recommendation
            or ""
        )

    # ------------------------------------------------------------
    # Analysis status
    # ------------------------------------------------------------

    supplied_analysis_status = safe_text(
        finding.get(
            "analysis_status"
        )
    ).strip().upper()

    if supplied_analysis_status:

        analysis_status = (
            supplied_analysis_status
        )

    elif llm_summary:

        analysis_status = "ANALYZED"

    else:

        analysis_status = "DETECTED"

    # Every newly persisted detection gets the actual current detection
    # timestamp. Do not reuse a stale timestamp supplied by the detector.
    analyzed_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # ------------------------------------------------------------
    # Threat status
    # ------------------------------------------------------------

    status = safe_text(
        finding.get(
            "status"
        )
        or "OPEN"
    ).upper()

    if status not in (
        "OPEN",
        "INVESTIGATING",
        "ACKNOWLEDGED",
        "RESOLVED",
        "CLOSED",
        "FALSE_POSITIVE",
    ):

        status = "OPEN"

    # ------------------------------------------------------------
    # Detection sources
    # ------------------------------------------------------------

    detection_sources = finding.get(
        "detection_sources"
    )

    if not isinstance(
        detection_sources,
        list,
    ):

        detection_sources = [
            detection_source
        ]

    detection_sources = [
        safe_text(source).strip()
        for source in detection_sources
        if safe_text(source).strip()
    ]

    if detection_source not in detection_sources:

        detection_sources.append(
            detection_source
        )

    # ------------------------------------------------------------
    # Create ThreatEvent
    # ------------------------------------------------------------

    event = ThreatEvent(

        title=title,

        description=description,

        threat_type=threat_type,

        severity=severity,

        confidence=confidence,

        source_ip=source_ip,

        dest_ip=dest_ip,

        user=username,

        mitre_techniques=mitre_techniques,

        detection_source=detection_source,

        rule_score=rule_score,

        ml_score=ml_score,

        anomaly_score=anomaly_score,

        threat_intelligence_score=(
            threat_intelligence_score
        ),

        correlation_score=correlation_score,

        llm_score=llm_score,

        detector_scores=serialize_json(
            detector_scores,
            default="{}",
        ),

        llm_summary=llm_summary,

        explanation=explanation,

        evidence=evidence,

        attack_pattern=attack_pattern,

        recommendation=recommendation,

        status=status,

        analysis_status=analysis_status,

        analyzed_at=analyzed_at,

        updated_at=analyzed_at,
    )

    return event


# ================================================================
# IP INVESTIGATION HELPERS
# ================================================================


def normalize_ip_address(value):
    """
    Validate and normalize an IPv4 or IPv6 address.
    """

    value = safe_text(
        value
    ).strip()

    if not value:

        raise ValueError(
            "IP address is required."
        )

    try:

        return str(
            ip_address(value)
        )

    except ValueError:

        raise ValueError(
            "Invalid IP address. "
            "Enter a valid IPv4 or IPv6 address."
        )


# ================================================================
# TIMEZONE / IST DISPLAY HELPERS
# ================================================================

IST = ZoneInfo("Asia/Kolkata")


def utc_to_ist(value):
    """
    Convert a stored UTC datetime to Asia/Kolkata.

    Existing ATHS database timestamps may be naive UTC datetimes,
    therefore a naive datetime is explicitly treated as UTC.
    """
    if value is None:
        return None

    if not isinstance(value, datetime):
        return value

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(IST)


def format_ist(value, fmt="%Y-%m-%d %H:%M:%S"):
    """Return a datetime formatted in India Standard Time."""
    if value is None:
        return "—"

    converted = utc_to_ist(value)

    if not isinstance(converted, datetime):
        return safe_text(converted) or "—"

    return converted.strftime(fmt)


def format_ist_with_timezone(value, fmt="%Y-%m-%d %H:%M:%S"):
    """Return a datetime formatted in IST with an explicit IST suffix."""
    if value is None:
        return "—"

    converted = utc_to_ist(value)

    if not isinstance(converted, datetime):
        return safe_text(converted) or "—"

    return f"{converted.strftime(fmt)} IST"


def ip_safe_datetime(value):
    """
    Convert datetime values to JSON-safe ISO strings.
    """

    if value is None:
        return None

    if isinstance(
        value,
        datetime,
    ):

        return value.isoformat()

    return safe_text(
        value
    )


def ip_threat_type(threat):
    """
    Return a normalized threat type for IP investigation.
    """

    value = safe_text(
        getattr(
            threat,
            "threat_type",
            None,
        )
    ).strip()

    if not value:

        value = safe_text(
            getattr(
                threat,
                "title",
                None,
            )
        ).strip()

    normalized = normalize_threat_type(
        value
    )

    if normalized in (
        "",
        "unknown",
        "unknown_threat",
    ):

        return "Unknown"

    return normalized


def serialize_ip_threat(
    threat,
    target_ip,
):
    """
    Serialize an existing ThreatEvent for IP investigation.

    This function is READ-ONLY.
    """

    source_ip = safe_text(
        getattr(
            threat,
            "source_ip",
            None,
        )
    ).strip()

    destination_ip = safe_text(
        getattr(
            threat,
            "dest_ip",
            None,
        )
    ).strip()

    source_match = (
        source_ip == target_ip
    )

    destination_match = (
        destination_ip == target_ip
    )

    if (
        source_match
        and destination_match
    ):

        ip_role = "BOTH"

    elif source_match:

        ip_role = "SOURCE"

    elif destination_match:

        ip_role = "DESTINATION"

    else:

        ip_role = "RELATED"

    confidence = normalize_percentage(
        getattr(
            threat,
            "confidence",
            0,
        )
    )

    llm_summary = safe_text(
        getattr(
            threat,
            "llm_summary",
            None,
        )
    ).strip()

    explanation = safe_text(
        getattr(
            threat,
            "explanation",
            None,
        )
    ).strip()

    return {

        "id":
            getattr(
                threat,
                "id",
                None,
            ),

        "title":
            safe_text(
                getattr(
                    threat,
                    "title",
                    None,
                )
            )
            or "Threat Detected",

        "description":
            safe_text(
                getattr(
                    threat,
                    "description",
                    None,
                )
            ),

        "threat_type":
            ip_threat_type(
                threat
            ),

        "severity":
            safe_text(
                getattr(
                    threat,
                    "severity",
                    None,
                )
            ).strip()
            or "Unknown",

        "confidence":
            confidence,

        "source_ip":
            source_ip,

        "dest_ip":
            destination_ip,

        "ip_role":
            ip_role,

        "user":
            safe_text(
                getattr(
                    threat,
                    "user",
                    None,
                )
            ),

        "detection_source":
            safe_text(
                getattr(
                    threat,
                    "detection_source",
                    None,
                )
            ).strip()
            or "Unknown",

        "status":
            safe_text(
                getattr(
                    threat,
                    "status",
                    None,
                )
            ).strip()
            or "Unknown",

        "analysis_status":
            safe_text(
                getattr(
                    threat,
                    "analysis_status",
                    None,
                )
            ).strip()
            or "Unknown",

        "attack_pattern":
            safe_text(
                getattr(
                    threat,
                    "attack_pattern",
                    None,
                )
            ),

        "recommendation":
            safe_text(
                getattr(
                    threat,
                    "recommendation",
                    None,
                )
            ),

        "llm_summary":
            llm_summary,

        "llm_explanation":
            llm_summary,

        "llm_score":
            normalize_percentage(
                getattr(
                    threat,
                    "llm_score",
                    0,
                )
            ),

        "explanation":
            explanation,

        "created_at":
            ip_safe_datetime(
                getattr(
                    threat,
                    "created_at",
                    None,
                )
            ),

        "updated_at":
            ip_safe_datetime(
                getattr(
                    threat,
                    "updated_at",
                    None,
                )
            ),

        "analyzed_at":
            ip_safe_datetime(
                getattr(
                    threat,
                    "analyzed_at",
                    None,
                )
            ),
    }


def serialize_ip_log(log):
    """
    Serialize a LogEntry for IP investigation.
    """

    return {

        "id":
            getattr(
                log,
                "id",
                None,
            ),

        "timestamp":
            ip_safe_datetime(
                getattr(
                    log,
                    "timestamp",
                    None,
                )
            ),

        "source_file":
            safe_text(
                getattr(
                    log,
                    "source_file",
                    None,
                )
            ),

        "source_ip":
            safe_text(
                getattr(
                    log,
                    "source_ip",
                    None,
                )
            ),

        "dest_ip":
            safe_text(
                getattr(
                    log,
                    "dest_ip",
                    None,
                )
            ),

        "user":
            safe_text(
                getattr(
                    log,
                    "user",
                    None,
                )
            ),

        "event":
            safe_text(
                getattr(
                    log,
                    "event",
                    None,
                )
            ),

        "raw_line":
            safe_text(
                getattr(
                    log,
                    "raw_line",
                    None,
                )
            ),
    }


def current_user_is_admin():
    """Return True when the authenticated account has the admin role."""
    try:
        return safe_text(getattr(current_user, "role", "")).strip().lower() == "admin"
    except Exception:
        return False


def scoped_threat_query():
    """Return a ThreatEvent query scoped to the authenticated account.

    Admins can see every threat. Normal users can only see threats whose
    ThreatEvent.owner_user_id belongs to their own account.
    """
    query = ThreatEvent.query
    if current_user_is_admin():
        return query
    return query.filter(
        ThreatEvent.owner_user_id == int(current_user.id)
    )


def scoped_alert_query():
    """Return an Alert query scoped through its owning ThreatEvent.

    Admins can see every alert. Normal users can only see alerts attached
    to ThreatEvents owned by their own account.
    """
    query = Alert.query.join(
        ThreatEvent,
        Alert.threat_event_id == ThreatEvent.id,
    )
    if current_user_is_admin():
        return query
    return query.filter(
        ThreatEvent.owner_user_id == int(current_user.id)
    )


def ensure_threat_owner_column(app):
    """Migrate older SQLite databases to ThreatEvent.owner_user_id.

    Existing databases may contain the temporary/legacy ``user_id`` column
    created by an earlier version of the application. When present, its
    values are copied into ``owner_user_id`` for rows that do not already have
    an owner. No threat rows are deleted by this migration.
    """
    try:
        with app.app_context():
            if not str(db.engine.url).startswith("sqlite"):
                app.logger.info(
                    "Threat owner migration skipped: database is not SQLite."
                )
                return

            table_name = ThreatEvent.__table__.name
            inspector = inspect(db.engine)
            columns = {
                column["name"]
                for column in inspector.get_columns(table_name)
            }

            quoted_table = '"' + table_name.replace('"', '""') + '"'

            # The new models.py defines owner_user_id, but existing SQLite
            # databases created before that change need the column added.
            if "owner_user_id" not in columns:
                with db.engine.begin() as connection:
                    connection.execute(
                        text(
                            f"ALTER TABLE {quoted_table} "
                            "ADD COLUMN owner_user_id INTEGER"
                        )
                    )
                app.logger.info(
                    "Added ThreatEvent.owner_user_id ownership column to %s.",
                    table_name,
                )
                columns.add("owner_user_id")

            # Preserve ownership already written by the previous app version.
            if "user_id" in columns:
                with db.engine.begin() as connection:
                    connection.execute(
                        text(
                            f"UPDATE {quoted_table} "
                            "SET owner_user_id = user_id "
                            "WHERE owner_user_id IS NULL AND user_id IS NOT NULL"
                        )
                    )
                app.logger.info(
                    "Migrated legacy ThreatEvent.user_id values into owner_user_id."
                )

    except Exception:
        app.logger.exception(
            "Unable to migrate ThreatEvent ownership automatically."
        )


def persist_threat_owner(event, owner_id):
    """Persist the authenticated account id on a ThreatEvent."""
    if event is None or owner_id is None:
        return

    try:
        owner_id = int(owner_id)
    except (TypeError, ValueError):
        return

    # Keep the SQLAlchemy object synchronized with the database row.
    event.owner_user_id = owner_id

    # Explicit SQL also keeps this reliable with an older database schema
    # immediately after the migration.
    table_name = ThreatEvent.__table__.name
    quoted_table = '"' + table_name.replace('"', '""') + '"'
    db.session.execute(
        text(
            f"UPDATE {quoted_table} SET owner_user_id = :owner_id "
            "WHERE id = :threat_id"
        ),
        {
            "owner_id": owner_id,
            "threat_id": event.id,
        },
    )


def threat_to_dashboard_dict(threat):
    """
    Build a dashboard-safe threat representation.

    This deliberately normalizes confidence to 0-100 and exposes severity,
    status, source IP and the actual persisted detection time consistently
    to JSON consumers.
    """
    if threat is None:
        return {}

    try:
        data = threat.to_dict()
    except Exception:
        data = {}

    if not isinstance(data, dict):
        data = {}

    severity = safe_text(getattr(threat, "severity", None) or data.get("severity") or "MEDIUM").upper()
    if severity not in SEVERITY_ORDER:
        severity = "MEDIUM"

    status = safe_text(getattr(threat, "status", None) or data.get("status") or "OPEN").upper()
    if status not in {"OPEN", "INVESTIGATING", "ACKNOWLEDGED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"}:
        status = "OPEN"

    source_ip = safe_text(getattr(threat, "source_ip", None) or data.get("source_ip") or data.get("src_ip") or "").strip()
    dest_ip = safe_text(getattr(threat, "dest_ip", None) or data.get("dest_ip") or data.get("destination_ip") or "").strip()

    created_at = getattr(threat, "created_at", None) or data.get("created_at")
    updated_at = getattr(threat, "updated_at", None) or data.get("updated_at")
    analyzed_at = getattr(threat, "analyzed_at", None) or data.get("analyzed_at")

    data.update({
        "id": getattr(threat, "id", None),
        "title": safe_text(getattr(threat, "title", None) or data.get("title") or "Threat Detected"),
        "threat_type": normalize_threat_type(getattr(threat, "threat_type", None) or data.get("threat_type") or "unknown"),
        "severity": severity,
        "status": status,
        "confidence": normalize_percentage(getattr(threat, "confidence", None) if getattr(threat, "confidence", None) is not None else data.get("confidence", 0)),
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "created_at": ip_safe_datetime(created_at),
        "updated_at": ip_safe_datetime(updated_at),
        "analyzed_at": ip_safe_datetime(analyzed_at),
        "owner_user_id": getattr(threat, "owner_user_id", None),
        "owner_username": safe_text(getattr(threat, "user", None) or ""),
    })
    return data


# ================================================================
# APPLICATION FACTORY
# ================================================================


def create_app():

    app = Flask(
        __name__
    )

    app.config.from_object(
        Config
    )

    # ------------------------------------------------------------
    # Timestamp display
    # ------------------------------------------------------------
    # Database timestamps remain UTC. Jinja converts them to IST only
    # when rendering the page.
    @app.template_filter("ist")
    def ist_filter(value):
        return format_ist(value)

    @app.template_filter("ist_full")
    def ist_full_filter(value):
        return format_ist_with_timezone(value)

    # ============================================================
    # DATABASE
    # ============================================================

    init_db(
        app
    )

    ensure_alert_status_column(app)
    ensure_threat_owner_column(app)

    # ============================================================
    # LOGIN MANAGER
    # ============================================================

    init_login_manager(
        app
    )

    # ============================================================
    # AUTHENTICATION
    # ============================================================

    app.register_blueprint(
        auth_bp,
        url_prefix="/auth",
    )

    app.register_blueprint(
        forgot_password_bp,
        url_prefix="/forgot-password",
    )

    # ============================================================
    # DETECTION ENGINE
    # ============================================================

    detection_engine = DetectionEngine()

    # ============================================================
    # MANUAL SECURITY EVENT / THREAT ANALYSIS API
    # ============================================================
    #
    # This endpoint uses the SAME DetectionEngine, normalization,
    # deduplication and ThreatEvent persistence pipeline as log uploads.
    # It is intended for the "Analyze Security Event" section of
    # analyze.html.
    #
    # POST JSON:
    # {
    #     "event": "raw security event / log line"
    # }
    #
    @app.route(
        "/api/analyze-event",
        methods=["POST"],
    )
    @login_required
    def api_analyze_event():
        try:
            payload = request.get_json(silent=True) or {}

            event_text = safe_text(
                payload.get("event")
                or payload.get("text")
                or payload.get("log")
                or payload.get("message")
                or ""
            ).strip()

            if not event_text:
                return jsonify({
                    "success": False,
                    "error": "EMPTY_EVENT",
                    "message": "Please enter a security event or log message.",
                    "data": None,
                }), 400

            if len(event_text) > 20000:
                return jsonify({
                    "success": False,
                    "error": "EVENT_TOO_LARGE",
                    "message": "Security event is too large. Maximum length is 20,000 characters.",
                    "data": None,
                }), 400

            # Manual analysis replaces the previous Analyze-page results.
            try:
                clear_previous_analysis_results()
                db.session.commit()
            except Exception as exc:
                db.session.rollback()
                app.logger.exception("Unable to clear previous manual analysis results")
                return jsonify({
                    "success": False,
                    "error": "ANALYSIS_RESET_FAILED",
                    "message": f"Unable to prepare a clean analysis session: {exc}",
                    "data": None,
                }), 500

            # Run the exact same detector used by uploaded log files.
            result = detection_engine.run(
                [event_text],
                source_name="manual_event",
            )

            if not isinstance(result, dict):
                result = {}

            raw_findings = result.get("findings")

            if raw_findings is None:
                for alternate_key in (
                    "threats",
                    "detections",
                    "detected_threats",
                    "results",
                ):
                    candidate = result.get(alternate_key)
                    if candidate is not None:
                        raw_findings = candidate
                        break

            if raw_findings is None:
                raw_findings = []

            findings = normalize_findings(raw_findings)

            # The manual event itself is the strongest source of evidence.
            # Attach it to every finding so the response remains useful even
            # when a detector does not expose a raw_line field.
            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                finding.setdefault("raw_line", event_text)
                finding.setdefault("event", event_text)

                if not finding.get("detection_source"):
                    finding["detection_source"] = "manual_event"

                # If the detector did not return an IP but the event contains
                # exactly one valid IP, safely associate that IP with the finding.
                if not (
                    finding.get("source_ip")
                    or finding.get("src_ip")
                    or finding.get("dest_ip")
                    or finding.get("dst_ip")
                    or finding.get("destination_ip")
                ):
                    event_ips = extract_ip_addresses_from_text(event_text)
                    if len(event_ips) == 1:
                        finding["source_ip"] = event_ips[0]

            findings = deduplicate_findings(findings)

            created_events = []
            invalid_findings = 0

            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                if is_unknown_finding(finding):
                    invalid_findings += 1
                    continue

                try:
                    finding["threat_type"] = normalize_threat_type(
                        finding.get("threat_type")
                        or finding.get("type")
                        or finding.get("classification")
                    )

                    # Preserve the actual detector supplied by DetectionEngine.
                    # ``manual_event`` is only an input channel, not a detector.
                    if not finding.get("detection_source"):
                        finding["detection_source"] = "detection_engine"

                    event = build_threat_event(finding)
                    db.session.add(event)
                    db.session.flush()
                    persist_threat_owner(event, current_user.id)

                    created_events.append((event, finding))

                except Exception:
                    invalid_findings += 1
                    app.logger.exception(
                        "Failed to create manual ThreatEvent"
                    )

            db.session.commit()

            # Create the same email-alert records used by upload/live analysis.
            for event, finding in created_events:
                try:
                    alert_status, err_msg = send_threat_alert_email(finding)
                    alert_status = safe_text(
                        alert_status or "FAILED"
                    ).strip().upper()

                    if alert_status not in {
                        "SENT",
                        "FAILED",
                        "SUPPRESSED",
                    }:
                        alert_status = "FAILED"

                    email_was_sent = alert_status == "SENT"

                    db.session.add(
                        Alert(
                            threat_event_id=event.id,
                            channel="email",
                            status=alert_status,
                            sent=email_was_sent,
                            sent_at=(
                                datetime.now(timezone.utc).replace(tzinfo=None)
                                if email_was_sent
                                else None
                            ),
                            error=err_msg,
                        )
                    )

                except Exception as exc:
                    app.logger.exception(
                        "Manual threat email alert processing failed"
                    )
                    db.session.add(
                        Alert(
                            threat_event_id=event.id,
                            channel="email",
                            status="FAILED",
                            sent=False,
                            sent_at=None,
                            error=str(exc),
                        )
                    )

            db.session.commit()

            threat_data = [
                threat_to_dashboard_dict(event)
                for event, _finding in created_events
            ]

            return jsonify({
                "success": True,
                "error": None,
                "message": (
                    f"Security event analyzed successfully. "
                    f"{len(threat_data)} threat(s) detected."
                    if threat_data
                    else "Security event analyzed successfully. No known threat detected."
                ),
                "data": {
                    "event": event_text,
                    "threats": threat_data,
                    "findings": threat_data,
                    "threat_count": len(threat_data),
                    "invalid_findings": invalid_findings,
                    "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                },
            })

        except Exception as exc:
            db.session.rollback()
            app.logger.exception(
                "Manual security event analysis failed"
            )

            return jsonify({
                "success": False,
                "error": "ANALYSIS_FAILED",
                "message": f"Threat analysis failed: {exc}",
                "data": None,
            }), 500

    # ============================================================
    # LIVE THREAT DETECTION
    # ============================================================

    def process_live_batch(lines, source_name):
        """Run the existing detection engine and persist live findings."""
        raw_lines = lines if isinstance(lines, list) else [str(lines)]
        result = detection_engine.run(
            raw_lines,
            source_name=os.path.basename(source_name or "live.log"),
        )
        if not isinstance(result, dict):
            return []

        findings = normalize_findings(result.get("findings", []))
        persisted = []

        for finding in findings:
            if is_unknown_finding(finding):
                continue
            try:
                finding["detection_source"] = "live_monitor"
                event = build_threat_event(finding)
                db.session.add(event)
                db.session.flush()
                owner_id = getattr(live_monitor, "owner_user_id", None)
                if owner_id is not None:
                    persist_threat_owner(event, owner_id)

                # Live detection runs in a background thread, so there is
                # no Flask current_user request context. Always resolve the
                # configured live-alert recipient explicitly.
                live_recipient = safe_text(
                    getattr(
                        Config,
                        "LIVE_ALERT_RECIPIENT_EMAIL",
                        "",
                    )
                    or getattr(
                        Config,
                        "ALERT_EMAIL_TO",
                        "",
                    )
                    or ""
                ).strip()

                alert_status, err_msg = send_threat_alert_email(
                    finding,
                    recipient_email=live_recipient or None,
                )
                alert_status = safe_text(alert_status or "FAILED").strip().upper()
                if alert_status not in {"SENT", "FAILED", "SUPPRESSED"}:
                    alert_status = "FAILED"

                email_was_sent = alert_status == "SENT"
                db.session.add(
                    Alert(
                        threat_event_id=event.id,
                        channel="email",
                        status=alert_status,
                        sent=email_was_sent,
                        sent_at=datetime.now(timezone.utc).replace(tzinfo=None) if email_was_sent else None,
                        error=err_msg,
                    )
                )
                persisted.append(finding)
            except Exception:
                db.session.rollback()
                app.logger.exception("Failed to persist live threat finding")

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Failed to commit live threat findings")
            return []

        return persisted

    live_monitor = LiveLogMonitor(app, process_live_batch)
    live_monitor.owner_user_id = None
    app.extensions["live_threat_monitor"] = live_monitor

    # Live monitoring is intentionally NOT auto-started here. The monitor is
    # shared by the Flask process, so it must first be assigned to the
    # authenticated account that starts it. This prevents unowned/global
    # live detections from leaking between normal users.

    # ============================================================
    # DASHBOARD
    # ============================================================

    @app.route("/")
    @login_required
    def dashboard():

        total_threats = (
            scoped_threat_query().count()
        )

        open_threats = (
            scoped_threat_query()
            .filter_by(
                status="OPEN"
            )
            .count()
        )

        critical_threats = (
            scoped_threat_query()
            .filter_by(
                severity="CRITICAL"
            )
            .count()
        )

        high_threats = (
            scoped_threat_query()
            .filter_by(
                severity="HIGH"
            )
            .count()
        )

        medium_threats = (
            scoped_threat_query()
            .filter_by(
                severity="MEDIUM"
            )
            .count()
        )

        low_threats = (
            scoped_threat_query()
            .filter_by(
                severity="LOW"
            )
            .count()
        )

        recent_threats = (
            scoped_threat_query()
            .order_by(
                ThreatEvent.created_at.desc()
            )
            .limit(10)
            .all()
        )

        severity_stats = {

            "LOW":
                low_threats,

            "MEDIUM":
                medium_threats,

            "HIGH":
                high_threats,

            "CRITICAL":
                critical_threats,
        }

        all_threats = (
            scoped_threat_query().all()
        )

        if all_threats:

            confidence_values = [

                normalize_percentage(
                    t.confidence
                )

                for t in all_threats
            ]

            average_confidence = round(

                sum(
                    confidence_values
                )
                /
                len(
                    confidence_values
                ),

                2,
            )

        else:

            average_confidence = 0

        threat_type_stats = {}

        for threat in all_threats:

            category = classify_threat_type(
                threat
            )

            if category == "unknown":
                continue

            threat_type_stats[
                category
            ] = (

                threat_type_stats.get(
                    category,
                    0,
                )

                + 1
            )

        suspicious_ip_stats = {}

        for threat in all_threats:

            source_ip = (
                threat.source_ip
            )

            if source_ip:

                source_ip = safe_text(
                    source_ip
                ).strip()

                if source_ip:

                    suspicious_ip_stats[
                        source_ip
                    ] = (

                        suspicious_ip_stats.get(
                            source_ip,
                            0,
                        )

                        + 1
                    )

        top_suspicious_ips = sorted(

            suspicious_ip_stats.items(),

            key=lambda x: x[1],

            reverse=True,

        )[:10]

        correlated_threats = []

        ip_groups = {}

        for threat in all_threats:

            source_ip = (
                threat.source_ip
            )

            if not source_ip:
                continue

            ip_groups.setdefault(
                source_ip,
                [],
            ).append(
                threat
            )

        for (
            source_ip,
            threats_for_ip,
        ) in ip_groups.items():

            threat_types = set(

                classify_threat_type(
                    t
                )

                for t in threats_for_ip

                if t.threat_type
            )

            if len(
                threats_for_ip
            ) > 1:

                correlated_threats.append({

                    "source_ip":
                        source_ip,

                    "event_count":
                        len(
                            threats_for_ip
                        ),

                    "threat_types":
                        sorted(
                            threat_types
                        ),
                })

        privilege_escalation_count = (

            threat_type_stats.get(
                "privilege_escalation",
                0,
            )
        )

        suspicious_ip_count = (

            threat_type_stats.get(
                "suspicious_ip",
                0,
            )
        )

        llm_analyzed_count = (

            scoped_threat_query()

            .filter(
                ThreatEvent.llm_summary.isnot(None)
            )

            .count()
        )

        mitre_mapped_count = (

            scoped_threat_query()

            .filter(
                ThreatEvent.mitre_techniques.isnot(None)
            )

            .count()
        )

        return render_template(

            "dashboard.html",

            total_threats=total_threats,

            open_threats=open_threats,

            critical_threats=critical_threats,

            high_threats=high_threats,

            medium_threats=medium_threats,

            low_threats=low_threats,

            severity_stats=severity_stats,

            average_confidence=average_confidence,

            threat_type_stats=threat_type_stats,

            recent_threats=recent_threats,

            # Normalized copies are available to dashboard templates that
            # consume dictionary-style data. The original ORM objects are
            # retained for backward compatibility.
            recent_threats_data=[
                threat_to_dashboard_dict(t) for t in recent_threats
            ],

            suspicious_ip_count=suspicious_ip_count,

            top_suspicious_ips=top_suspicious_ips,

            privilege_escalation_count=
                privilege_escalation_count,

            correlated_threats=
                correlated_threats,

            llm_analyzed_count=
                llm_analyzed_count,

            mitre_mapped_count=
                mitre_mapped_count,
        )


    # ================================================================
    # ================================================================
    # LATEST ANALYSIS CLEANUP
    # ================================================================

    def clear_previous_analysis_results():
        """Remove previous Analyze-page file/manual threat results."""
        # Everything except explicitly marked live-monitoring records is
        # treated as an Analyze-page result. This also removes legacy rows
        # created before the new source markers were introduced.
        old_events = (
            scoped_threat_query()
            .filter(ThreatEvent.detection_source != "live_monitor")
            .all()
        )
        if not old_events:
            return 0

        old_ids = [event.id for event in old_events]
        Alert.query.filter(
            Alert.threat_event_id.in_(old_ids)
        ).delete(synchronize_session=False)

        for event in old_events:
            db.session.delete(event)

        db.session.flush()
        app.logger.info(
            "Cleared %s previous Analyze-page threat result(s)",
            len(old_events),
        )
        return len(old_events)

    # LOG UPLOAD / ANALYSIS
    # ================================================================

    @app.route(
        "/upload",
        methods=["GET", "POST"],
    )
    @login_required
    def upload():

        if request.method == "POST":

            err = validate_upload_request(
                request.files,
                request.form,
            )

            if err:

                flash(
                    err,
                    "danger",
                )

                return redirect(
                    url_for("upload")
                )

            # New upload = new analysis session.
            try:
                clear_previous_analysis_results()
                db.session.commit()
            except Exception as exc:
                db.session.rollback()
                app.logger.exception("Unable to clear previous analysis results")
                flash(
                    "Unable to prepare a clean analysis session: "
                    f"{exc}",
                    "danger",
                )
                return redirect(url_for("upload"))

            try:

                saved_path, safe_name = (
                    save_uploaded_file(

                        request.files[
                            "logfile"
                        ],

                        Config.UPLOAD_FOLDER,

                        Config.ALLOWED_EXTENSIONS,
                    )
                )

            except ValueError as exc:

                flash(
                    str(exc),
                    "danger",
                )

                return redirect(
                    url_for("upload")
                )

            try:

                raw_lines = read_text_file(
                    saved_path
                )

            except Exception as exc:

                flash(
                    "Unable to read uploaded log file: "
                    f"{exc}",
                    "danger",
                )

                return redirect(
                    url_for("upload")
                )

            # ====================================================
            # RUN DETECTION ENGINE
            # ====================================================

            try:

                result = detection_engine.run(

                    raw_lines,

                    source_name=safe_name,
                )

            except Exception as exc:

                db.session.rollback()

                flash(
                    "Threat analysis failed: "
                    f"{exc}",
                    "danger",
                )

                app.logger.exception(
                    "Detection engine failure"
                )

                return redirect(
                    url_for("upload")
                )

            # ====================================================
            # VALIDATE ENGINE RESULT
            # ====================================================

            if not isinstance(
                result,
                dict,
            ):

                app.logger.error(
                    "DetectionEngine returned invalid result: %r",
                    result,
                )

                result = {}

            app.logger.info(
                "DetectionEngine returned keys: %s",
                list(result.keys()),
            )

            # ====================================================
            # NORMALIZED LOG RECORDS
            # ====================================================

            normalized_records = (
                result.get(
                    "normalized_records",
                    [],
                )
            )

            if not isinstance(
                normalized_records,
                list,
            ):

                try:

                    normalized_records = list(
                        normalized_records
                    )

                except Exception:

                    normalized_records = []

            # ====================================================
            # SAVE NORMALIZED LOG RECORDS
            # ====================================================

            for rec in normalized_records[:5000]:

                if not isinstance(
                    rec,
                    dict,
                ):
                    continue

                try:

                    record_source_file = (
                        rec.get(
                            "source_file"
                        )
                        or safe_name
                    )

                    db.session.add(

                        LogEntry(

                            source_file=
                                record_source_file,

                            raw_line=safe_text(
                                rec.get(
                                    "raw_line"
                                )
                            )[:2000],

                            log_type=rec.get(
                                "log_type"
                            ),

                            timestamp=rec.get(
                                "timestamp"
                            ),

                            source_ip=rec.get(
                                "source_ip"
                            ),

                            dest_ip=rec.get(
                                "dest_ip"
                            ),

                            user=rec.get(
                                "user"
                            ),

                            event=rec.get(
                                "event"
                            ),

                            extra_json=serialize_json(
                                rec.get(
                                    "extra_json"
                                )
                            ),
                        )
                    )

                except Exception:

                    app.logger.exception(
                        "Failed to save normalized log entry"
                    )

            # ====================================================
            # FINDINGS
            #
            # Supports:
            #   findings
            #   threats
            #   detections
            #   detected_threats
            #   results
            # ====================================================

            raw_findings = result.get(
                "findings"
            )

            if raw_findings is None:

                for alternate_key in (
                    "threats",
                    "detections",
                    "detected_threats",
                    "results",
                ):

                    candidate = result.get(
                        alternate_key
                    )

                    if candidate is not None:

                        raw_findings = candidate

                        app.logger.info(
                            "Using alternate detection result key: %s",
                            alternate_key,
                        )

                        break

            if raw_findings is None:
                raw_findings = []

            normalized_raw_findings = (
                normalize_findings(
                    raw_findings
                )
            )

            app.logger.info(
                "Raw detection finding count: %s",
                len(
                    normalized_raw_findings
                ),
            )

            # ====================================================
            # ENRICH FINDINGS FROM NORMALIZED LOG RECORDS
            #
            # Some detectors identify the threat correctly but do not carry
            # source_ip/dest_ip into their finding object. Recover those IPs
            # from the same uploaded records BEFORE deduplication so the
            # threat identity becomes:
            #
            #     threat_type + source_ip + destination_ip
            #
            # without assigning one arbitrary IP to unrelated threats.
            # ====================================================

            normalized_raw_findings = enrich_findings_with_log_records(
                normalized_raw_findings,
                normalized_records,
            )

            # ====================================================
            # LOG RAW FINDINGS
            # ====================================================

            for index, finding in enumerate(
                normalized_raw_findings,
                start=1,
            ):

                app.logger.info(
                    "RAW FINDING %s: type=%s title=%s "
                    "severity=%s confidence=%s source_ip=%s "
                    "dest_ip=%s detector=%s",
                    index,
                    finding.get("threat_type"),
                    finding.get("title"),
                    finding.get("severity"),
                    finding.get("confidence"),
                    finding.get("source_ip"),
                    finding.get("dest_ip"),
                    finding.get(
                        "detection_source"
                    ),
                )

            # ====================================================
            # DEDUPLICATE FINDINGS
            # ====================================================

            findings = deduplicate_findings(
                normalized_raw_findings
            )

            app.logger.info(
                "Consolidated valid finding count: %s",
                len(findings),
            )

            for index, finding in enumerate(
                findings,
                start=1,
            ):

                app.logger.info(
                    "CONSOLIDATED FINDING %s: type=%s title=%s "
                    "severity=%s confidence=%s source_ip=%s "
                    "dest_ip=%s detector=%s",
                    index,
                    finding.get("threat_type"),
                    finding.get("title"),
                    finding.get("severity"),
                    finding.get("confidence"),
                    finding.get("source_ip"),
                    finding.get("dest_ip"),
                    finding.get(
                        "detection_source"
                    ),
                )

            created_events = []

            # Database-level duplicate suppression is intentionally
            # disabled. Each upload is an independent analysis.
            skipped_duplicates = 0

            invalid_findings = 0

            # ====================================================
            # CREATE THREAT EVENTS
            # ====================================================

            for finding in findings:

                if not isinstance(
                    finding,
                    dict,
                ):
                    continue

                # ------------------------------------------------
                # Never save unknown findings.
                # ------------------------------------------------

                if is_unknown_finding(
                    finding
                ):

                    invalid_findings += 1

                    app.logger.warning(
                        "Skipping unknown finding: %s",
                        finding,
                    )

                    continue

                try:

                    finding["threat_type"] = (
                        normalize_threat_type(
                            finding.get(
                                "threat_type"
                            )
                        )
                    )

                    # The file is the input channel, not the detection algorithm.
                    # Keep it separately for UI/debugging without overwriting
                    # the detector selected by DetectionEngine.
                    finding["input_source"] = "file_upload"
                    finding["detection_source"] = classify_detection_algorithm(finding)

                    # ------------------------------------------------
                    # IMPORTANT: do NOT deduplicate against the database.
                    # ------------------------------------------------
                    #
                    # DetectionEngine already consolidates duplicate
                    # detector findings within THIS upload using:
                    #     threat_type + source_ip + destination_ip
                    #
                    # A later upload must be analyzed independently.
                    # Therefore the same threat/IP appearing in a new
                    # file is a NEW analysis result and must be stored
                    # as a new ThreatEvent.
                    #
                    # The old global database duplicate check caused a
                    # second upload to report:
                    #     0 new threat(s) detected
                    # even though the uploaded file contained a real
                    # threat.
                    # ------------------------------------------------

                    event = build_threat_event(
                        finding
                    )

                    db.session.add(
                        event
                    )
                    db.session.flush()
                    persist_threat_owner(event, current_user.id)

                    created_events.append(
                        (
                            event,
                            finding,
                        )
                    )

                except Exception:

                    invalid_findings += 1

                    app.logger.exception(
                        "Failed to create ThreatEvent"
                    )

            # ====================================================
            # DATABASE COMMIT
            # ====================================================

            try:

                db.session.commit()

            except Exception as exc:

                db.session.rollback()

                app.logger.exception(
                    "Threat database commit failed"
                )

                flash(
                    "Threat analysis completed, "
                    "but the database could not save "
                    f"the results: {exc}",
                    "danger",
                )

                return redirect(
                    url_for("upload")
                )

            # ====================================================
            # EMAIL ALERTS
            # ====================================================
            #
            # IMPORTANT:
            # send_threat_alert_email() returns:
            #     ("SENT", None)
            #     ("FAILED", reason)
            #     ("SUPPRESSED", reason)
            #
            # Do NOT use bool(status), because:
            #     bool("FAILED")     == True
            #     bool("SUPPRESSED") == True
            #
            # Only the exact status "SENT" means the email was
            # successfully accepted by the SMTP server.
            #
            # We call the function even when email alerts are
            # disabled so SUPPRESSED results are recorded instead
            # of disappearing from the alert history.
            # ====================================================

            for (
                event,
                finding,
            ) in created_events:

                try:

                    alert_status, err_msg = (
                        send_threat_alert_email(
                            finding
                        )
                    )

                    alert_status = safe_text(
                        alert_status
                    ).strip().upper()

                    email_was_sent = (
                        alert_status == "SENT"
                    )

                    if alert_status == "SENT":

                        app.logger.info(
                            "EMAIL ALERT SENT: "
                            "threat_event_id=%s "
                            "severity=%s "
                            "title=%s "
                            "recipient=%s",
                            event.id,
                            finding.get(
                                "severity",
                                "UNKNOWN",
                            ),
                            finding.get(
                                "title",
                                "Threat Detected",
                            ),
                            Config.ALERT_EMAIL_TO
                            or "NOT_CONFIGURED",
                        )

                    elif alert_status == "SUPPRESSED":

                        app.logger.info(
                            "EMAIL ALERT SUPPRESSED: "
                            "threat_event_id=%s "
                            "severity=%s "
                            "reason=%s",
                            event.id,
                            finding.get(
                                "severity",
                                "UNKNOWN",
                            ),
                            err_msg
                            or "No reason supplied.",
                        )

                    else:

                        app.logger.error(
                            "EMAIL ALERT FAILED: "
                            "threat_event_id=%s "
                            "severity=%s "
                            "reason=%s",
                            event.id,
                            finding.get(
                                "severity",
                                "UNKNOWN",
                            ),
                            err_msg
                            or "Unknown email delivery failure.",
                        )

                    db.session.add(

                        Alert(

                            threat_event_id=
                                event.id,

                            channel="email",

                            # CRITICAL FIX:
                            # Only SENT is True.
                            sent=email_was_sent,

                            sent_at=(

                                datetime.utcnow()

                                if email_was_sent

                                else None
                            ),

                            error=err_msg,
                        )
                    )

                except Exception as exc:

                    app.logger.exception(
                        "Threat alert email processing failed"
                    )

                    db.session.add(

                        Alert(

                            threat_event_id=
                                event.id,

                            channel="email",

                            sent=False,

                            sent_at=None,

                            error=str(exc),
                        )
                    )

            try:

                db.session.commit()

            except Exception:

                db.session.rollback()

                app.logger.exception(
                    "Failed to save alert records"
                )

            # ====================================================
            # ANALYSIS STATISTICS
            # ====================================================

            parsed_records = result.get(
                "parsed_records"
            )

            if parsed_records is None:

                parsed_records = result.get(
                    "processed_records",
                    len(
                        normalized_records
                    ),
                )

            try:

                parsed_records = int(
                    parsed_records
                )

            except (
                TypeError,
                ValueError,
            ):

                parsed_records = len(
                    normalized_records
                )

            # ====================================================
            # UNIQUE IP COUNT
            # ====================================================

            unique_ips = result.get(
                "unique_ips_analyzed"
            )

            if unique_ips is None:

                unique_ip_values = set()

                for rec in normalized_records:

                    if not isinstance(
                        rec,
                        dict,
                    ):
                        continue

                    source_ip = safe_text(
                        rec.get(
                            "source_ip"
                        )
                    ).strip()

                    dest_ip = safe_text(
                        rec.get(
                            "dest_ip"
                        )
                    ).strip()

                    if source_ip:
                        unique_ip_values.add(
                            source_ip
                        )

                    if dest_ip:
                        unique_ip_values.add(
                            dest_ip
                        )

                for finding in findings:

                    if not isinstance(
                        finding,
                        dict,
                    ):
                        continue

                    source_ip = safe_text(
                        finding.get(
                            "source_ip"
                        )
                    ).strip()

                    dest_ip = safe_text(
                        finding.get(
                            "dest_ip"
                        )
                    ).strip()

                    if source_ip:
                        unique_ip_values.add(
                            source_ip
                        )

                    if dest_ip:
                        unique_ip_values.add(
                            dest_ip
                        )

                unique_ips = len(
                    unique_ip_values
                )

            try:

                unique_ips = int(
                    unique_ips
                )

            except (
                TypeError,
                ValueError,
            ):

                unique_ips = 0

            # ====================================================
            # THREAT COUNT
            # ====================================================

            threat_count = len(
                created_events
            )

            # ====================================================
            # USER MESSAGE
            # ====================================================

            if skipped_duplicates > 0:

                message = (

                    f"Analyzed {parsed_records} "
                    f"log records across {unique_ips} "
                    f"unique IPs. "
                    f"{threat_count} new threat(s) detected. "
                    f"{skipped_duplicates} duplicate threat(s) skipped."
                )

            else:

                message = (

                    f"Analyzed {parsed_records} "
                    f"log records across {unique_ips} "
                    f"unique IPs. "
                    f"{threat_count} threat(s) detected."
                )

            if invalid_findings > 0:

                message += (
                    f" {invalid_findings} invalid/"
                    f"unknown finding(s) ignored."
                )

            flash(

                message,

                "success"
                if threat_count
                else "info",
            )

            return redirect(
                url_for("threats")
            )

        # ========================================================
        # GET
        # ========================================================

        return render_template(
            "upload.html"
        )


    # ================================================================
    # THREATS PAGE
    # ================================================================

    @app.route(
        "/auth/threats"
    )
    @login_required
    def threats():

        severity_filter = request.args.get(
            "severity"
        )

        query = scoped_threat_query()

        if (
            severity_filter
            and severity_filter.upper() != "ALL"
        ):

            query = query.filter_by(
                severity=severity_filter.upper()
            )

        all_threats = (

            query

            .order_by(
                ThreatEvent.created_at.desc()
            )

            .limit(500)

            .all()
        )

        return render_template(

            "threats.html",

            threats=all_threats,

            severity_filter=(
                severity_filter
                or "ALL"
            ),
        )


    # ================================================================
    # UPDATE THREAT STATUS
    # ================================================================

    @app.route(
        "/threats/<int:threat_id>/status",
        methods=["POST"],
    )
    @login_required
    def update_threat_status(
        threat_id
    ):

        event = (
            scoped_threat_query().get_or_404(
                threat_id
            )
        )

        # scoped_threat_query already prevents normal users from reaching
        # another account's threat. Admins intentionally have global access.
        new_status = request.form.get(
            "status",
            "OPEN",
        ).upper()

        allowed_statuses = (

            "OPEN",

            "ACKNOWLEDGED",

            "INVESTIGATING",

            "RESOLVED",

            "CLOSED",

            "FALSE_POSITIVE",
        )

        if new_status in allowed_statuses:

            event.status = new_status

            event.updated_at = (
                datetime.utcnow()
            )

            db.session.commit()

            flash(

                f"Threat #{threat_id} marked as "
                f"{new_status}.",

                "success",
            )

        else:

            flash(
                "Invalid threat status.",
                "danger",
            )

        return redirect(
            url_for("threats")
        )


    # ================================================================
    # FULL PDF REPORT
    # ================================================================

    @app.route(
        "/reports",
        methods=["GET", "POST"],
    )
    @app.route(
        "/auth/reports",
        methods=["GET", "POST"],
    )
    @app.route(
        "/auth/report",
        methods=["GET", "POST"],
    )
    @login_required
    def report():

        if request.method == "POST":

            try:

                days = int(
                    request.form.get(
                        "days",
                        7,
                    )
                )

            except (
                TypeError,
                ValueError,
            ):

                days = 7

            days = max(
                1,
                min(
                    days,
                    3650,
                ),
            )

            since = (

                datetime.utcnow()

                - timedelta(
                    days=days
                )
            )

            threats_qs = (

                scoped_threat_query()

                .filter(
                    ThreatEvent.created_at
                    >= since
                )

                .order_by(
                    ThreatEvent.created_at.desc()
                )

                .all()
            )

            threat_dicts = [

                t.to_dict()

                for t in threats_qs
            ]

            filename = (

                "threat_report_"

                f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

                ".pdf"
            )

            os.makedirs(
                Config.REPORTS_FOLDER,
                exist_ok=True,
            )

            output_path = os.path.join(
                Config.REPORTS_FOLDER,
                filename,
            )

            try:

                generate_threat_report(

                    threat_dicts,

                    output_path,

                    generated_by=(
                        current_user.username
                    ),
                )

            except Exception as exc:

                app.logger.exception(
                    "PDF report generation failed"
                )

                flash(

                    "PDF report generation failed: "
                    f"{exc}",

                    "danger",
                )

                return redirect(
                    url_for("report")
                )

            db.session.add(

                Report(

                    filename=filename,

                    generated_by=(
                        current_user.id
                    ),

                    threat_count=len(
                        threat_dicts
                    ),
                )
            )

            try:

                db.session.commit()

            except Exception as exc:

                db.session.rollback()

                flash(

                    "Report record could not be saved: "
                    f"{exc}",

                    "danger",
                )

                return redirect(
                    url_for("report")
                )

            flash(

                f"Report generated with "
                f"{len(threat_dicts)} threats.",

                "success",
            )

            return redirect(

                url_for(
                    "download_report",
                    filename=filename,
                )
            )

        recent_reports = (

            Report.query

            .order_by(
                Report.created_at.desc()
            )

            .limit(20)

            .all()
        )

        return render_template(

            "report.html",

            reports=recent_reports,
        )


    # ================================================================
    # DOWNLOAD FULL REPORT
    # ================================================================

    @app.route(
        "/reports/download/<path:filename>"
    )
    @login_required
    def download_report(filename):

        return send_from_directory(

            Config.REPORTS_FOLDER,

            filename,

            as_attachment=True,
        )


    # ================================================================
    # DASHBOARD STATISTICS API
    # ================================================================

    @app.route(
        "/api/stats",
        methods=["GET"],
    )
    @login_required
    def api_stats():

        try:

            from_date = request.args.get(
                "from"
            )

            to_date = request.args.get(
                "to"
            )

            query = scoped_threat_query()

            if from_date:

                try:

                    start_date = datetime.strptime(

                        from_date,

                        "%Y-%m-%d",
                    )

                    query = query.filter(

                        ThreatEvent.created_at
                        >= start_date
                    )

                except ValueError:

                    return jsonify({

                        "success":
                            False,

                        "message":
                            "Invalid from date. "
                            "Use YYYY-MM-DD.",

                    }), 400

            if to_date:

                try:

                    end_date = (

                        datetime.strptime(

                            to_date,

                            "%Y-%m-%d",
                        )

                        + timedelta(
                            days=1
                        )
                    )

                    query = query.filter(

                        ThreatEvent.created_at
                        < end_date
                    )

                except ValueError:

                    return jsonify({

                        "success":
                            False,

                        "message":
                            "Invalid to date. "
                            "Use YYYY-MM-DD.",

                    }), 400

            threats_list = query.all()

            total_threats = len(
                threats_list
            )

            # ----------------------------------------------------
            # All supported threat categories
            # ----------------------------------------------------

            threat_counts = {

                "brute_force": 0,

                "powershell_execution": 0,

                "privilege_escalation": 0,

                "network_scan": 0,

                "reverse_shell": 0,

                "malware_execution": 0,

                "data_exfiltration": 0,

                "registry_persistence": 0,

                "scheduled_task_persistence": 0,

                "c2_beaconing": 0,

                "mass_file_deletion": 0,

                "firewall_tampering": 0,

                "sql_injection": 0,

                "command_injection": 0,

                "suspicious_ip": 0,

                "unknown": 0,
            }

            severity_counts = {

                "LOW": 0,

                "MEDIUM": 0,

                "HIGH": 0,

                "CRITICAL": 0,
            }

            ip_counts = {}

            for threat in threats_list:

                category = classify_threat_type(
                    threat
                )

                if category not in threat_counts:

                    category = "unknown"

                threat_counts[
                    category
                ] += 1

                severity = safe_text(

                    threat.severity

                    or "LOW"
                ).strip().upper()

                if severity in (
                    "CRIT",
                    "CRITICAL",
                ):

                    severity = "CRITICAL"

                elif severity == "HIGH":

                    severity = "HIGH"

                elif severity in (
                    "MEDIUM",
                    "MED",
                    "MODERATE",
                ):

                    severity = "MEDIUM"

                else:

                    severity = "LOW"

                severity_counts[
                    severity
                ] += 1

                source_ip = (
                    threat.source_ip
                )

                if source_ip:

                    source_ip = safe_text(
                        source_ip
                    ).strip()

                    if source_ip:

                        ip_counts[
                            source_ip
                        ] = (

                            ip_counts.get(
                                source_ip,
                                0,
                            )

                            + 1
                        )

            sorted_ips = sorted(

                ip_counts.items(),

                key=lambda item: item[1],

                reverse=True,
            )

            top_source_ips = [

                {
                    "ip": ip,
                    "count": count,
                }

                for ip, count
                in sorted_ips[:10]
            ]

            open_threats = sum(

                1

                for threat
                in threats_list

                if safe_text(

                    threat.status
                    or "OPEN"

                ).strip().upper()
                == "OPEN"
            )

            if threats_list:

                confidence_values = [

                    normalize_percentage(
                        threat.confidence
                    )

                    for threat
                    in threats_list
                ]

                average_confidence = round(

                    sum(
                        confidence_values
                    )
                    /
                    len(
                        confidence_values
                    ),

                    2,
                )

            else:

                average_confidence = 0

            llm_analyzed_count = sum(

                1

                for threat
                in threats_list

                if threat.llm_summary
            )

            mitre_mapped_count = sum(

                1

                for threat
                in threats_list

                if threat.mitre_techniques
            )

            data = {

                "total_threats":
                    total_threats,

                "open_threats":
                    open_threats,

                "failed_login_attempts":
                    0,

                **threat_counts,

                # ------------------------------------------------
                # Backward compatibility:
                # existing dashboard may expect "malware".
                # ------------------------------------------------

                "malware":
                    threat_counts[
                        "malware_execution"
                    ],

                "port_scan":
                    threat_counts[
                        "network_scan"
                    ],

                "critical_threats":
                    severity_counts[
                        "CRITICAL"
                    ],

                "high_threats":
                    severity_counts[
                        "HIGH"
                    ],

                "medium_threats":
                    severity_counts[
                        "MEDIUM"
                    ],

                "low_threats":
                    severity_counts[
                        "LOW"
                    ],

                "severity_counts":
                    severity_counts,

                "threat_counts":
                    threat_counts,

                "average_confidence":
                    average_confidence,

                "top_source_ips":
                    top_source_ips,

                "llm_analyzed_count":
                    llm_analyzed_count,

                "mitre_mapped_count":
                    mitre_mapped_count,
            }

            # ====================================================
            # FAILED LOGIN ATTEMPTS
            # ====================================================

            try:

                failed_query = (

                    LoginActivity.query

                    .filter(
                        LoginActivity.login_status
                        .ilike("FAILED")
                    )
                )

                if from_date:

                    failed_query = (

                        failed_query.filter(

                            LoginActivity.login_time
                            >= datetime.strptime(

                                from_date,

                                "%Y-%m-%d"
                            )
                        )
                    )

                if to_date:

                    failed_query = (

                        failed_query.filter(

                            LoginActivity.login_time
                            < (

                                datetime.strptime(

                                    to_date,

                                    "%Y-%m-%d"
                                )

                                + timedelta(
                                    days=1
                                )
                            )
                        )
                    )

                data[
                    "failed_login_attempts"
                ] = failed_query.count()

            except Exception:

                app.logger.exception(
                    "Unable to calculate failed login count"
                )

                data[
                    "failed_login_attempts"
                ] = 0

            return jsonify({

                "success":
                    True,

                "error":
                    None,

                "message":
                    "Dashboard statistics loaded successfully.",

                "data":
                    data,
            })

        except Exception as exc:

            app.logger.exception(
                "Error in /api/stats"
            )

            return jsonify({

                "success":
                    False,

                "error":
                    str(exc),

                "message":
                    "Failed to load threat statistics.",

                "data": {
                    "total_threats": 0,
                    "open_threats": 0,
                    "failed_login_attempts": 0,
                    "brute_force": 0,
                    "powershell_execution": 0,
                    "privilege_escalation": 0,
                    "network_scan": 0,
                    "reverse_shell": 0,
                    "malware_execution": 0,
                    "malware": 0,
                    "data_exfiltration": 0,
                    "registry_persistence": 0,
                    "scheduled_task_persistence": 0,
                    "c2_beaconing": 0,
                    "mass_file_deletion": 0,
                    "firewall_tampering": 0,
                    "sql_injection": 0,
                    "command_injection": 0,
                    "suspicious_ip": 0,
                    "port_scan": 0,
                    "critical_threats": 0,
                    "high_threats": 0,
                    "medium_threats": 0,
                    "low_threats": 0,
                    "average_confidence": 0,
                    "top_source_ips": [],
                },
            }), 500


    # ================================================================
    # ADMIN LOGIN ACTIVITY API
    # ================================================================

    @app.route(
        "/auth/admin/login-activity",
        methods=["GET"],
    )
    @login_required
    def admin_login_activity():

        try:

            role = safe_text(

                getattr(
                    current_user,
                    "role",
                    "",
                )

            ).strip().lower()

            if role != "admin":

                return jsonify({

                    "success":
                        False,

                    "error":
                        "ADMIN_ACCESS_REQUIRED",

                    "message":
                        "Admin access required.",

                    "activities": [],
                }), 403

            activities = (

                LoginActivity.query

                .order_by(
                    LoginActivity.login_time.desc()
                )

                .limit(100)

                .all()
            )

            data = []

            for activity in activities:

                try:

                    if hasattr(
                        activity,
                        "to_dict",
                    ):

                        item = (
                            activity.to_dict()
                        )

                    else:

                        item = {

                            "id":
                                activity.id,

                            "username":
                                activity.username,

                            "user_id":
                                activity.user_id,

                            "ip_address":
                                activity.ip_address,

                            "login_status":
                                activity.login_status,

                            "failed_attempts":
                                activity.failed_attempts,

                            "threat_status":
                                activity.threat_status,

                            "severity":
                                activity.severity,

                            "login_time": (

                                activity.login_time.isoformat()

                                if activity.login_time

                                else None
                            ),
                        }

                    data.append(
                        item
                    )

                except Exception:

                    app.logger.exception(
                        "Failed to serialize login activity"
                    )

            return jsonify({

                "success":
                    True,

                "error":
                    None,

                "message":
                    "Login activity loaded successfully.",

                "activities":
                    data,

                "count":
                    len(data),
            })

        except Exception as exc:

            app.logger.exception(
                "Error loading admin login activity"
            )

            return jsonify({

                "success":
                    False,

                "error":
                    str(exc),

                "message":
                    "Failed to load login activity.",

                "activities": [],

                "count": 0,
            }), 500


    # ================================================================
    # ALL THREATS JSON API
    # ================================================================

    @app.route(
        "/api/threats",
        methods=["GET"],
    )
    @login_required
    def api_threats():

        try:

            threats_qs = (

                scoped_threat_query()

                .order_by(
                    ThreatEvent.created_at.desc()
                )

                .limit(200)

                .all()
            )

            return jsonify({

                "success":
                    True,

                "error":
                    None,

                "message":
                    "Threats loaded successfully.",

                "data": [

                    threat_to_dashboard_dict(t)

                    for t in threats_qs
                ],
            })

        except Exception as exc:

            app.logger.exception(
                "Error loading threats"
            )

            return jsonify({

                "success":
                    False,

                "error":
                    str(exc),

                "message":
                    "Failed to load threats.",

                "data": [],
            }), 500


    # ================================================================
    # IP THREAT INVESTIGATION API
    # ================================================================

    @app.route(
        "/api/threats/by-ip",
        methods=["GET"],
    )
    @login_required
    def api_threats_by_ip():

        try:

            raw_ip = request.args.get(
                "ip",
                "",
            )

            try:

                target_ip = normalize_ip_address(
                    raw_ip
                )

            except ValueError as exc:

                return jsonify({

                    "success":
                        False,

                    "error":
                        "INVALID_IP",

                    "message":
                        str(exc),

                    "data":
                        None,
                }), 400

            # ====================================================
            # IMPORTANT:
            #
            # This route is READ-ONLY.
            #
            # It NEVER creates a ThreatEvent.
            #
            # It only checks threats that were already detected
            # and stored by the detection engine.
            # ====================================================

            threats = (

                scoped_threat_query()

                .filter(

                    or_(

                        ThreatEvent.source_ip
                        == target_ip,

                        ThreatEvent.dest_ip
                        == target_ip,
                    )
                )

                .order_by(

                    ThreatEvent.created_at.desc()
                )

                .all()
            )

            # ----------------------------------------------------
            # Remove any invalid legacy Unknown Threat records
            # from the investigation response.
            #
            # They are not deleted here; they are simply not
            # counted as real threats.
            # ----------------------------------------------------

            valid_threats = []

            for threat in threats:

                category = classify_threat_type(
                    threat
                )

                if category == "unknown":

                    app.logger.warning(
                        "Ignoring unknown legacy ThreatEvent "
                        "during IP investigation: id=%s ip=%s",
                        getattr(
                            threat,
                            "id",
                            None,
                        ),
                        target_ip,
                    )

                    continue

                valid_threats.append(
                    threat
                )

            threats = valid_threats

            # ----------------------------------------------------
            # FIND ALL RELATED LOGS
            # ----------------------------------------------------

            total_logs = (

                LogEntry.query

                .filter(

                    or_(

                        LogEntry.source_ip
                        == target_ip,

                        LogEntry.dest_ip
                        == target_ip,
                    )
                )

                .count()
            )

            logs = (

                LogEntry.query

                .filter(

                    or_(

                        LogEntry.source_ip
                        == target_ip,

                        LogEntry.dest_ip
                        == target_ip,
                    )
                )

                .order_by(
                    LogEntry.id.desc()
                )

                .limit(50)

                .all()
            )

            # ----------------------------------------------------
            # Summary containers
            # ----------------------------------------------------

            severity_counts = {

                "critical": 0,

                "high": 0,

                "medium": 0,

                "low": 0,

                "unknown": 0,
            }

            status_counts = {}

            threat_type_counts = {}

            detection_source_counts = {}

            source_matches = 0

            destination_matches = 0

            both_matches = 0

            confidences = []

            users = set()

            related_ips = set()

            dates = []

            serialized_threats = []

            llm_explanations = []

            # ----------------------------------------------------
            # Process existing threats
            # ----------------------------------------------------

            for threat in threats:

                source_ip = safe_text(

                    getattr(
                        threat,
                        "source_ip",
                        None,
                    )

                ).strip()

                destination_ip = safe_text(

                    getattr(
                        threat,
                        "dest_ip",
                        None,
                    )

                ).strip()

                source_match = (
                    source_ip == target_ip
                )

                destination_match = (
                    destination_ip == target_ip
                )

                if source_match:
                    source_matches += 1

                if destination_match:
                    destination_matches += 1

                if (
                    source_match
                    and destination_match
                ):

                    both_matches += 1

                severity = safe_text(

                    getattr(
                        threat,
                        "severity",
                        None,
                    )

                ).strip().lower()

                if severity in severity_counts:

                    severity_counts[
                        severity
                    ] += 1

                else:

                    severity_counts[
                        "unknown"
                    ] += 1

                threat_type = ip_threat_type(
                    threat
                )

                threat_type_counts[
                    threat_type
                ] = (

                    threat_type_counts.get(
                        threat_type,
                        0,
                    )

                    + 1
                )

                detection_source = safe_text(

                    getattr(
                        threat,
                        "detection_source",
                        None,
                    )

                ).strip()

                if not detection_source:

                    detection_source = "Unknown"

                detection_source_counts[
                    detection_source
                ] = (

                    detection_source_counts.get(
                        detection_source,
                        0,
                    )

                    + 1
                )

                status = safe_text(

                    getattr(
                        threat,
                        "status",
                        None,
                    )

                ).strip()

                if not status:

                    status = "Unknown"

                status_counts[
                    status
                ] = (

                    status_counts.get(
                        status,
                        0,
                    )

                    + 1
                )

                confidence = normalize_percentage(

                    getattr(
                        threat,
                        "confidence",
                        0,
                    )
                )

                try:

                    confidences.append(
                        float(confidence)
                    )

                except (
                    TypeError,
                    ValueError,
                ):

                    pass

                user = safe_text(

                    getattr(
                        threat,
                        "user",
                        None,
                    )

                ).strip()

                if user:

                    users.add(
                        user
                    )

                if (
                    source_ip
                    and source_ip != target_ip
                ):

                    related_ips.add(
                        source_ip
                    )

                if (
                    destination_ip
                    and destination_ip != target_ip
                ):

                    related_ips.add(
                        destination_ip
                    )

                created_at = getattr(
                    threat,
                    "created_at",
                    None,
                )

                if created_at:

                    dates.append(
                        created_at
                    )

                llm_summary = safe_text(

                    getattr(
                        threat,
                        "llm_summary",
                        None,
                    )

                ).strip()

                if llm_summary:

                    llm_explanations.append(
                        llm_summary
                    )

                serialized_threats.append(

                    serialize_ip_threat(

                        threat,

                        target_ip,
                    )
                )

            # ----------------------------------------------------
            # Confidence
            # ----------------------------------------------------

            if confidences:

                average_confidence = round(

                    sum(
                        confidences
                    )
                    /
                    len(
                        confidences
                    ),

                    2,
                )

            else:

                average_confidence = 0

            # ----------------------------------------------------
            # First/last seen
            # ----------------------------------------------------

            if dates:

                first_seen = (
                    min(dates).isoformat()
                )

                last_seen = (
                    max(dates).isoformat()
                )

            else:

                first_seen = None

                last_seen = None

            # ----------------------------------------------------
            # Logs
            # ----------------------------------------------------

            serialized_logs = [

                serialize_ip_log(
                    log
                )

                for log in logs
            ]

            # ----------------------------------------------------
            # Unique LLM explanations
            # ----------------------------------------------------

            unique_llm_explanations = []

            for explanation in llm_explanations:

                if (
                    explanation
                    not in unique_llm_explanations
                ):

                    unique_llm_explanations.append(
                        explanation
                    )

            # ====================================================
            # RETURN INVESTIGATION RESULT
            #
            # IMPORTANT:
            # If zero threats exist, return zero.
            #
            # Do NOT create:
            #     Unknown Threat
            #     LOW
            #     0%
            #     detection_engine
            # ====================================================

            return jsonify({

                "success":
                    True,

                "error":
                    None,

                "message":

                    (
                        f"Found {len(threats)} "
                        f"real threat(s) associated with "
                        f"{target_ip}."
                    ),

                "data": {

                    "ip":
                        target_ip,

                    "found":
                        bool(threats),

                    "summary": {

                        "total_threats":
                            len(threats),

                        "source_matches":
                            source_matches,

                        "destination_matches":
                            destination_matches,

                        "both_matches":
                            both_matches,

                        "critical":
                            severity_counts[
                                "critical"
                            ],

                        "high":
                            severity_counts[
                                "high"
                            ],

                        "medium":
                            severity_counts[
                                "medium"
                            ],

                        "low":
                            severity_counts[
                                "low"
                            ],

                        "unknown_severity":
                            severity_counts[
                                "unknown"
                            ],

                        "average_confidence":
                            average_confidence,

                        "status_counts":
                            status_counts,

                        "threat_types":
                            threat_type_counts,

                        "detection_sources":
                            detection_source_counts,

                        "affected_users":
                            sorted(
                                users
                            ),

                        "related_ips":
                            sorted(
                                related_ips
                            ),

                        "first_seen":
                            first_seen,

                        "last_seen":
                            last_seen,

                        "log_count":
                            total_logs,

                        "displayed_logs":
                            len(
                                serialized_logs
                            ),

                        "llm_explanation_count":
                            len(
                                unique_llm_explanations
                            ),
                    },

                    "threats":
                        serialized_threats,

                    "logs":
                        serialized_logs,

                    "llm_explanation":
                        (
                            unique_llm_explanations[0]
                            if unique_llm_explanations
                            else ""
                        ),

                    "llm_explanations":
                        unique_llm_explanations,
                },
            })

        except Exception as exc:

            app.logger.exception(
                "IP threat investigation failed"
            )

            return jsonify({

                "success":
                    False,

                "error":
                    str(exc),

                "message":
                    "Failed to analyze threats for the supplied IP address.",

                "data":
                    None,
            }), 500


    # ================================================================
    # THREAT DETAILS COMPATIBILITY API
    # ================================================================

    @app.route(
        "/api/threats/details",
        methods=["GET"],
    )
    @login_required
    def api_threat_details():

        try:

            threat_type = request.args.get(
                "type"
            )

            threats_list = (

                scoped_threat_query()

                .order_by(
                    ThreatEvent.created_at.desc()
                )

                .limit(200)

                .all()
            )

            # ----------------------------------------------------
            # Never return meaningless Unknown Threat rows.
            # ----------------------------------------------------

            threats_list = [

                threat

                for threat
                in threats_list

                if classify_threat_type(
                    threat
                ) != "unknown"
            ]

            if threat_type:

                normalized_type = (

                    normalize_threat_type(
                        threat_type
                    )
                )

                if normalized_type not in (
                    "",
                    "threat",
                    "all",
                ):

                    threats_list = [

                        threat

                        for threat
                        in threats_list

                        if (

                            classify_threat_type(
                                threat
                            )

                            == normalized_type
                        )
                    ]

            return jsonify({

                "success":
                    True,

                "error":
                    None,

                "message":
                    "Threat details loaded successfully.",

                "data": [

                    threat.to_dict()

                    for threat
                    in threats_list
                ],

                "count":
                    len(
                        threats_list
                    ),
            })

        except Exception as exc:

            app.logger.exception(
                "Threat details API failed"
            )

            return jsonify({

                "success":
                    False,

                "error":
                    str(exc),

                "message":
                    "Failed to load threat details.",

                "data": [],

                "count": 0,
            }), 500


    # ================================================================
    # SINGLE THREAT DETAILS API
    # ================================================================

    @app.route(
        "/api/threats/<int:threat_id>",
        methods=["GET"],
    )
    @login_required
    def api_single_threat(
        threat_id
    ):

        try:

            threat = (

                scoped_threat_query().get_or_404(
                    threat_id
                )
            )

            if classify_threat_type(
                threat
            ) == "unknown":

                return jsonify({

                    "success":
                        False,

                    "error":
                        "UNKNOWN_THREAT",

                    "message":
                        "This threat record is invalid or no longer available.",

                    "data":
                        None,
                }), 404

            return jsonify({

                "success":
                    True,

                "error":
                    None,

                "message":
                    "Threat details loaded successfully.",

                "data":
                    threat.to_dict(),
            })

        except Exception as exc:

            app.logger.exception(
                "Error loading threat details"
            )

            return jsonify({

                "success":
                    False,

                "error":
                    str(exc),

                "message":
                    "Failed to load threat details.",

                "data":
                    None,
            }), 500


    # ================================================================
    # SINGLE THREAT PDF
    # ================================================================

    @app.route(
        "/api/threats/<int:threat_id>/pdf",
        methods=["GET"],
    )
    @login_required
    def download_threat_pdf(
        threat_id
    ):

        try:

            threat = (

                scoped_threat_query().get_or_404(
                    threat_id
                )
            )

            if classify_threat_type(
                threat
            ) == "unknown":

                return jsonify({

                    "success":
                        False,

                    "error":
                        "UNKNOWN_THREAT",

                    "message":
                        "Cannot generate a report for an invalid threat.",

                }), 404

            threat_dict = (
                threat.to_dict()
            )

            os.makedirs(

                Config.REPORTS_FOLDER,

                exist_ok=True,
            )

            filename = (

                "threat_"

                f"{threat_id}_"

                f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

                ".pdf"
            )

            output_path = os.path.join(

                Config.REPORTS_FOLDER,

                filename,
            )

            generate_threat_report(

                [
                    threat_dict
                ],

                output_path,

                generated_by=(
                    current_user.username
                ),
            )

            return send_from_directory(

                Config.REPORTS_FOLDER,

                filename,

                as_attachment=True,
            )

        except Exception as exc:

            app.logger.exception(
                "Single threat PDF generation failed"
            )

            return jsonify({

                "success":
                    False,

                "error":
                    str(exc),

                "message":
                    "Failed to generate threat PDF.",

            }), 500


    # ================================================================
    # RECENT THREATS API
    # ================================================================

    @app.route(
        "/api/threats/recent",
        methods=["GET"],
    )
    @login_required
    def api_recent_threats():

        try:

            limit = request.args.get(
                "limit",
                10,
                type=int,
            )

            limit = max(
                1,
                min(
                    limit,
                    100,
                ),
            )

            threats_qs = (

                scoped_threat_query()

                .order_by(
                    ThreatEvent.created_at.desc()
                )

                .limit(limit)

                .all()
            )

            threats_qs = [

                threat

                for threat
                in threats_qs

                if classify_threat_type(
                    threat
                ) != "unknown"
            ]

            return jsonify({

                "success":
                    True,

                "error":
                    None,

                "message":
                    "Recent threats loaded successfully.",

                "data": [

                    threat_to_dashboard_dict(t)

                    for t in threats_qs
                ],
            })

        except Exception as exc:

            app.logger.exception(
                "Recent threats API failed"
            )

            return jsonify({

                "success":
                    False,

                "error":
                    str(exc),

                "message":
                    "Failed to load recent threats.",

                "data": [],
            }), 500


    # ================================================================
    # THREAT COUNTS BY TYPE
    # ================================================================

    @app.route(
        "/api/threats/types",
        methods=["GET"],
    )
    @login_required
    def api_threat_types():

        try:

            threats_list = (
                scoped_threat_query().all()
            )

            counts = {

                "brute_force": 0,

                "powershell_execution": 0,

                "privilege_escalation": 0,

                "network_scan": 0,

                "reverse_shell": 0,

                "malware_execution": 0,

                "data_exfiltration": 0,

                "registry_persistence": 0,

                "scheduled_task_persistence": 0,

                "c2_beaconing": 0,

                "mass_file_deletion": 0,

                "firewall_tampering": 0,

                "sql_injection": 0,

                "command_injection": 0,

                "suspicious_ip": 0,

                "unknown": 0,
            }

            for threat in threats_list:

                category = classify_threat_type(
                    threat
                )

                if category not in counts:

                    category = "unknown"

                counts[
                    category
                ] += 1

            return jsonify({

                "success":
                    True,

                "error":
                    None,

                "message":
                    "Threat type statistics loaded.",

                "data":
                    counts,
            })

        except Exception as exc:

            app.logger.exception(
                "Threat type statistics failed"
            )

            return jsonify({

                "success":
                    False,

                "error":
                    str(exc),

                "message":
                    "Failed to load threat type statistics.",

                "data": {},
            }), 500


    # ================================================================
    # COMPATIBILITY / AUTH ROUTES
    # ================================================================

    @app.route(
        "/auth/analyze",
        methods=["GET"],
    )
    @login_required
    def auth_analyze():

        return render_template(
            "analyze.html"
        )


    @app.route(
        "/auth/alerts",
        methods=["GET"],
    )
    @login_required
    def auth_alerts():

        alerts = (
            scoped_alert_query()
            .order_by(Alert.sent_at.desc())
            .limit(100)
            .all()
        )

        return render_template(

            "alerts.html",

            alerts=alerts,
        )


    # ================================================================
    # SECURITY HISTORY
    # ================================================================

    @app.route(
        "/auth/history",
        methods=["GET"],
    )
    @login_required
    def auth_history():
        """Show a persistent history of detected threats and email alerts."""

        limit = request.args.get("limit", 200, type=int)
        limit = max(1, min(500, limit))

        # Keep history user-scoped for normal users; administrators can
        # review the complete system history.
        threat_query = (
            scoped_threat_query()
            .order_by(ThreatEvent.created_at.desc())
        )
        threats_history = threat_query.limit(limit).all()

        # Alert has no created_at in the current schema, so sent_at is
        # the correct notification timestamp and ordering field.
        alerts_history = (
            scoped_alert_query()
            .order_by(Alert.sent_at.desc())
            .limit(limit)
            .all()
        )

        return render_template(
            "history.html",
            threats_history=threats_history,
            alerts_history=alerts_history,
        )


    # ================================================================
    # /threats COMPATIBILITY ROUTE
    # ================================================================

    @app.route(
        "/threats",
        methods=["GET"],
    )
    @login_required
    def threats_compat():

        return redirect(
            url_for("threats")
        )


    # ================================================================
    # LIVE MONITOR API
    # ================================================================

    @app.route("/api/live/status", methods=["GET"])
    @login_required
    def live_status():
        return jsonify({
            "success": True,
            "data": live_monitor.status(),
        })

    @app.route("/api/live/threats", methods=["GET"])
    @login_required
    def live_threats():
        limit = request.args.get("limit", 25, type=int)
        limit = max(1, min(100, limit))
        recent = live_monitor.status()["recent_threats"]
        if current_user_is_admin():
            data = recent[:limit]
        else:
            data = [
                item for item in recent
                if item.get("owner_user_id") == int(current_user.id)
            ][:limit]
        return jsonify({
            "success": True,
            "data": data,
        })

    @app.route("/api/live/start", methods=["POST"])
    @login_required
    def live_start():
        try:
            if live_monitor.running and live_monitor.owner_user_id not in {None, current_user.id} and not current_user_is_admin():
                return jsonify({
                    "success": False,
                    "error": "LIVE_MONITOR_IN_USE",
                    "message": "Live threat monitoring is currently running for another user.",
                }), 409

            live_monitor.owner_user_id = current_user.id
            started = live_monitor.start()
            return jsonify({
                "success": True,
                "started": started,
                "message": "Live threat monitor started." if started else "Live threat monitor is already running.",
                "data": live_monitor.status(),
            })
        except Exception as exc:
            app.logger.exception("Live monitor start failed")
            return jsonify({
                "success": False,
                "error": str(exc),
                "message": "Unable to start live threat monitor.",
            }), 500

    @app.route("/api/live/stop", methods=["POST"])
    @login_required
    def live_stop():
        try:
            if (
                live_monitor.running
                and not current_user_is_admin()
                and live_monitor.owner_user_id not in {None, current_user.id}
            ):
                return jsonify({
                    "success": False,
                    "error": "LIVE_MONITOR_IN_USE",
                    "message": "You cannot stop another user's live monitor.",
                }), 403

            stopped = live_monitor.stop()
            if stopped:
                live_monitor.owner_user_id = None
            return jsonify({
                "success": True,
                "stopped": stopped,
                "message": "Live threat monitor stopped." if stopped else "Live threat monitor is already stopped.",
                "data": live_monitor.status(),
            })
        except Exception as exc:
            app.logger.exception("Live monitor stop failed")
            return jsonify({
                "success": False,
                "error": str(exc),
                "message": "Unable to stop live threat monitor.",
            }), 500

    @app.route("/auth/live", methods=["GET"])
    @login_required
    def auth_live():
        # JSON avoids requiring a new template just to use the live API.
        return jsonify({
            "success": True,
            "message": "Live threat detection API is available.",
            "endpoints": {
                "status": url_for("live_status"),
                "threats": url_for("live_threats"),
                "start": url_for("live_start"),
                "stop": url_for("live_stop"),
            },
            "data": live_monitor.status(),
        })


    # ================================================================
    # ERROR HANDLERS
    # ================================================================

    @app.errorhandler(404)
    def not_found(error):

        return error_response(

            "Resource not found.",

            404,
        )


    @app.errorhandler(413)
    def too_large(error):

        return error_response(

            "Uploaded file is too large.",

            413,
        )


    @app.errorhandler(500)
    def internal_server_error(error):

        try:

            db.session.rollback()

        except Exception:

            pass

        app.logger.exception(
            "Internal server error"
        )

        return error_response(

            "Internal server error.",

            500,
        )


    # ================================================================
    # RETURN APPLICATION
    # ================================================================

    return app



# ================================================================
# DATABASE COMPATIBILITY
# ================================================================

def ensure_alert_status_column(app):
    """Add Alert.status to older SQLite databases when necessary."""
    try:
        # db.engine is Flask-SQLAlchemy scoped and requires an active
        # Flask application context.
        with app.app_context():
            if not str(db.engine.url).startswith("sqlite"):
                return

            inspector = inspect(db.engine)
            columns = {
                column["name"]
                for column in inspector.get_columns("alerts")
            }

            # The column already exists in the current database.
            # Do not attempt another ALTER TABLE.
            if "status" in columns:
                app.logger.info(
                    "alerts.status column already exists; no migration needed."
                )
                return

            with db.engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE alerts "
                        "ADD COLUMN status VARCHAR(20) "
                        "DEFAULT 'SUPPRESSED' NOT NULL"
                    )
                )

            app.logger.info(
                "Added missing alerts.status column to SQLite database."
            )

    except Exception:
        app.logger.exception(
            "Unable to migrate alerts.status column automatically."
        )


# ================================================================
# CREATE APPLICATION
# ================================================================

app = create_app()


# ================================================================
# START APPLICATION
# ================================================================

if __name__ == "__main__":

    app.run(

        host=Config.HOST,

        port=Config.PORT,

        debug=Config.DEBUG,
    )