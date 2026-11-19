"""
Log_Processing/log_parser.py
Parses raw log lines from several common formats into a list of
loosely-structured dictionaries. Unmatched lines fall back to a
generic "unknown" record so nothing is silently dropped.

Supported formats (best-effort, regex-based):
  - Linux syslog / sshd auth logs
  - Apache / Nginx combined access logs
  - Windows Security Event log style lines (EventID=...)
  - Generic firewall / port-scan style lines
  - Generic application log lines
"""

import re
from datetime import datetime

# --- Regex patterns -------------------------------------------------------

SYSLOG_SSHD_FAILED = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (invalid user )?"
    r"(?P<user>\S+) from (?P<src_ip>[\d.]+) port (?P<port>\d+)"
)

SYSLOG_SSHD_ACCEPTED = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted (password|publickey) for "
    r"(?P<user>\S+) from (?P<src_ip>[\d.]+) port (?P<port>\d+)"
)

WEB_ACCESS_LOG = re.compile(
    r"(?P<src_ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<request_line>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)\s+\"[^\"]*\"\s+\"(?P<agent>[^\"]*)\""
)
REQUEST_LINE_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>.*)\s+HTTP/[\d.]+$")

PORT_SCAN_LINE = re.compile(
    r"(?P<src_ip>[\d.]+)\s+attempted connection to port\s+(?P<port>\d+)\s+on host\s+"
    r"(?P<dst_ip>[\d.]+)"
)

WINDOWS_EVENT = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+EventID=(?P<event_id>\d+)\s+Account Name:\s*(?P<user>\S+)\s+"
    r"Source Network Address:\s*(?P<src_ip>[\d.]+)"
)

GENERIC_SYSLOG_PREFIX = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.*)"
)

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

CURRENT_YEAR = datetime.utcnow().year


def _build_syslog_timestamp(month, day, time_str):
    try:
        dt = datetime.strptime(f"{CURRENT_YEAR} {month} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S")
        return dt
    except ValueError:
        return None


def parse_line(line: str) -> dict:
    """Parse a single raw log line into a structured dict."""
    line = line.strip()
    if not line:
        return None

    # SSH failed login
    m = SYSLOG_SSHD_FAILED.search(line)
    if m:
        return {
            "log_type": "ssh_auth",
            "event": "failed_login",
            "timestamp": _build_syslog_timestamp(m["month"], m["day"], m["time"]),
            "source_ip": m["src_ip"],
            "dest_ip": None,
            "user": m["user"],
            "raw_line": line,
            "extra": {"port": m["port"], "host": m["host"]},
        }

    # SSH accepted login
    m = SYSLOG_SSHD_ACCEPTED.search(line)
    if m:
        return {
            "log_type": "ssh_auth",
            "event": "successful_login",
            "timestamp": _build_syslog_timestamp(m["month"], m["day"], m["time"]),
            "source_ip": m["src_ip"],
            "dest_ip": None,
            "user": m["user"],
            "raw_line": line,
            "extra": {"port": m["port"], "host": m["host"]},
        }

    # Web access log (Apache/Nginx combined)
    m = WEB_ACCESS_LOG.search(line)
    if m:
        req_match = REQUEST_LINE_RE.match(m["request_line"].strip())
        method = req_match["method"] if req_match else ""
        path = req_match["path"] if req_match else m["request_line"]
        return {
            "log_type": "web_access",
            "event": "http_request",
            "timestamp": None,  # kept as raw apache format string in extra
            "source_ip": m["src_ip"],
            "dest_ip": None,
            "user": None,
            "raw_line": line,
            "extra": {
                "method": method,
                "path": path,
                "status": m["status"],
                "size": m["size"],
                "agent": m["agent"],
                "raw_timestamp": m["timestamp"],
            },
        }

    # Port scan style line
    m = PORT_SCAN_LINE.search(line)
    if m:
        return {
            "log_type": "network",
            "event": "connection_attempt",
            "timestamp": None,
            "source_ip": m["src_ip"],
            "dest_ip": m["dst_ip"],
            "user": None,
            "raw_line": line,
            "extra": {"port": m["port"]},
        }

    # Windows-style event log line
    m = WINDOWS_EVENT.search(line)
    if m:
        event_id = m["event_id"]
        event_name = "failed_login" if event_id == "4625" else (
            "successful_login" if event_id == "4624" else f"event_{event_id}"
        )
        return {
            "log_type": "windows_event",
            "event": event_name,
            "timestamp": _build_syslog_timestamp(m["month"], m["day"], m["time"]),
            "source_ip": m["src_ip"],
            "dest_ip": None,
            "user": m["user"],
            "raw_line": line,
            "extra": {"event_id": event_id, "host": m["host"]},
        }

    # Generic syslog-prefixed application line
    m = GENERIC_SYSLOG_PREFIX.search(line)
    if m:
        ip_matches = IP_REGEX.findall(m["message"])
        return {
            "log_type": "application",
            "event": "generic",
            "timestamp": _build_syslog_timestamp(m["month"], m["day"], m["time"]),
            "source_ip": ip_matches[0] if ip_matches else None,
            "dest_ip": ip_matches[1] if len(ip_matches) > 1 else None,
            "user": None,
            "raw_line": line,
            "extra": {"process": m["process"], "message": m["message"]},
        }

    # Fallback: unknown format, still capture any IPs found
    ip_matches = IP_REGEX.findall(line)
    return {
        "log_type": "unknown",
        "event": "unparsed",
        "timestamp": None,
        "source_ip": ip_matches[0] if ip_matches else None,
        "dest_ip": ip_matches[1] if len(ip_matches) > 1 else None,
        "user": None,
        "raw_line": line,
        "extra": {},
    }


def parse_lines(lines) -> list:
    """Parse a list of raw log lines, skipping empties."""
    parsed = []
    for line in lines:
        record = parse_line(line)
        if record:
            parsed.append(record)
    return parsed
