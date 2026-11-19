"""
Log_Processing/feature_extractor.py
Aggregates normalized log records into per-source-IP numeric feature
vectors that can be fed into the ML and anomaly detection models.

Feature vector (order matters - must match training in train_model.py):
  [
    failed_login_count,
    successful_login_count,
    unique_users,
    unique_dest_ports,
    http_error_count,
    http_request_count,
    distinct_paths,
    total_events,
    night_time_ratio,     # fraction of events between 00:00-05:00
  ]
"""

from collections import defaultdict
import datetime

FEATURE_NAMES = [
    "failed_login_count",
    "successful_login_count",
    "unique_users",
    "unique_dest_ports",
    "http_error_count",
    "http_request_count",
    "distinct_paths",
    "total_events",
    "night_time_ratio",
]


def _is_night(timestamp):
    if not timestamp:
        return False
    hour = timestamp.hour if isinstance(timestamp, datetime.datetime) else None
    return hour is not None and (hour < 5 or hour >= 23)


def extract_features_per_ip(normalized_records: list) -> dict:
    """
    Groups normalized records by source_ip and computes a feature dict for each.
    Returns: { ip: {feature_name: value, ...}, ... }
    """
    buckets = defaultdict(lambda: {
        "failed_login_count": 0,
        "successful_login_count": 0,
        "users": set(),
        "ports": set(),
        "http_error_count": 0,
        "http_request_count": 0,
        "paths": set(),
        "total_events": 0,
        "night_events": 0,
    })

    for rec in normalized_records:
        ip = rec.get("source_ip")
        if not ip:
            continue

        bucket = buckets[ip]
        bucket["total_events"] += 1

        if rec.get("event") == "failed_login":
            bucket["failed_login_count"] += 1
        elif rec.get("event") == "successful_login":
            bucket["successful_login_count"] += 1

        if rec.get("user"):
            bucket["users"].add(rec["user"])

        extra = rec.get("extra") or {}
        if "port" in extra:
            bucket["ports"].add(str(extra["port"]))

        if rec.get("log_type") == "web_access":
            bucket["http_request_count"] += 1
            status = str(extra.get("status", ""))
            if status.startswith(("4", "5")):
                bucket["http_error_count"] += 1
            if "path" in extra:
                bucket["paths"].add(extra["path"])

        if _is_night(rec.get("timestamp")):
            bucket["night_events"] += 1

    features = {}
    for ip, b in buckets.items():
        total = max(b["total_events"], 1)
        features[ip] = {
            "failed_login_count": b["failed_login_count"],
            "successful_login_count": b["successful_login_count"],
            "unique_users": len(b["users"]),
            "unique_dest_ports": len(b["ports"]),
            "http_error_count": b["http_error_count"],
            "http_request_count": b["http_request_count"],
            "distinct_paths": len(b["paths"]),
            "total_events": b["total_events"],
            "night_time_ratio": round(b["night_events"] / total, 3),
        }
    return features


def feature_dict_to_vector(feature_dict: dict) -> list:
    """Convert a per-IP feature dict into an ordered numeric vector."""
    return [feature_dict.get(name, 0) for name in FEATURE_NAMES]
