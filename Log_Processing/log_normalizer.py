"""
Log_Processing/log_normalizer.py
Takes loosely-structured records from log_parser and normalizes them into
a consistent schema ready for storage and feature extraction.
"""

import json
from datetime import datetime


NORMALIZED_FIELDS = [
    "log_type", "event", "timestamp", "source_ip", "dest_ip",
    "user", "raw_line", "extra_json",
]


def normalize_record(record: dict, source_file: str = None) -> dict:
    """Ensure every field is present with a safe default and JSON-serialize extras."""
    if record is None:
        return None

    timestamp = record.get("timestamp")
    if isinstance(timestamp, datetime):
        ts_value = timestamp
    else:
        ts_value = None

    extra = record.get("extra") or {}
    try:
        extra_json = json.dumps(extra, default=str)
    except (TypeError, ValueError):
        extra_json = "{}"

    return {
        "source_file": source_file,
        "log_type": record.get("log_type", "unknown"),
        "event": record.get("event", "unparsed"),
        "timestamp": ts_value,
        "source_ip": record.get("source_ip"),
        "dest_ip": record.get("dest_ip"),
        "user": record.get("user"),
        "raw_line": record.get("raw_line", ""),
        "extra_json": extra_json,
        "extra": extra,  # kept in-memory (not persisted directly) for downstream use
    }


def normalize_records(records, source_file: str = None) -> list:
    normalized = []
    for record in records:
        norm = normalize_record(record, source_file=source_file)
        if norm:
            normalized.append(norm)
    return normalized
