"""
live_detection_service.py

Live autonomous threat detection service.

Connects:

    LiveLogMonitor
          ↓
    DetectionEngine
          ↓
    ThreatEvent
          ↓
    Alert
          ↓
    Email

The service intentionally does NOT perform a global database
duplicate check.

A new live detection is allowed to create a new ThreatEvent.
"""

import threading
import time
from collections import OrderedDict


class LiveDetectionService:

    def __init__(
        self,
        app,
        detection_engine,
        build_threat_event,
        is_unknown_finding,
        send_email_alert=None,
        db=None,
        Alert=None,
        logger=None,
        dedup_seconds=30,
    ):
        self.app = app

        self.detection_engine = (
            detection_engine
        )

        self.build_threat_event = (
            build_threat_event
        )

        self.is_unknown_finding = (
            is_unknown_finding
        )

        self.send_email_alert = (
            send_email_alert
        )

        self.db = db

        self.Alert = Alert

        self.logger = logger

        self.dedup_seconds = max(
            int(dedup_seconds),
            0,
        )

        self._lock = threading.RLock()

        self._recent_fingerprints = (
            OrderedDict()
        )

        self._running = False

        self._started_at = None

        self._processed_batches = 0

        self._processed_lines = 0

        self._detected_threats = 0

        self._saved_threats = 0

        self._skipped_threats = 0

        self._failed_threats = 0

        self._last_source = None

        self._last_detection_at = None

        self._last_error = None


    # ============================================================
    # LOGGING
    # ============================================================

    def _log(
        self,
        level,
        message,
        *args,
    ):
        logger = (
            self.logger
        )

        if logger is None:
            return

        try:
            method = getattr(
                logger,
                level,
                None,
            )

            if method:
                method(
                    message,
                    *args,
                )

        except Exception:
            pass


    # ============================================================
    # STATUS
    # ============================================================

    def status(self):
        with self._lock:
            return {
                "running": self._running,
                "started_at": self._started_at,
                "processed_batches": (
                    self._processed_batches
                ),
                "processed_lines": (
                    self._processed_lines
                ),
                "detected_threats": (
                    self._detected_threats
                ),
                "saved_threats": (
                    self._saved_threats
                ),
                "skipped_threats": (
                    self._skipped_threats
                ),
                "failed_threats": (
                    self._failed_threats
                ),
                "last_source": (
                    self._last_source
                ),
                "last_detection_at": (
                    self._last_detection_at
                ),
                "last_error": (
                    self._last_error
                ),
            }


    # ============================================================
    # START
    # ============================================================

    def mark_started(self):
        with self._lock:
            self._running = True

            self._started_at = time.time()

            self._last_error = None


    # ============================================================
    # STOP
    # ============================================================

    def mark_stopped(self):
        with self._lock:
            self._running = False


    # ============================================================
    # FINDING FINGERPRINT
    # ============================================================

    def _fingerprint(
        self,
        source_name,
        finding,
    ):
        try:
            from live_log_monitor import (
                evidence_fingerprint,
            )

            return evidence_fingerprint(
                source_name,
                finding,
            )

        except Exception:
            return None


    def _is_recent_duplicate(
        self,
        fingerprint,
    ):
        if not fingerprint:
            return False

        if self.dedup_seconds <= 0:
            return False

        now = time.time()

        with self._lock:

            # ----------------------------------------------------
            # Remove expired fingerprints.
            # ----------------------------------------------------

            expired = []

            for key, timestamp in (
                self._recent_fingerprints.items()
            ):
                if (
                    now - timestamp
                    > self.dedup_seconds
                ):
                    expired.append(
                        key
                    )

            for key in expired:
                self._recent_fingerprints.pop(
                    key,
                    None,
                )

            # ----------------------------------------------------
            # Check current fingerprint.
            # ----------------------------------------------------

            previous = (
                self._recent_fingerprints.get(
                    fingerprint
                )
            )

            if previous is not None:
                return True

            self._recent_fingerprints[
                fingerprint
            ] = now

        return False


    # ============================================================
    # ENGINE EXECUTION
    # ============================================================

    def _run_engine(
        self,
        text,
        source_name,
    ):
        """
        Call the existing DetectionEngine.

        The project has historically exposed detection through
        different method names. This adapter supports the normal
        run()/detect() patterns without changing the engine.
        """

        engine = (
            self.detection_engine
        )

        # --------------------------------------------------------
        # Preferred interface.
        # --------------------------------------------------------

        if hasattr(
            engine,
            "run",
        ):
            try:
                result = engine.run(
                    text,
                    source_name=source_name,
                )
                return result
            except TypeError:
                # Some versions don't accept source_name.
                return engine.run(
                    text
                )

        # --------------------------------------------------------
        # Compatibility interface.
        # --------------------------------------------------------

        if hasattr(
            engine,
            "detect",
        ):
            try:
                return engine.detect(
                    text,
                    source_name=source_name,
                )
            except TypeError:
                return engine.detect(
                    text
                )

        raise RuntimeError(
            "DetectionEngine does not expose "
            "run() or detect()."
        )


    # ============================================================
    # EXTRACT FINDINGS
    # ============================================================

    @staticmethod
    def _extract_findings(result):
        if result is None:
            return []

        if isinstance(
            result,
            dict,
        ):
            findings = result.get(
                "findings"
            )

            if isinstance(
                findings,
                list,
            ):
                return findings

            # Some detector versions return
            # a single finding dictionary.
            if (
                result.get(
                    "threat_type"
                )
                or result.get(
                    "type"
                )
                or result.get(
                    "classification"
                )
            ):
                return [result]

            return []

        if isinstance(
            result,
            list,
        ):
            return result

        return []


    # ============================================================
    # MAIN CALLBACK
    # ============================================================

    def process_batch(
        self,
        source_name,
        text,
    ):
        """
        Process one live batch.

        This function is called by LiveLogMonitor.
        """

        if not text or not str(
            text
        ).strip():
            return {
                "success": True,
                "findings": 0,
                "saved": 0,
                "skipped": 0,
            }

        with self._lock:
            self._processed_batches += 1

            self._last_source = (
                source_name
            )

            self._last_error = None

            self._processed_lines += len(
                str(text).splitlines()
            )

        # --------------------------------------------------------
        # Detection must execute inside Flask application context
        # because downstream project code may use Config, models,
        # database sessions, etc.
        # --------------------------------------------------------

        with self.app.app_context():

            try:
                result = self._run_engine(
                    text,
                    source_name,
                )

            except Exception as exc:

                with self._lock:
                    self._last_error = str(
                        exc
                    )

                self._log(
                    "exception",
                    "Live DetectionEngine failure: %s",
                    exc,
                )

                return {
                    "success": False,
                    "findings": 0,
                    "saved": 0,
                    "skipped": 0,
                    "error": str(
                        exc
                    ),
                }

            findings = (
                self._extract_findings(
                    result
                )
            )

            saved = 0

            skipped = 0

            failed = 0

            # ----------------------------------------------------
            # Process EVERY finding.
            #
            # Important:
            #
            # IP A / brute_force
            # IP A / powershell_execution
            # IP B / brute_force
            #
            # remain three separate events.
            # ----------------------------------------------------

            for finding in findings:

                if not isinstance(
                    finding,
                    dict,
                ):
                    skipped += 1
                    continue

                try:

                    if self.is_unknown_finding(
                        finding
                    ):
                        skipped += 1

                        self._log(
                            "warning",
                            "Ignoring unknown live finding: %s",
                            finding,
                        )

                        continue

                    # ------------------------------------------------
                    # Live source marker.
                    # ------------------------------------------------

                    finding = dict(
                        finding
                    )

                    existing_source = (
                        finding.get(
                            "detection_source"
                        )
                    )

                    if not existing_source:
                        finding[
                            "detection_source"
                        ] = (
                            "live_detection_engine"
                        )

                    # ------------------------------------------------
                    # Protect against the same exact finding being
                    # emitted repeatedly while the same evidence is
                    # still inside the rolling context.
                    # ------------------------------------------------

                    fingerprint = (
                        self._fingerprint(
                            source_name,
                            finding,
                        )
                    )

                    if self._is_recent_duplicate(
                        fingerprint
                    ):
                        skipped += 1

                        continue

                    # ------------------------------------------------
                    # Build ThreatEvent using the EXISTING project
                    # function.
                    # ------------------------------------------------

                    event = (
                        self.build_threat_event(
                            finding
                        )
                    )

                    if event is None:
                        skipped += 1
                        continue

                    # ------------------------------------------------
                    # Ensure live events are independent database
                    # records.
                    #
                    # There is intentionally NO:
                    #
                    # ThreatEvent.query.filter(...)
                    #
                    # here.
                    # ------------------------------------------------

                    self.db.session.add(
                        event
                    )

                    self.db.session.flush()

                    saved += 1

                    with self._lock:
                        self._detected_threats += 1

                    # ------------------------------------------------
                    # Email alert.
                    # ------------------------------------------------

                    self._create_email_alert(
                        event,
                        finding,
                    )

                except Exception as exc:

                    failed += 1

                    with self._lock:
                        self._failed_threats += 1
                        self._last_error = str(
                            exc
                        )

                    self._log(
                        "exception",
                        "Failed to save live threat: %s",
                        exc,
                    )

            # --------------------------------------------------------
            # Commit all live events from this batch.
            # --------------------------------------------------------

            try:
                self.db.session.commit()

                with self._lock:
                    self._saved_threats += saved

                    self._last_detection_at = (
                        time.time()
                    )

            except Exception as exc:

                self.db.session.rollback()

                with self._lock:
                    self._last_error = str(
                        exc
                    )

                self._log(
                    "exception",
                    "Live threat database commit failed: %s",
                    exc,
                )

                return {
                    "success": False,
                    "findings": len(
                        findings
                    ),
                    "saved": 0,
                    "skipped": skipped,
                    "failed": failed,
                    "error": str(
                        exc
                    ),
                }

        return {
            "success": True,
            "findings": len(
                findings
            ),
            "saved": saved,
            "skipped": skipped,
            "failed": failed,
        }


    # ============================================================
    # EMAIL ALERT
    # ============================================================

    def _create_email_alert(
        self,
        event,
        finding,
    ):
        """
        Create Alert record.

        Supports:

            SENT
            FAILED
            SUPPRESSED

        and preserves the existing boolean `sent` field.
        """

        if (
            self.Alert is None
            or self.send_email_alert is None
        ):
            return

        try:

            status, error_message = (
                self.send_email_alert(
                    finding
                )
            )

            status = str(
                status or "FAILED"
            ).strip().upper()

            if status not in (
                "SENT",
                "FAILED",
                "SUPPRESSED",
            ):
                status = "FAILED"

            was_sent = (
                status == "SENT"
            )

            alert = self.Alert(
                threat_event_id=event.id,
                channel="email",
                status=status,
                sent=was_sent,
                sent_at=(
                    self._utcnow()
                    if was_sent
                    else None
                ),
                error=error_message,
            )

            self.db.session.add(
                alert
            )

        except Exception as exc:

            self._log(
                "exception",
                "Live email alert failed: %s",
                exc,
            )

            try:
                alert = self.Alert(
                    threat_event_id=event.id,
                    channel="email",
                    status="FAILED",
                    sent=False,
                    sent_at=None,
                    error=str(exc),
                )

                self.db.session.add(
                    alert
                )

            except Exception:
                pass


    @staticmethod
    def _utcnow():
        from datetime import datetime

        return datetime.utcnow()


    # ============================================================
    # RESET
    # ============================================================

    def reset_recent_deduplication(self):
        with self._lock:
            self._recent_fingerprints.clear()