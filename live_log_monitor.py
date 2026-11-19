"""
live_log_monitor.py

Continuous live log monitoring for the
Autonomous Threat Hunting System.

Responsibilities
---------------
- Monitor one or more log files.
- Read only newly appended lines.
- Handle log truncation.
- Handle log rotation/replacement.
- Maintain a rolling context window.
- Send batches of new log data to the detection callback.
- Prevent repeated processing of the same live evidence.
"""

import hashlib
import os
import threading
import time
from collections import deque


class LiveLogMonitor:
    """
    Tail-like live log monitor.

    The monitor itself does NOT know anything about Flask,
    SQLAlchemy, ThreatEvent, Alert, or email.

    It simply watches files and calls:

        on_batch(source_name, text)

    whenever new lines arrive.
    """

    def __init__(
        self,
        on_batch,
        poll_interval=2.0,
        batch_lines=200,
        context_lines=500,
        start_at_end=True,
        logger=None,
    ):
        self.on_batch = on_batch

        self.poll_interval = max(
            float(poll_interval),
            0.25,
        )

        self.batch_lines = max(
            int(batch_lines),
            1,
        )

        self.context_lines = max(
            int(context_lines),
            1,
        )

        self.start_at_end = bool(
            start_at_end
        )

        self.logger = logger

        self._stop_event = threading.Event()

        self._thread = None

        self._files = {}

        self._lock = threading.RLock()

        self._running = False

        self._started_at = None

        self._last_cycle_at = None

        self._last_error = None

        self._processed_lines = 0

        self._processed_batches = 0

        self._detected_callbacks = 0


    # ============================================================
    # LOGGING
    # ============================================================

    def _log(self, level, message, *args):
        if self.logger is None:
            return

        try:
            method = getattr(
                self.logger,
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
    # FILE REGISTRATION
    # ============================================================

    def add_file(self, path):
        """
        Register a file for monitoring.
        """

        if not path:
            return False

        path = os.path.abspath(
            os.path.expanduser(
                os.path.expandvars(
                    str(path)
                )
            )
        )

        with self._lock:
            if path not in self._files:
                self._files[path] = {
                    "path": path,
                    "offset": 0,
                    "inode": None,
                    "size": 0,
                    "initialized": False,
                    "context": deque(
                        maxlen=self.context_lines
                    ),
                    "last_error": None,
                }

        return True


    def remove_file(self, path):
        path = os.path.abspath(
            os.path.expanduser(
                os.path.expandvars(
                    str(path)
                )
            )
        )

        with self._lock:
            self._files.pop(
                path,
                None,
            )


    def set_files(self, paths):
        """
        Replace the monitored file list.
        """

        normalized = []

        for path in paths or []:
            if not path:
                continue

            path = os.path.abspath(
                os.path.expanduser(
                    os.path.expandvars(
                        str(path)
                    )
                )
            )

            if path not in normalized:
                normalized.append(path)

        with self._lock:
            existing = set(
                self._files.keys()
            )

            wanted = set(normalized)

            for path in existing - wanted:
                self._files.pop(
                    path,
                    None,
                )

            for path in normalized:
                if path not in self._files:
                    self._files[path] = {
                        "path": path,
                        "offset": 0,
                        "inode": None,
                        "size": 0,
                        "initialized": False,
                        "context": deque(
                            maxlen=self.context_lines
                        ),
                        "last_error": None,
                    }


    # ============================================================
    # STATUS
    # ============================================================

    @property
    def running(self):
        return self._running


    def status(self):
        with self._lock:
            files = []

            for state in self._files.values():
                files.append(
                    {
                        "path": state["path"],
                        "exists": os.path.exists(
                            state["path"]
                        ),
                        "offset": state["offset"],
                        "size": state["size"],
                        "initialized": state[
                            "initialized"
                        ],
                        "last_error": state[
                            "last_error"
                        ],
                    }
                )

            return {
                "running": self._running,
                "started_at": self._started_at,
                "last_cycle_at": self._last_cycle_at,
                "last_error": self._last_error,
                "processed_lines": self._processed_lines,
                "processed_batches": self._processed_batches,
                "detected_callbacks": self._detected_callbacks,
                "files": files,
            }


    # ============================================================
    # START
    # ============================================================

    def start(self):
        with self._lock:
            if self._running:
                return False

            self._stop_event.clear()

            self._running = True

            self._started_at = time.time()

            self._last_error = None

            self._thread = threading.Thread(
                target=self._run,
                name="live-threat-monitor",
                daemon=True,
            )

            self._thread.start()

        self._log(
            "info",
            "Live log monitor started.",
        )

        return True


    # ============================================================
    # STOP
    # ============================================================

    def stop(self, timeout=5):
        with self._lock:
            if not self._running:
                return False

            self._stop_event.set()

            thread = self._thread

        if thread is not None:
            thread.join(
                timeout=max(
                    float(timeout),
                    0.1,
                )
            )

        with self._lock:
            self._running = False
            self._thread = None

        self._log(
            "info",
            "Live log monitor stopped.",
        )

        return True


    # ============================================================
    # THREAD
    # ============================================================

    def _run(self):
        try:
            while not self._stop_event.is_set():

                cycle_started = time.time()

                try:
                    self._scan_all_files()

                    with self._lock:
                        self._last_cycle_at = (
                            time.time()
                        )
                        self._last_error = None

                except Exception as exc:

                    with self._lock:
                        self._last_error = str(
                            exc
                        )

                    self._log(
                        "exception",
                        "Live monitor cycle failed: %s",
                        exc,
                    )

                elapsed = (
                    time.time()
                    - cycle_started
                )

                remaining = max(
                    self.poll_interval
                    - elapsed,
                    0.05,
                )

                self._stop_event.wait(
                    remaining
                )

        finally:
            with self._lock:
                self._running = False


    # ============================================================
    # SCAN FILES
    # ============================================================

    def _scan_all_files(self):
        with self._lock:
            paths = list(
                self._files.keys()
            )

        for path in paths:

            if self._stop_event.is_set():
                break

            try:
                self._read_new_data(
                    path
                )

            except Exception as exc:

                with self._lock:
                    state = self._files.get(
                        path
                    )

                    if state:
                        state["last_error"] = str(
                            exc
                        )

                    self._last_error = str(
                        exc
                    )

                self._log(
                    "exception",
                    "Live monitor failed for %s: %s",
                    path,
                    exc,
                )


    # ============================================================
    # READ NEW DATA
    # ============================================================

    def _read_new_data(self, path):
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            return

        with self._lock:
            state = self._files.get(path)

            if state is None:
                return

            current_size = stat.st_size

            current_inode = getattr(
                stat,
                "st_ino",
                None,
            )

            # ----------------------------------------------------
            # First observation
            # ----------------------------------------------------

            if not state["initialized"]:

                state["inode"] = (
                    current_inode
                )

                state["size"] = (
                    current_size
                )

                if self.start_at_end:
                    state["offset"] = (
                        current_size
                    )
                else:
                    state["offset"] = 0

                state["initialized"] = True

                state["last_error"] = None

                return

            # ----------------------------------------------------
            # File replacement / rotation
            # ----------------------------------------------------

            if (
                state["inode"] is not None
                and current_inode is not None
                and current_inode != state["inode"]
            ):
                self._log(
                    "info",
                    "Live log rotation detected: %s",
                    path,
                )

                state["offset"] = 0

                state["context"].clear()

                state["inode"] = (
                    current_inode
                )

            # ----------------------------------------------------
            # File truncation
            # ----------------------------------------------------

            elif current_size < state["offset"]:

                self._log(
                    "info",
                    "Live log truncation detected: %s",
                    path,
                )

                state["offset"] = 0

                state["context"].clear()

            offset = state["offset"]

        # --------------------------------------------------------
        # Nothing new
        # --------------------------------------------------------

        if current_size <= offset:
            with self._lock:
                state = self._files.get(path)

                if state:
                    state["size"] = current_size

            return

        # --------------------------------------------------------
        # Read appended bytes
        # --------------------------------------------------------

        try:
            with open(
                path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:

                handle.seek(
                    offset
                )

                data = handle.read()

                new_offset = handle.tell()

        except (
            OSError,
            UnicodeError,
        ) as exc:

            with self._lock:
                state = self._files.get(path)

                if state:
                    state["last_error"] = str(
                        exc
                    )

            raise

        # --------------------------------------------------------
        # Update offset
        # --------------------------------------------------------

        with self._lock:
            state = self._files.get(path)

            if state is None:
                return

            state["offset"] = (
                new_offset
            )

            state["size"] = current_size

            state["last_error"] = None

        if not data:
            return

        # --------------------------------------------------------
        # Split complete lines
        # --------------------------------------------------------

        lines = data.splitlines()

        if not lines:
            return

        # --------------------------------------------------------
        # Process line batches
        # --------------------------------------------------------

        self._process_lines(
            path,
            lines,
        )


    # ============================================================
    # PROCESS LINES
    # ============================================================

    def _process_lines(
        self,
        path,
        lines,
    ):
        if not lines:
            return

        with self._lock:
            state = self._files.get(path)

            if state is None:
                return

            context_lines = list(
                state["context"]
            )

        # --------------------------------------------------------
        # Break large input into manageable batches.
        # --------------------------------------------------------

        start = 0

        while start < len(lines):

            batch = lines[
                start:
                start + self.batch_lines
            ]

            start += self.batch_lines

            if not batch:
                continue

            # ----------------------------------------------------
            # Include recent context.
            #
            # This allows the detection engine to see events that
            # arrived immediately before this polling cycle.
            # ----------------------------------------------------

            analysis_lines = (
                context_lines
                + batch
            )

            analysis_text = "\n".join(
                analysis_lines
            )

            if not analysis_text.strip():
                continue

            source_name = path

            try:
                self.on_batch(
                    source_name,
                    analysis_text,
                )

                with self._lock:
                    self._detected_callbacks += 1

            except Exception as exc:

                self._log(
                    "exception",
                    "Live detection callback failed for %s: %s",
                    path,
                    exc,
                )

                with self._lock:
                    self._last_error = str(
                        exc
                    )

                # Do not discard the new lines from the context.
                # They can be retried on a later cycle if desired.
                continue

            # ----------------------------------------------------
            # Save only newly arrived lines as rolling context.
            # ----------------------------------------------------

            with self._lock:
                state = self._files.get(path)

                if state is None:
                    return

                state["context"].extend(
                    batch
                )

                self._processed_lines += len(
                    batch
                )

                self._processed_batches += 1

                context_lines = list(
                    state["context"]
                )


    # ============================================================
    # RESET
    # ============================================================

    def reset_file_position(
        self,
        path,
        start_at_end=None,
    ):
        """
        Reset a monitored file position.

        Useful when an administrator wants to re-read a file.
        """

        path = os.path.abspath(
            os.path.expanduser(
                os.path.expandvars(
                    str(path)
                )
            )
        )

        with self._lock:
            state = self._files.get(path)

            if state is None:
                return False

            try:
                size = os.path.getsize(
                    path
                )
            except OSError:
                size = 0

            if start_at_end is None:
                start_at_end = (
                    self.start_at_end
                )

            state["offset"] = (
                size
                if start_at_end
                else 0
            )

            state["size"] = size

            state["initialized"] = True

            state["context"].clear()

            try:
                stat = os.stat(
                    path
                )

                state["inode"] = getattr(
                    stat,
                    "st_ino",
                    None,
                )
            except OSError:
                state["inode"] = None

        return True


# ================================================================
# HELPERS
# ================================================================

def parse_live_file_list(value):
    """
    Convert LIVE_LOG_FILES into a unique list.

    Supported separators:

        ;
        newline

    Example:

        C:\\Logs\\security.log;
        C:\\Logs\\application.log
    """

    if not value:
        return []

    raw = str(value)

    raw = raw.replace(
        "\r\n",
        "\n",
    )

    parts = []

    for line in raw.split("\n"):
        for item in line.split(";"):

            item = item.strip()

            if item:
                parts.append(item)

    unique = []

    for path in parts:

        normalized = os.path.abspath(
            os.path.expanduser(
                os.path.expandvars(
                    path
                )
            )
        )

        if normalized not in unique:
            unique.append(
                normalized
            )

    return unique


def discover_log_files(
    directory,
    extensions=None,
):
    """
    Discover log files in a directory.

    Only the directory itself is scanned;
    recursive scanning is intentionally disabled by default.
    """

    if not directory:
        return []

    directory = os.path.abspath(
        os.path.expanduser(
            os.path.expandvars(
                directory
            )
        )
    )

    if not os.path.isdir(directory):
        return []

    if extensions is None:
        extensions = [
            ".log",
            ".txt",
        ]

    normalized_extensions = set()

    for extension in extensions:
        extension = str(
            extension
        ).strip().lower()

        if not extension:
            continue

        if not extension.startswith("."):
            extension = "." + extension

        normalized_extensions.add(
            extension
        )

    result = []

    try:
        for name in os.listdir(
            directory
        ):
            path = os.path.join(
                directory,
                name,
            )

            if not os.path.isfile(
                path
            ):
                continue

            extension = os.path.splitext(
                name
            )[1].lower()

            if (
                extension
                in normalized_extensions
            ):
                result.append(
                    os.path.abspath(
                        path
                    )
                )

    except OSError:
        return []

    return sorted(
        result
    )


def evidence_fingerprint(
    source_name,
    finding,
):
    """
    Generate a stable fingerprint for a live finding.

    This is intentionally based on the finding/evidence rather
    than database identity.
    """

    if not isinstance(
        finding,
        dict,
    ):
        return None

    threat_type = str(
        finding.get(
            "threat_type",
            "",
        )
        or ""
    ).strip().lower()

    source_ip = str(
        finding.get(
            "source_ip",
            "",
        )
        or ""
    ).strip()

    dest_ip = str(
        finding.get(
            "dest_ip",
            "",
        )
        or ""
    ).strip()

    evidence = str(
        finding.get(
            "evidence",
            "",
        )
        or ""
    ).strip()

    raw = "|".join(
        [
            str(
                source_name
                or ""
            ),
            threat_type,
            source_ip,
            dest_ip,
            evidence,
        ]
    )

    return hashlib.sha256(
        raw.encode(
            "utf-8",
            errors="ignore",
        )
    ).hexdigest()