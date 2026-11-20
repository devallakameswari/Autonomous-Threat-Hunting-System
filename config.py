"""
config.py

Central configuration for the Autonomous Threat Hunting System.

All configurable values are loaded from environment variables
(.env) with safe defaults.
"""

import os

from dotenv import load_dotenv


# ================================================================
# BASE DIRECTORY
# ================================================================

BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


# ================================================================
# ENVIRONMENT
# ================================================================

ENV_FILE = os.path.join(
    BASE_DIR,
    ".env",
)

load_dotenv(
    ENV_FILE,
    override=False,
)


# ================================================================
# HELPERS
# ================================================================

def _bool(value, default=False):
    """
    Convert an environment value to boolean.
    """
    if value is None:
        return default

    return str(value).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _int(value, default):
    """
    Safely convert a value to integer.
    """
    try:
        return int(value)
    except (
        TypeError,
        ValueError,
    ):
        return default


def _float(value, default):
    """
    Safely convert a value to float.
    """
    try:
        return float(value)
    except (
        TypeError,
        ValueError,
    ):
        return default


# ================================================================
# CONFIGURATION
# ================================================================

class Config:

    # ============================================================
    # CORE FLASK
    # ============================================================

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "change-this-secret-key-in-production",
    )

    DEBUG = _bool(
        os.getenv("DEBUG"),
        True,
    )

    HOST = os.getenv(
        "HOST",
        "0.0.0.0",
    )

    PORT = _int(
        os.getenv("PORT"),
        5000,
    )


    # ============================================================
    # DATABASE
    # ============================================================

    DB_PATH = os.path.join(
        BASE_DIR,
        "Database",
        "threat_hunting.db",
    )

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{DB_PATH}",
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False


    # ============================================================
    # FILE UPLOADS
    # ============================================================

    UPLOAD_FOLDER = os.path.join(
        BASE_DIR,
        "uploads",
    )

    REPORTS_FOLDER = os.path.join(
        BASE_DIR,
        "reports",
    )

    ALLOWED_EXTENSIONS = {
        "log",
        "txt",
        "csv",
        "json",
    }

    MAX_CONTENT_LENGTH = (
        _int(
            os.getenv(
                "MAX_UPLOAD_MB",
                25,
            ),
            25,
        )
        * 1024
        * 1024
    )


    # ============================================================
    # MACHINE LEARNING
    # ============================================================

    MODEL_DIR = os.path.join(
        BASE_DIR,
        "Machine_learning",
        "models",
    )

    RANDOM_FOREST_PATH = os.path.join(
        MODEL_DIR,
        "random_forest.pkl",
    )

    ISOLATION_FOREST_PATH = os.path.join(
        MODEL_DIR,
        "isolation_forest.pkl",
    )

    AUTOENCODER_PATH = os.path.join(
        MODEL_DIR,
        "autoencoder.keras",
    )

    AUTOENCODER_FALLBACK_PATH = os.path.join(
        MODEL_DIR,
        "autoencoder_pca.pkl",
    )


    # ============================================================
    # ANOMALY DETECTION
    # ============================================================

    ANOMALY_ZSCORE_THRESHOLD = _float(
        os.getenv(
            "ANOMALY_ZSCORE_THRESHOLD",
            3.0,
        ),
        3.0,
    )


    # ============================================================
    # LLM / OLLAMA
    # ============================================================

    OLLAMA_HOST = os.getenv(
        "OLLAMA_HOST",
        "http://localhost:11434",
    )

    OLLAMA_MODEL = os.getenv(
        "OLLAMA_MODEL",
        "llama3",
    )

    OLLAMA_TIMEOUT = _int(
        os.getenv(
            "OLLAMA_TIMEOUT",
            15,
        ),
        15,
    )

    LLM_ENABLED = _bool(
        os.getenv(
            "LLM_ENABLED",
        ),
        True,
    )


    # ============================================================
    # EMAIL ALERTS
    # ============================================================

    # ------------------------------------------------------------
    # Enable / disable email alerts
    # ------------------------------------------------------------

    EMAIL_ALERTS_ENABLED = _bool(
        os.getenv(
            "EMAIL_ALERTS_ENABLED",
            "true",
        ),
        True,
    )


    # ------------------------------------------------------------
    # Minimum severity that triggers email
    #
    # LOW      -> no email
    # MEDIUM   -> no email
    # HIGH     -> email
    # CRITICAL -> email
    # ------------------------------------------------------------

    EMAIL_ALERT_MIN_SEVERITY = os.getenv(
        "EMAIL_ALERT_MIN_SEVERITY",
        "HIGH",
    ).strip().upper()


    # ------------------------------------------------------------
    # SMTP SERVER
    #
    # Gmail:
    #
    # smtp.gmail.com
    # port 587
    # STARTTLS
    #
    # ------------------------------------------------------------

    SMTP_HOST = os.getenv(
        "SMTP_HOST",
        "smtp.gmail.com",
    )

    SMTP_PORT = _int(
        os.getenv(
            "SMTP_PORT",
            587,
        ),
        587,
    )


    # ------------------------------------------------------------
    # TLS / SSL
    #
    # Gmail port 587:
    #
    # SMTP_USE_TLS=true
    # SMTP_USE_SSL=false
    #
    # DO NOT use SSL + STARTTLS together.
    # ------------------------------------------------------------

    SMTP_USE_TLS = _bool(
        os.getenv(
            "SMTP_USE_TLS",
            "true",
        ),
        True,
    )

    SMTP_USE_SSL = _bool(
        os.getenv(
            "SMTP_USE_SSL",
            "false",
        ),
        False,
    )


    # ------------------------------------------------------------
    # SMTP AUTHENTICATION
    # ------------------------------------------------------------

    SMTP_USERNAME = os.getenv(
        "SMTP_USERNAME",
        "",
    ).strip()

    SMTP_PASSWORD = os.getenv(
        "SMTP_PASSWORD",
        "",
    ).strip()


    # ------------------------------------------------------------
    # EMAIL SENDER
    # ------------------------------------------------------------

    ALERT_EMAIL_FROM = os.getenv(
        "ALERT_EMAIL_FROM",
        SMTP_USERNAME,
    ).strip()


    # ------------------------------------------------------------
    # EMAIL RECIPIENT
    #
    # If the user is logged in and has an email address,
    # email_alert.py will prefer that address.
    #
    # Otherwise ALERT_EMAIL_TO is used.
    # ------------------------------------------------------------

    ALERT_EMAIL_TO = os.getenv(
        "ALERT_EMAIL_TO",
        "",
    ).strip()


    # ------------------------------------------------------------
    # SMTP CONNECTION TIMEOUT
    #
    # Prevent the Flask request/background worker from waiting
    # indefinitely when the SMTP server cannot be reached.
    # ------------------------------------------------------------

    SMTP_TIMEOUT = _int(
        os.getenv(
            "SMTP_TIMEOUT",
            15,
        ),
        15,
    )


    # ============================================================
    # THREAT DETECTION THRESHOLDS
    # ============================================================

    BRUTE_FORCE_FAILED_LOGIN_THRESHOLD = _int(
        os.getenv(
            "BRUTE_FORCE_THRESHOLD",
            5,
        ),
        5,
    )

    BRUTE_FORCE_WINDOW_SECONDS = _int(
        os.getenv(
            "BRUTE_FORCE_WINDOW_SECONDS",
            300,
        ),
        300,
    )

    PORT_SCAN_UNIQUE_PORT_THRESHOLD = _int(
        os.getenv(
            "PORT_SCAN_THRESHOLD",
            10,
        ),
        10,
    )

    ATTACK_CORRELATION_WINDOW_SECONDS = _int(
        os.getenv(
            "ATTACK_CORRELATION_WINDOW_SECONDS",
            1800,
        ),
        1800,
    )


    # ============================================================
    # LIVE ALERT RECIPIENT
    # ============================================================

    # Email address that receives automatic alerts generated by the
    # background live monitor. This is required because the background
    # thread does not have a browser request/current_user context.
    LIVE_ALERT_RECIPIENT_EMAIL = os.getenv(
        "LIVE_ALERT_RECIPIENT_EMAIL",
        ALERT_EMAIL_TO,
    ).strip()


    # ============================================================
    # LIVE THREAT DETECTION
    # ============================================================

    LIVE_DETECTION_ENABLED = _bool(
        os.getenv(
            "LIVE_DETECTION_ENABLED",
            "true",
        ),
        True,
    )

    LIVE_POLL_INTERVAL = _float(
        os.getenv(
            "LIVE_POLL_INTERVAL",
            2,
        ),
        2.0,
    )

    LIVE_BATCH_LINES = _int(
        os.getenv(
            "LIVE_BATCH_LINES",
            200,
        ),
        200,
    )

    LIVE_CONTEXT_LINES = _int(
        os.getenv(
            "LIVE_CONTEXT_LINES",
            500,
        ),
        500,
    )

    LIVE_START_AT_END = _bool(
        os.getenv(
            "LIVE_START_AT_END",
            "true",
        ),
        True,
    )

    LIVE_DEDUP_SECONDS = _int(
        os.getenv(
            "LIVE_DEDUP_SECONDS",
            30,
        ),
        30,
    )


    # ------------------------------------------------------------
    # Optional list of live log files
    #
    # Windows:
    #
    # LIVE_LOG_FILES=C:\Logs\Security.log;C:\Logs\Application.log
    #
    # Linux:
    #
    # LIVE_LOG_FILES=/var/log/auth.log;/var/log/syslog
    # ------------------------------------------------------------

    LIVE_LOG_FILES = os.getenv(
        "LIVE_LOG_FILES",
        "",
    ).strip()


    # ------------------------------------------------------------
    # Optional live log directory
    # ------------------------------------------------------------

    LIVE_LOG_DIRECTORY = os.getenv(
        "LIVE_LOG_DIRECTORY",
        "",
    ).strip()


    # ------------------------------------------------------------
    # Extensions monitored inside LIVE_LOG_DIRECTORY
    # ------------------------------------------------------------

    LIVE_LOG_EXTENSIONS = os.getenv(
        "LIVE_LOG_EXTENSIONS",
        ".log,.txt",
    )


    # ------------------------------------------------------------
    # Main live log used by the application
    # ------------------------------------------------------------

    LIVE_LOG_FILE = os.path.join(
        BASE_DIR,
        "uploads",
        "live.log",
    )


    # ============================================================
    # SESSION
    # ============================================================

    SESSION_COOKIE_HTTPONLY = True

    REMEMBER_COOKIE_DURATION = (
        60
        * 60
        * 24
        * 7
    )