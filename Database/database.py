# ============================================================
# Database/database.py
# ============================================================

import os
import sqlite3

from flask_sqlalchemy import SQLAlchemy


# ============================================================
# SQLAlchemy
# ============================================================

db = SQLAlchemy()


# ============================================================
# ThreatEvent columns
#
# These are the columns that may be missing from an older
# threat_hunting.db database.
# ============================================================

THREAT_EVENT_COLUMNS = {
    "rule_score": "FLOAT NOT NULL DEFAULT 0.0",

    "ml_score": "FLOAT NOT NULL DEFAULT 0.0",

    "anomaly_score": "FLOAT NOT NULL DEFAULT 0.0",

    "threat_intelligence_score": "FLOAT NOT NULL DEFAULT 0.0",

    "correlation_score": "FLOAT NOT NULL DEFAULT 0.0",

    "llm_score": "FLOAT NOT NULL DEFAULT 0.0",

    "detector_scores": "TEXT",

    "llm_summary": "TEXT",

    "explanation": (
        "TEXT NOT NULL DEFAULT "
        "'Threat detected by the autonomous threat detection system.'"
    ),

    "evidence": "TEXT",

    "attack_pattern": "TEXT",

    "recommendation": "TEXT",

    "status": "VARCHAR(20) NOT NULL DEFAULT 'OPEN'",

    "analysis_status": (
        "VARCHAR(30) NOT NULL DEFAULT 'ANALYZED'"
    ),

    "analyzed_at": "DATETIME",

    "updated_at": "DATETIME",

    "created_at": "DATETIME",
}


# ============================================================
# Get SQLite path
# ============================================================

def get_sqlite_path(app):
    """
    Get the actual SQLite database file used by Flask.

    Flask-SQLAlchemy resolves relative SQLite paths
    relative to app.instance_path.
    """

    database_url = app.config.get(
        "SQLALCHEMY_DATABASE_URI",
        ""
    )

    if not database_url.startswith("sqlite:///"):
        return None

    database_path = database_url[len("sqlite:///"):]

    # Handle in-memory database
    if database_path == ":memory:":
        return None

    # Flask-SQLAlchemy resolves relative SQLite paths
    # inside the Flask instance directory.
    if not os.path.isabs(database_path):
        database_path = os.path.join(
            app.instance_path,
            database_path
        )

    return os.path.abspath(database_path)


# ============================================================
# Check existing columns
# ============================================================

def get_existing_columns(connection):
    """
    Return all existing columns from threat_events.
    """

    cursor = connection.execute(
        "PRAGMA table_info(threat_events)"
    )

    rows = cursor.fetchall()

    return {row[1] for row in rows}


# ============================================================
# Check whether table exists
# ============================================================

def threat_events_table_exists(connection):
    """
    Check whether the threat_events table exists.
    """

    cursor = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table'
        AND name='threat_events'
        """
    )

    return cursor.fetchone() is not None


# ============================================================
# Migrate threat_events
# ============================================================

def migrate_threat_events(app):
    """
    Add missing ThreatEvent columns to an existing SQLite
    database.

    Existing data is preserved.
    """

    database_path = get_sqlite_path(app)

    if database_path is None:
        print(
            "[DATABASE] Migration skipped: "
            "database is not SQLite."
        )
        return

    print()
    print("=" * 60)
    print("DATABASE MIGRATION")
    print("=" * 60)

    print("[DATABASE] Using database:")
    print(f"[DATABASE] {database_path}")

    # --------------------------------------------------------
    # Make sure database directory exists
    # --------------------------------------------------------

    database_directory = os.path.dirname(database_path)

    if database_directory:
        os.makedirs(
            database_directory,
            exist_ok=True
        )

    # --------------------------------------------------------
    # Database might not exist yet
    # --------------------------------------------------------

    if not os.path.exists(database_path):
        print(
            "[DATABASE] Database file does not exist yet."
        )

        print(
            "[DATABASE] SQLAlchemy will create it."
        )

        print("=" * 60)

        return

    connection = None

    try:

        connection = sqlite3.connect(
            database_path
        )

        # ----------------------------------------------------
        # Make sure threat_events exists
        # ----------------------------------------------------

        if not threat_events_table_exists(connection):

            print(
                "[DATABASE] threat_events table does not "
                "exist yet."
            )

            print(
                "[DATABASE] Nothing to migrate."
            )

            print("=" * 60)

            return

        # ----------------------------------------------------
        # Get existing columns
        # ----------------------------------------------------

        existing_columns = get_existing_columns(
            connection
        )

        print(
            f"[DATABASE] Existing columns: "
            f"{len(existing_columns)}"
        )

        # ----------------------------------------------------
        # Add missing columns
        # ----------------------------------------------------

        added_columns = []

        for column_name, column_definition in (
            THREAT_EVENT_COLUMNS.items()
        ):

            if column_name not in existing_columns:

                sql = (
                    "ALTER TABLE threat_events "
                    f"ADD COLUMN {column_name} "
                    f"{column_definition}"
                )

                print(
                    f"[DATABASE] Adding column: "
                    f"{column_name}"
                )

                connection.execute(sql)

                added_columns.append(
                    column_name
                )

        connection.commit()

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        if added_columns:

            print()
            print(
                "[DATABASE] Migration successful."
            )

            print(
                "[DATABASE] Added columns:"
            )

            for column in added_columns:

                print(
                    f"    + {column}"
                )

        else:

            print(
                "[DATABASE] threat_events schema "
                "is already up to date."
            )

        print("=" * 60)

    except Exception as exc:

        if connection is not None:
            connection.rollback()

        print()
        print(
            "[DATABASE] MIGRATION ERROR"
        )

        print(
            f"[DATABASE] {type(exc).__name__}: {exc}"
        )

        print("=" * 60)

        raise

    finally:

        if connection is not None:
            connection.close()


# ============================================================
# Verify required ThreatEvent columns
# ============================================================

def verify_threat_event_schema(app):
    """
    Verify that all required ThreatEvent columns exist.
    """

    database_path = get_sqlite_path(app)

    if database_path is None:
        return False

    if not os.path.exists(database_path):
        print(
            "[DATABASE] WARNING: Database file does not exist."
        )
        return False

    connection = None

    try:

        connection = sqlite3.connect(
            database_path
        )

        # ----------------------------------------------------
        # Check table
        # ----------------------------------------------------

        if not threat_events_table_exists(connection):

            print(
                "[DATABASE] WARNING: "
                "threat_events table does not exist."
            )

            return False

        # ----------------------------------------------------
        # Get columns
        # ----------------------------------------------------

        existing_columns = get_existing_columns(
            connection
        )

        print(
            f"[DATABASE] Current ThreatEvent columns: "
            f"{len(existing_columns)}"
        )

        # ----------------------------------------------------
        # Find missing columns
        # ----------------------------------------------------

        missing_columns = [
            column
            for column in THREAT_EVENT_COLUMNS
            if column not in existing_columns
        ]

        # ----------------------------------------------------
        # Display missing columns
        # ----------------------------------------------------

        if missing_columns:

            print(
                "[DATABASE] WARNING: Missing columns:"
            )

            for column in missing_columns:

                print(
                    f"    - {column}"
                )

            return False

        # ----------------------------------------------------
        # Schema verified
        # ----------------------------------------------------

        print(
            "[DATABASE] ThreatEvent schema verified."
        )

        return True

    except Exception as exc:

        print(
            "[DATABASE] Schema verification error:"
        )

        print(
            f"[DATABASE] {type(exc).__name__}: {exc}"
        )

        return False

    finally:

        if connection is not None:
            connection.close()


# ============================================================
# Print database information
# ============================================================

def print_database_info(app):
    """
    Print useful information about the active database.
    """

    database_path = get_sqlite_path(app)

    print()
    print("=" * 60)
    print("DATABASE INFORMATION")
    print("=" * 60)

    if database_path is None:

        print(
            "[DATABASE] Database type is not SQLite."
        )

        print("=" * 60)

        return

    print(
        f"[DATABASE] Active database:"
    )

    print(
        f"[DATABASE] {database_path}"
    )

    print(
        f"[DATABASE] Exists: "
        f"{os.path.exists(database_path)}"
    )

    if os.path.exists(database_path):

        try:

            connection = sqlite3.connect(
                database_path
            )

            cursor = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                ORDER BY name
                """
            )

            tables = [
                row[0]
                for row in cursor.fetchall()
            ]

            print(
                f"[DATABASE] Tables: {tables}"
            )

            if "threat_events" in tables:

                columns = get_existing_columns(
                    connection
                )

                print(
                    f"[DATABASE] threat_events columns: "
                    f"{len(columns)}"
                )

            connection.close()

        except Exception as exc:

            print(
                "[DATABASE] Unable to inspect database:"
            )

            print(
                f"[DATABASE] {exc}"
            )

    print("=" * 60)


# ============================================================
# Initialize database
# ============================================================

def init_app(app):
    """
    Initialize SQLAlchemy.

    1. Register SQLAlchemy with Flask.
    2. Import models.
    3. Create missing tables.
    4. Migrate old threat_events table.
    5. Verify the schema.
    """

    print()
    print("=" * 60)
    print("INITIALIZING DATABASE")
    print("=" * 60)

    # --------------------------------------------------------
    # Register SQLAlchemy
    # --------------------------------------------------------

    db.init_app(app)

    # --------------------------------------------------------
    # Flask application context
    # --------------------------------------------------------

    with app.app_context():

        # ----------------------------------------------------
        # Import models BEFORE create_all().
        # ----------------------------------------------------

        from Database import models  # noqa: F401

        # ----------------------------------------------------
        # Display active database
        # ----------------------------------------------------

        database_path = get_sqlite_path(app)

        if database_path:

            print(
                "[DATABASE] Active SQLite database:"
            )

            print(
                f"[DATABASE] {database_path}"
            )

        # ----------------------------------------------------
        # Create tables that don't exist.
        # ----------------------------------------------------

        print()
        print(
            "[DATABASE] Running create_all()..."
        )

        db.create_all()

        print(
            "[DATABASE] create_all() completed."
        )

        # ----------------------------------------------------
        # Migrate existing ThreatEvent table.
        # ----------------------------------------------------

        migrate_threat_events(app)

        # ----------------------------------------------------
        # Verify final schema.
        # ----------------------------------------------------

        if verify_threat_event_schema(app):

            print()
            print(
                "[DATABASE] Database is ready."
            )

        else:

            print()
            print(
                "[DATABASE] WARNING: Database schema "
                "verification failed."
            )

        # ----------------------------------------------------
        # Print database information
        # ----------------------------------------------------

        print_database_info(app)

    # --------------------------------------------------------
    # Initialization finished
    # --------------------------------------------------------

    print("=" * 60)
    print("DATABASE INITIALIZATION FINISHED")
    print("=" * 60)
    print()