"""
Database/models.py

ORM models for:
- Users
- Log entries
- Threat events
- Alerts
- Reports
- Registration OTP
- Authorized users
- Login activity

ACCESS CONTROL
--------------

Admin:
    - Can access all users
    - Can access all threat events
    - Can access all alerts
    - Can access all reports
    - Can access all login activity

Normal User:
    - Can access only their own threat events
    - Can access only alerts belonging to their threats
    - Can access only their own reports
    - Can access only their own login activity

IMPORTANT OWNERSHIP FIELDS
--------------------------

ThreatEvent.user
    The username/user mentioned inside the security event or log.

ThreatEvent.owner_user_id
    The authenticated ATHS account that owns the detected threat.

Alert
    Belongs to a ThreatEvent through threat_event_id.
    Therefore alert ownership is determined through:
        Alert -> ThreatEvent -> owner_user_id

Alert does NOT contain created_at.

The available alert timestamp is:
    sent_at

For FAILED and SUPPRESSED alerts, sent_at may be NULL.
"""


from datetime import datetime

from flask_login import UserMixin

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from Database.database import db


# =========================================================
# USER
# =========================================================

class User(db.Model, UserMixin):

    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False,
        index=True,
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False,
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    role = db.Column(
        db.String(20),
        default="analyst",
        nullable=False,
        index=True,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
    )

    last_login = db.Column(
        db.DateTime,
        nullable=True,
    )

    # =====================================================
    # PASSWORD
    # =====================================================

    def set_password(
        self,
        raw_password: str,
    ) -> None:

        self.password_hash = generate_password_hash(
            raw_password
        )

    def check_password(
        self,
        raw_password: str,
    ) -> bool:

        return check_password_hash(
            self.password_hash,
            raw_password,
        )

    # =====================================================
    # ROLE HELPERS
    # =====================================================

    def is_admin(self) -> bool:
        """
        Return True when this user has administrator
        privileges.
        """

        return (
            str(self.role or "")
            .strip()
            .lower()
            == "admin"
        )

    def is_normal_user(self) -> bool:
        """
        Return True for non-admin users.
        """

        return not self.is_admin()

    # =====================================================
    # REPRESENTATION
    # =====================================================

    def __repr__(self):

        return f"<User {self.username}>"


# =========================================================
# LOG ENTRY
# =========================================================

class LogEntry(db.Model):

    __tablename__ = "log_entries"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    source_file = db.Column(
        db.String(255),
        nullable=True,
    )

    raw_line = db.Column(
        db.Text,
        nullable=False,
    )

    log_type = db.Column(
        db.String(50),
        nullable=True,
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=True,
    )

    source_ip = db.Column(
        db.String(45),
        nullable=True,
        index=True,
    )

    dest_ip = db.Column(
        db.String(45),
        nullable=True,
    )

    user = db.Column(
        db.String(120),
        nullable=True,
    )

    event = db.Column(
        db.String(255),
        nullable=True,
    )

    extra_json = db.Column(
        db.Text,
        nullable=True,
    )

    ingested_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        index=True,
    )

    # =====================================================
    # DICTIONARY
    # =====================================================

    def to_dict(self):

        return {

            "id": self.id,

            "source_file": self.source_file,

            "raw_line": self.raw_line,

            "log_type": self.log_type,

            "timestamp": (
                self.timestamp.isoformat()
                if self.timestamp
                else None
            ),

            "source_ip": self.source_ip,

            "dest_ip": self.dest_ip,

            "user": self.user,

            "event": self.event,

            "extra_json": self.extra_json,

            "ingested_at": (
                self.ingested_at.isoformat()
                if self.ingested_at
                else None
            ),
        }

    # =====================================================
    # REPRESENTATION
    # =====================================================

    def __repr__(self):

        return (
            f"<LogEntry "
            f"{self.id} "
            f"{self.log_type} "
            f"{self.source_ip}>"
        )


# =========================================================
# THREAT EVENT
# =========================================================

class ThreatEvent(db.Model):

    __tablename__ = "threat_events"

    # =====================================================
    # BASIC INFORMATION
    # =====================================================

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    title = db.Column(
        db.String(255),
        nullable=False,
    )

    description = db.Column(
        db.Text,
        nullable=True,
    )

    threat_type = db.Column(
        db.String(100),
        nullable=False,
        index=True,
    )

    # =====================================================
    # SEVERITY
    # =====================================================

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="LOW",
        index=True,
    )

    confidence = db.Column(
        db.Float,
        default=0.0,
        nullable=False,
        index=True,
    )

    # =====================================================
    # SOURCE / DESTINATION
    # =====================================================

    source_ip = db.Column(
        db.String(45),
        nullable=True,
        index=True,
    )

    dest_ip = db.Column(
        db.String(45),
        nullable=True,
    )

    # =====================================================
    # EVENT USER
    # =====================================================
    #
    # IMPORTANT:
    #
    # This field represents the username/user mentioned
    # inside the security event or log.
    #
    # It is NOT the ownership field.
    #
    # Ownership is stored separately in:
    #
    #     owner_user_id
    #
    # =====================================================

    user = db.Column(
        db.String(120),
        nullable=True,
        index=True,
    )

    # =====================================================
    # THREAT OWNER
    # =====================================================
    #
    # This identifies the authenticated ATHS account that
    # owns the threat detection.
    #
    # ADMIN:
    #     Can see all owner_user_id values.
    #
    # NORMAL USER:
    #     Can only see records where:
    #
    #     owner_user_id == current_user.id
    #
    # nullable=True is intentionally used for compatibility
    # with existing threat records created before ownership
    # tracking was introduced.
    #
    # =====================================================

    owner_user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id"
        ),
        nullable=True,
        index=True,
    )

    owner = db.relationship(
        "User",
        foreign_keys=[owner_user_id],
        backref=db.backref(
            "threat_events",
            lazy=True,
        ),
    )

    # =====================================================
    # MITRE ATT&CK
    # =====================================================

    mitre_techniques = db.Column(
        db.Text,
        nullable=True,
    )

    # =====================================================
    # DETECTION SOURCE
    # =====================================================

    detection_source = db.Column(
        db.String(100),
        nullable=True,
    )

    # =====================================================
    # DETECTOR SCORES
    # =====================================================

    rule_score = db.Column(
        db.Float,
        default=0.0,
        nullable=False,
    )

    ml_score = db.Column(
        db.Float,
        default=0.0,
        nullable=False,
    )

    anomaly_score = db.Column(
        db.Float,
        default=0.0,
        nullable=False,
    )

    threat_intelligence_score = db.Column(
        db.Float,
        default=0.0,
        nullable=False,
    )

    correlation_score = db.Column(
        db.Float,
        default=0.0,
        nullable=False,
    )

    llm_score = db.Column(
        db.Float,
        default=0.0,
        nullable=False,
    )

    # =====================================================
    # COMBINED DETECTOR INFORMATION
    # =====================================================

    detector_scores = db.Column(
        db.Text,
        nullable=True,
    )

    # =====================================================
    # LLM ANALYSIS
    # =====================================================

    llm_summary = db.Column(
        db.Text,
        nullable=True,
    )

    # =====================================================
    # EXPLANATION
    # =====================================================

    explanation = db.Column(
        db.Text,
        nullable=False,
        default=(
            "Threat detected by the autonomous "
            "threat detection system."
        ),
    )

    # =====================================================
    # EVIDENCE
    # =====================================================

    evidence = db.Column(
        db.Text,
        nullable=True,
    )

    # =====================================================
    # ATTACK PATTERN
    # =====================================================

    attack_pattern = db.Column(
        db.Text,
        nullable=True,
    )

    # =====================================================
    # RECOMMENDATION
    # =====================================================

    recommendation = db.Column(
        db.Text,
        nullable=True,
    )

    # =====================================================
    # STATUS
    # =====================================================

    status = db.Column(
        db.String(20),
        default="OPEN",
        nullable=False,
        index=True,
    )

    # =====================================================
    # ANALYSIS STATUS
    # =====================================================

    analysis_status = db.Column(
        db.String(30),
        default="ANALYZED",
        nullable=False,
    )

    analyzed_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    # =====================================================
    # TIMESTAMPS
    # =====================================================

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        index=True,
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    # =====================================================
    # DICTIONARY
    # =====================================================

    def to_dict(self):

        confidence_value = float(
            self.confidence or 0.0
        )

        confidence_value = max(
            0.0,
            min(
                100.0,
                confidence_value,
            ),
        )

        explanation_value = (
            self.explanation
            or self.llm_summary
            or (
                "The system detected a potential "
                f"{self.threat_type or 'security'} threat."
            )
        )

        return {

            "id": self.id,

            "title": self.title,

            "description": self.description,

            "threat_type": self.threat_type,

            "severity": self.severity,

            "confidence": round(
                confidence_value,
                2,
            ),

            "source_ip": self.source_ip,

            "dest_ip": self.dest_ip,

            "user": self.user,

            # =================================================
            # OWNERSHIP
            # =================================================

            "owner_user_id": self.owner_user_id,

            "owner_username": (
                self.owner.username
                if self.owner
                else None
            ),

            # =================================================
            # MITRE
            # =================================================

            "mitre_techniques": (
                self.mitre_techniques
            ),

            # =================================================
            # DETECTION
            # =================================================

            "detection_source": (
                self.detection_source
            ),

            # =================================================
            # SCORES
            # =================================================

            "rule_score": round(
                float(
                    self.rule_score or 0.0
                ),
                2,
            ),

            "ml_score": round(
                float(
                    self.ml_score or 0.0
                ),
                2,
            ),

            "anomaly_score": round(
                float(
                    self.anomaly_score or 0.0
                ),
                2,
            ),

            "threat_intelligence_score": round(
                float(
                    self.threat_intelligence_score
                    or 0.0
                ),
                2,
            ),

            "correlation_score": round(
                float(
                    self.correlation_score
                    or 0.0
                ),
                2,
            ),

            "llm_score": round(
                float(
                    self.llm_score or 0.0
                ),
                2,
            ),

            "detector_scores": (
                self.detector_scores
            ),

            # =================================================
            # LLM
            # =================================================

            "llm_summary": self.llm_summary,

            # =================================================
            # EXPLANATION
            # =================================================

            "explanation": explanation_value,

            # =================================================
            # EVIDENCE
            # =================================================

            "evidence": self.evidence,

            "attack_pattern": self.attack_pattern,

            "recommendation": self.recommendation,

            # =================================================
            # STATUS
            # =================================================

            "status": self.status,

            "analysis_status": (
                self.analysis_status
            ),

            # =================================================
            # TIMESTAMPS
            # =================================================

            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),

            "updated_at": (
                self.updated_at.isoformat()
                if self.updated_at
                else None
            ),

            "analyzed_at": (
                self.analyzed_at.isoformat()
                if self.analyzed_at
                else None
            ),
        }

    # =====================================================
    # REPRESENTATION
    # =====================================================

    def __repr__(self):

        return (
            f"<ThreatEvent "
            f"{self.id} "
            f"{self.threat_type} "
            f"{self.severity} "
            f"{self.confidence}% "
            f"owner={self.owner_user_id}>"
        )


# =========================================================
# ALERT
# =========================================================

class Alert(db.Model):

    __tablename__ = "alerts"

    # =====================================================
    # BASIC INFORMATION
    # =====================================================

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    # =====================================================
    # RELATED THREAT
    # =====================================================

    threat_event_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "threat_events.id"
        ),
        nullable=False,
        index=True,
    )

    # =====================================================
    # CHANNEL
    # =====================================================

    channel = db.Column(
        db.String(20),
        default="email",
        nullable=False,
    )

    # =====================================================
    # STATUS
    # =====================================================

    status = db.Column(
        db.String(20),
        default="SUPPRESSED",
        nullable=False,
        index=True,
    )

    # =====================================================
    # LEGACY BOOLEAN
    # =====================================================

    sent = db.Column(
        db.Boolean,
        default=False,
        nullable=False,
    )

    # =====================================================
    # SENT TIMESTAMP
    # =====================================================
    #
    # IMPORTANT:
    #
    # Do NOT use:
    #
    #     Alert.created_at
    #
    # because that field does not exist.
    #
    # Use:
    #
    #     Alert.sent_at
    #
    # For FAILED and SUPPRESSED alerts this can be NULL.
    #
    # =====================================================

    sent_at = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    # =====================================================
    # ERROR
    # =====================================================

    error = db.Column(
        db.Text,
        nullable=True,
    )

    # =====================================================
    # RELATIONSHIP
    # =====================================================

    threat_event = db.relationship(
        "ThreatEvent",
        backref=db.backref(
            "alerts",
            lazy=True,
        ),
    )

    # =====================================================
    # OWNER PROPERTY
    # =====================================================
    #
    # Alert ownership comes from its ThreatEvent.
    #
    # This allows:
    #
    #     alert.owner_user_id
    #
    # to resolve to:
    #
    #     alert.threat_event.owner_user_id
    #
    # without storing a duplicate owner field.
    #
    # =====================================================

    @property
    def owner_user_id(self):

        if self.threat_event is None:
            return None

        return self.threat_event.owner_user_id

    @property
    def owner(self):

        if self.threat_event is None:
            return None

        return self.threat_event.owner

    # =====================================================
    # DICTIONARY
    # =====================================================

    def to_dict(self):

        alert_status = str(
            self.status or ""
        ).strip().upper()

        if alert_status not in {
            "SENT",
            "FAILED",
            "SUPPRESSED",
        }:

            if self.sent:
                alert_status = "SENT"

            elif self.error:
                alert_status = "FAILED"

            else:
                alert_status = "SUPPRESSED"

        return {

            "id": self.id,

            "threat_event_id": (
                self.threat_event_id
            ),

            "owner_user_id": (
                self.owner_user_id
            ),

            "owner_username": (
                self.owner.username
                if self.owner
                else None
            ),

            "channel": self.channel,

            "status": alert_status,

            "sent": (
                alert_status == "SENT"
            ),

            "sent_at": (
                self.sent_at.isoformat()
                if self.sent_at
                else None
            ),

            "error": self.error,
        }

    # =====================================================
    # REPRESENTATION
    # =====================================================

    def __repr__(self):

        return (
            f"<Alert "
            f"{self.id} "
            f"{self.status} "
            f"ThreatEvent={self.threat_event_id} "
            f"owner={self.owner_user_id}>"
        )


# =========================================================
# REPORT
# =========================================================

class Report(db.Model):

    __tablename__ = "reports"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    filename = db.Column(
        db.String(255),
        nullable=False,
    )

    generated_by = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id"
        ),
        nullable=True,
        index=True,
    )

    threat_count = db.Column(
        db.Integer,
        default=0,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        index=True,
    )

    user = db.relationship(
        "User",
        foreign_keys=[generated_by],
    )

    # =====================================================
    # OWNER PROPERTY
    # =====================================================

    @property
    def owner_user_id(self):

        return self.generated_by

    # =====================================================
    # DICTIONARY
    # =====================================================

    def to_dict(self):

        return {

            "id": self.id,

            "filename": self.filename,

            "generated_by": self.generated_by,

            "owner_user_id": self.generated_by,

            "owner_username": (
                self.user.username
                if self.user
                else None
            ),

            "threat_count": self.threat_count,

            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),
        }

    # =====================================================
    # REPRESENTATION
    # =====================================================

    def __repr__(self):

        return (
            f"<Report "
            f"{self.id} "
            f"owner={self.generated_by}>"
        )


# =========================================================
# REGISTRATION OTP
# =========================================================

class RegistrationOTP(db.Model):

    __tablename__ = "registration_otps"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    email = db.Column(
        db.String(255),
        nullable=False,
        index=True,
    )

    otp = db.Column(
        db.String(6),
        nullable=False,
    )

    admin_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id"
        ),
        nullable=True,
        index=True,
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False,
    )

    used = db.Column(
        db.Boolean,
        default=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        index=True,
    )

    admin = db.relationship(
        "User",
        foreign_keys=[admin_id],
    )

    # =====================================================
    # DICTIONARY
    # =====================================================

    def to_dict(self):

        return {

            "id": self.id,

            "email": self.email,

            "admin_id": self.admin_id,

            "expires_at": (
                self.expires_at.isoformat()
                if self.expires_at
                else None
            ),

            "used": self.used,

            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),
        }

    # =====================================================
    # REPRESENTATION
    # =====================================================

    def __repr__(self):

        return (
            f"<RegistrationOTP "
            f"{self.id} "
            f"{self.email}>"
        )


# =========================================================
# AUTHORIZED USER
# =========================================================

class AuthorizedUser(db.Model):

    __tablename__ = "authorized_users"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False,
        index=True,
    )

    authorized_by = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id"
        ),
        nullable=False,
        index=True,
    )

    authorized_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        index=True,
    )

    used = db.Column(
        db.Boolean,
        default=False,
    )

    admin = db.relationship(
        "User",
        foreign_keys=[authorized_by],
    )

    # =====================================================
    # DICTIONARY
    # =====================================================

    def to_dict(self):

        return {

            "id": self.id,

            "email": self.email,

            "authorized_by": self.authorized_by,

            "authorized_at": (
                self.authorized_at.isoformat()
                if self.authorized_at
                else None
            ),

            "used": self.used,
        }

    # =====================================================
    # REPRESENTATION
    # =====================================================

    def __repr__(self):

        return (
            f"<AuthorizedUser "
            f"{self.id} "
            f"{self.email}>"
        )


# =========================================================
# LOGIN ACTIVITY
# =========================================================

class LoginActivity(db.Model):

    __tablename__ = "login_activity"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    # =====================================================
    # USER INFORMATION
    # =====================================================

    username = db.Column(
        db.String(80),
        nullable=False,
        index=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id"
        ),
        nullable=True,
        index=True,
    )

    # =====================================================
    # NETWORK
    # =====================================================

    ip_address = db.Column(
        db.String(45),
        nullable=False,
        index=True,
    )

    # =====================================================
    # LOGIN STATUS
    # =====================================================

    login_status = db.Column(
        db.String(20),
        nullable=False,
        index=True,
    )

    # =====================================================
    # FAILED ATTEMPTS
    # =====================================================

    failed_attempts = db.Column(
        db.Integer,
        default=0,
    )

    # =====================================================
    # THREAT STATUS
    # =====================================================

    threat_status = db.Column(
        db.String(30),
        default="NORMAL",
    )

    # =====================================================
    # SEVERITY
    # =====================================================

    severity = db.Column(
        db.String(20),
        default="LOW",
    )

    # =====================================================
    # LOGIN TIME
    # =====================================================

    login_time = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        index=True,
    )

    # =====================================================
    # USER RELATIONSHIP
    # =====================================================

    user = db.relationship(
        "User",
        foreign_keys=[user_id],
        backref=db.backref(
            "login_activities",
            lazy=True,
        ),
    )

    # =====================================================
    # DICTIONARY
    # =====================================================

    def to_dict(self):

        return {

            "id": self.id,

            "username": self.username,

            "user_id": self.user_id,

            "ip_address": self.ip_address,

            "login_status": self.login_status,

            "failed_attempts": (
                self.failed_attempts
            ),

            "threat_status": (
                self.threat_status
            ),

            "severity": self.severity,

            "login_time": (
                self.login_time.isoformat()
                if self.login_time
                else None
            ),
        }

    # =====================================================
    # REPRESENTATION
    # =====================================================

    def __repr__(self):

        return (
            f"<LoginActivity "
            f"{self.username} "
            f"{self.ip_address} "
            f"{self.login_status} "
            f"user_id={self.user_id}>"
        )


# =========================================================
# EXPORTS
# =========================================================

__all__ = [
    "User",
    "LogEntry",
    "ThreatEvent",
    "Alert",
    "Report",
    "RegistrationOTP",
    "AuthorizedUser",
    "LoginActivity",
]