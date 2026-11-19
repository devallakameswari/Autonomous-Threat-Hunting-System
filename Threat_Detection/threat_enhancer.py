
"""
Threat_Detection/threat_enhancer.py

Threat enrichment and secondary detection module.

Responsibilities:
- Threat severity calculation
- Threat evidence generation
- Suspicious IP detection
- Privilege escalation detection
- Threat correlation
- Threat deduplication
- Attack-pattern generation
- Recommendation generation
- Mandatory explanation generation
- Threat investigation information

Important:
    Confidence calculation is primarily handled by
    threat_classifier.py.

    This module must NOT overwrite an already calculated
    evidence-based confidence score.
"""

from collections import defaultdict


# =========================================================
# SEVERITY ORDER
# =========================================================

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def normalize_score(value, default=0.0):
    """
    Normalize a confidence/score value to 0.0 - 1.0.

    Supports:

        0.85
        85
        "85"
        "0.85"
    """

    if value is None:
        return default

    try:

        value = float(value)

        if value > 1:
            value /= 100.0

        return max(
            0.0,
            min(
                1.0,
                value
            )
        )

    except (
        TypeError,
        ValueError
    ):

        return default


def normalize_confidence(value):
    """
    Return confidence as a percentage between 0 and 100.

    This helper is mainly useful when displaying or storing
    confidence outside the detection pipeline.
    """

    score = normalize_score(value)

    return round(
        score * 100,
        2
    )


def bump_severity(current, minimum):
    """
    Increase severity only if the minimum severity is higher.
    """

    current = str(
        current or "LOW"
    ).upper()

    minimum = str(
        minimum or "LOW"
    ).upper()

    if (
        SEVERITY_ORDER.get(
            minimum,
            0
        )
        >
        SEVERITY_ORDER.get(
            current,
            0
        )
    ):

        return minimum

    return current


# =========================================================
# 1. THREAT SEVERITY
# =========================================================

def calculate_severity(
    threat_type,
    event_count=1,
    confidence=0,
    current_severity=None
):
    """
    Calculate threat severity using:

    - Threat type
    - Event count
    - Confidence
    - Existing severity

    Severity:

        LOW
        MEDIUM
        HIGH
        CRITICAL
    """

    threat_type = str(
        threat_type or ""
    ).lower()

    confidence = normalize_confidence(
        confidence
    )

    try:

        event_count = int(
            event_count or 1
        )

    except (
        TypeError,
        ValueError
    ):

        event_count = 1

    # -----------------------------------------------------
    # Threat-type baseline
    # -----------------------------------------------------

    critical = [
        "privilege escalation",
        "privilege_escalation",
        "ransomware",
        "critical malware",
        "known malicious ip",
        "known_malicious_ip",
    ]

    high = [
        "sql injection",
        "sql_injection",
        "command injection",
        "command_injection",
        "brute force",
        "brute_force",
        "malware",
        "malware detected",
        "malware_detected",
    ]

    medium = [
        "port scan",
        "port_scan",
        "suspicious login",
        "suspicious_login",
        "suspicious ip",
        "suspicious_ip",
        "anomalous behavior",
        "anomalous_behavior",
        "ml flagged",
        "ml_flagged",
    ]

    if any(
        item in threat_type
        for item in critical
    ):

        severity = "CRITICAL"

    elif any(
        item in threat_type
        for item in high
    ):

        severity = "HIGH"

    elif any(
        item in threat_type
        for item in medium
    ):

        severity = "MEDIUM"

    else:

        severity = "LOW"

    # -----------------------------------------------------
    # Preserve an already higher severity
    # -----------------------------------------------------

    if current_severity:

        severity = bump_severity(
            severity,
            current_severity
        )

    # -----------------------------------------------------
    # Event-count adjustment
    # -----------------------------------------------------

    if event_count >= 10:

        severity = bump_severity(
            severity,
            "CRITICAL"
        )

    elif event_count >= 5:

        severity = bump_severity(
            severity,
            "HIGH"
        )

    # -----------------------------------------------------
    # Confidence adjustment
    # -----------------------------------------------------

    if confidence >= 95:

        severity = bump_severity(
            severity,
            "HIGH"
        )

    if confidence >= 98:

        severity = bump_severity(
            severity,
            "CRITICAL"
        )

    return severity


# =========================================================
# 2. LEGACY CONFIDENCE HELPER
# =========================================================

def calculate_confidence(
    rule_match=False,
    anomaly_detected=False,
    threat_intelligence=False,
    llm_confirmed=False,
    existing_confidence=None
):
    """
    Compatibility helper.

    The main dynamic confidence calculation is performed by
    threat_classifier.calculate_confidence().

    This function exists so older modules that import
    threat_enhancer.calculate_confidence() do not break.

    If an existing confidence is supplied, it is preserved.

    Otherwise a conservative fallback is calculated.
    """

    if existing_confidence is not None:

        return normalize_confidence(
            existing_confidence
        )

    score = 0

    if rule_match:
        score += 30

    if anomaly_detected:
        score += 25

    if threat_intelligence:
        score += 25

    if llm_confirmed:
        score += 20

    return min(
        score,
        100
    )


# =========================================================
# 3. SUSPICIOUS IP DETECTION
# =========================================================

def detect_suspicious_ip(events):
    """
    Detect suspicious IP addresses based on observed
    security-related activities.

    Parameters
    ----------
    events : list

        Normalized log records.

    Returns
    -------
    list

        Suspicious IP findings.
    """

    suspicious_ips = defaultdict(list)

    if not isinstance(
        events,
        list
    ):

        return []

    indicators = [
        "failed login",
        "authentication failure",
        "brute force",
        "sql injection",
        "command injection",
        "port scan",
        "malware",
        "ransomware",
        "privilege escalation",
        "suspicious",
        "unauthorized",
        "access denied",
    ]

    for event in events:

        if not isinstance(
            event,
            dict
        ):

            continue

        ip = (
            event.get("source_ip")
            or event.get("src_ip")
            or event.get("ip")
        )

        if not ip:
            continue

        # -------------------------------------------------
        # Convert the complete event into searchable text
        # -------------------------------------------------

        text_parts = []

        for key, value in event.items():

            if value is None:
                continue

            text_parts.append(
                str(value)
            )

        text = " ".join(
            text_parts
        ).lower()

        matched = []

        for indicator in indicators:

            if indicator in text:

                matched.append(
                    indicator
                )

        if matched:

            for indicator in matched:

                if indicator not in suspicious_ips[ip]:

                    suspicious_ips[ip].append(
                        indicator
                    )

    results = []

    for ip, activities in (
        suspicious_ips.items()
    ):

        activity_count = len(
            activities
        )

        # More independent indicators
        # produce stronger evidence.
        confidence = min(
            0.55
            + (
                activity_count * 0.07
            ),
            0.90
        )

        severity = (
            "HIGH"
            if activity_count >= 4
            else "MEDIUM"
        )

        evidence = [
            f"Suspicious activity observed from {ip}.",
            f"{activity_count} security indicator(s) matched.",
        ]

        for activity in activities:

            evidence.append(
                f"Matched indicator: {activity}"
            )

        results.append({

            "threat_type":
                "suspicious_ip",

            "title":
                f"Suspicious IP activity detected from {ip}",

            "description":
                (
                    f"Multiple security-related indicators "
                    f"were observed for source IP {ip}."
                ),

            "source_ip":
                ip,

            "suspicious":
                True,

            "activities":
                activities,

            "activity_count":
                activity_count,

            "event_count":
                activity_count,

            "severity":
                severity,

            "confidence":
                confidence,

            "detection_source":
                "suspicious_ip",

            "evidence":
                evidence,

            "attack_pattern":
                (
                    "Repeated or multiple security-related "
                    "activities originating from the same "
                    "source IP."
                ),

            "recommendation":
                (
                    "Investigate the source IP, review related "
                    "events, and consider temporary blocking "
                    "if malicious behavior is confirmed."
                ),

            "rule_detected":
                False,

            "ml_detected":
                False,

            "anomaly_detected":
                False,

            "ioc_hit":
                False,
        })

    return results


# =========================================================
# 4. PRIVILEGE ESCALATION DETECTION
# =========================================================

def detect_privilege_escalation(events):
    """
    Detect possible privilege escalation activity.

    The function returns detailed evidence so the dashboard
    and PDF reports can explain why the threat was detected.
    """

    findings = []

    if not isinstance(
        events,
        list
    ):

        return findings

    keywords = [
        "sudo",
        "administrator",
        "admin privilege",
        "root",
        "privilege escalation",
        "role changed",
        "permission changed",
        "uid=0",
        "elevated privilege",
        "elevated privileges",
        "user added to administrators",
        "added to admin group",
    ]

    for event in events:

        if not isinstance(
            event,
            dict
        ):

            continue

        # -------------------------------------------------
        # Build searchable event text
        # -------------------------------------------------

        text_parts = []

        for key, value in event.items():

            if value is None:
                continue

            text_parts.append(
                str(value)
            )

        text = " ".join(
            text_parts
        ).lower()

        matched = [
            keyword
            for keyword in keywords
            if keyword in text
        ]

        if not matched:
            continue

        source_ip = event.get(
            "source_ip"
        )

        username = (
            event.get("username")
            or event.get("user")
        )

        timestamp = (
            event.get("timestamp")
            or event.get("time")
        )

        evidence = [
            "Privilege-related activity was detected.",
        ]

        for indicator in matched:

            evidence.append(
                f"Matched indicator: {indicator}"
            )

        findings.append({

            "threat_type":
                "privilege_escalation",

            "title":
                "Possible Privilege Escalation Detected",

            "description":
                (
                    "The log contains indicators associated "
                    "with elevated privileges or unauthorized "
                    "privilege changes."
                ),

            "severity":
                "HIGH",

            "confidence":
                0.84,

            "detection_source":
                "privilege_escalation",

            "source_ip":
                source_ip,

            "username":
                username,

            "user":
                username,

            "timestamp":
                timestamp,

            "matched_indicators":
                matched,

            "raw_event":
                event,

            "event_count":
                1,

            "evidence":
                evidence,

            "attack_pattern":
                (
                    "An account or process appears to have "
                    "obtained or attempted to obtain elevated "
                    "privileges."
                ),

            "recommendation":
                (
                    "Verify whether the privilege change was "
                    "authorized. Review the affected account, "
                    "audit administrative activity, and revoke "
                    "unauthorized privileges."
                ),

            "rule_detected":
                True,

            "ml_detected":
                False,

            "anomaly_detected":
                False,

            "ioc_hit":
                False,
        })

    return findings


# =========================================================
# 5. THREAT CORRELATION
# =========================================================

def correlate_threats(events):
    """
    Correlate multiple security events originating from
    the same source IP.

    Multiple threat types from the same source can indicate
    a multi-stage attack.
    """

    ip_events = defaultdict(list)

    if not isinstance(
        events,
        list
    ):

        return []

    for event in events:

        if not isinstance(
            event,
            dict
        ):

            continue

        ip = (
            event.get("source_ip")
            or event.get("src_ip")
            or event.get("ip")
        )

        if ip:

            ip_events[ip].append(
                event
            )

    correlated = []

    for ip, ip_event_list in (
        ip_events.items()
    ):

        threat_types = set()

        # -------------------------------------------------
        # Detect threat types
        # -------------------------------------------------

        for event in ip_event_list:

            threat = event.get(
                "threat_type"
            )

            if threat:

                threat_types.add(
                    str(threat)
                )

            # Search event text as well.
            text_parts = []

            for value in event.values():

                if value is None:
                    continue

                text_parts.append(
                    str(value)
                )

            text = " ".join(
                text_parts
            ).lower()

            if (
                "failed login" in text
                or "brute force" in text
            ):

                threat_types.add(
                    "Brute Force"
                )

            if "port scan" in text:

                threat_types.add(
                    "Port Scan"
                )

            if "sql injection" in text:

                threat_types.add(
                    "SQL Injection"
                )

            if "command injection" in text:

                threat_types.add(
                    "Command Injection"
                )

            if "privilege" in text:

                threat_types.add(
                    "Privilege Escalation"
                )

            if "malware" in text:

                threat_types.add(
                    "Malware"
                )

        # -------------------------------------------------
        # Multiple threat types = attack chain candidate
        # -------------------------------------------------

        if len(threat_types) >= 2:

            confidence = min(
                0.70
                + (
                    len(threat_types) * 0.05
                ),
                0.95
            )

            correlated.append({

                "source_ip":
                    ip,

                "threat_type":
                    "correlated_attack",

                "title":
                    "Correlated Multi-Stage Attack",

                "description":
                    (
                        f"Multiple different threat behaviors "
                        f"were observed from source IP {ip}."
                    ),

                "attack_pattern":
                    "Correlated Multi-Stage Attack",

                "related_threats":
                    sorted(
                        threat_types
                    ),

                "event_count":
                    len(
                        ip_event_list
                    ),

                "severity":
                    "HIGH",

                "confidence":
                    confidence,

                "detection_source":
                    "correlation",

                "correlated":
                    True,

                "evidence": [
                    (
                        f"Source IP {ip} generated "
                        f"{len(ip_event_list)} related event(s)."
                    ),
                    (
                        f"{len(threat_types)} different "
                        f"threat behavior(s) were identified."
                    ),
                    (
                        "The events may represent stages "
                        "of a coordinated attack."
                    ),
                ],

                "recommendation":
                    (
                        "Investigate the complete activity "
                        "timeline for the source IP, identify "
                        "the initial access vector, and contain "
                        "the source if malicious activity is confirmed."
                    ),

                "rule_detected":
                    False,

                "ml_detected":
                    False,

                "anomaly_detected":
                    False,

                "ioc_hit":
                    False,
            })

    return correlated


# =========================================================
# 6. THREAT DEDUPLICATION
# =========================================================

def deduplicate_findings(findings):
    """
    Remove duplicate findings.

    Key:

        threat_type + source_ip + username

    The strongest finding is retained.

    Evidence and detector information from duplicate
    findings are merged.
    """

    if not findings:
        return []

    unique = {}

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):

            continue

        key = (

            str(
                finding.get(
                    "threat_type",
                    ""
                )
            ).lower(),

            str(
                finding.get(
                    "source_ip",
                    ""
                )
            ),

            str(
                finding.get(
                    "username",
                    finding.get(
                        "user",
                        ""
                    )
                )
            ),
        )

        if key not in unique:

            unique[key] = dict(
                finding
            )

            continue

        existing = unique[key]

        # -------------------------------------------------
        # Confidence
        # -------------------------------------------------

        old_confidence = normalize_score(
            existing.get(
                "confidence"
            )
        )

        new_confidence = normalize_score(
            finding.get(
                "confidence"
            )
        )

        if new_confidence > old_confidence:

            existing["confidence"] = (
                new_confidence
            )

        # -------------------------------------------------
        # Severity
        # -------------------------------------------------

        existing["severity"] = bump_severity(
            existing.get(
                "severity",
                "LOW"
            ),
            finding.get(
                "severity",
                "LOW"
            )
        )

        # -------------------------------------------------
        # Boolean evidence
        # -------------------------------------------------

        boolean_fields = [

            "rule_detected",
            "ml_detected",
            "anomaly_detected",
            "ioc_hit",
            "correlated",

        ]

        for field in boolean_fields:

            if finding.get(field):

                existing[field] = True

        # -------------------------------------------------
        # Numeric detector scores
        # -------------------------------------------------

        score_fields = [

            "rule_score",
            "ml_score",
            "anomaly_score",
            "threat_intelligence_score",
            "correlation_score",
            "llm_score",

        ]

        for field in score_fields:

            old_score = normalize_score(
                existing.get(
                    field
                )
            )

            new_score = normalize_score(
                finding.get(
                    field
                )
            )

            existing[field] = max(
                old_score,
                new_score
            )

        # -------------------------------------------------
        # Maximum anomaly z-score
        # -------------------------------------------------

        try:

            old_zscore = float(
                existing.get(
                    "max_zscore",
                    0.0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            old_zscore = 0.0

        try:

            new_zscore = float(
                finding.get(
                    "max_zscore",
                    0.0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            new_zscore = 0.0

        existing["max_zscore"] = max(
            old_zscore,
            new_zscore
        )

        # -------------------------------------------------
        # Merge anomaly features
        # -------------------------------------------------

        old_features = existing.get(
            "anomaly_features",
            []
        )

        new_features = finding.get(
            "anomaly_features",
            []
        )

        if not isinstance(
            old_features,
            list
        ):

            old_features = []

        if not isinstance(
            new_features,
            list
        ):

            new_features = []

        combined_features = (
            old_features
            + new_features
        )

        merged_features = []

        for feature in combined_features:

            if feature not in merged_features:

                merged_features.append(
                    feature
                )

        existing[
            "anomaly_features"
        ] = merged_features

        # -------------------------------------------------
        # Merge evidence
        # -------------------------------------------------

        old_evidence = existing.get(
            "evidence",
            []
        )

        new_evidence = finding.get(
            "evidence",
            []
        )

        if not isinstance(
            old_evidence,
            list
        ):

            old_evidence = (
                [old_evidence]
                if old_evidence
                else []
            )

        if not isinstance(
            new_evidence,
            list
        ):

            new_evidence = (
                [new_evidence]
                if new_evidence
                else []
            )

        merged_evidence = []

        for item in (
            old_evidence
            + new_evidence
        ):

            if item not in merged_evidence:

                merged_evidence.append(
                    item
                )

        existing[
            "evidence"
        ] = merged_evidence

        # -------------------------------------------------
        # Preserve richer fields
        # -------------------------------------------------

        rich_fields = [

            "attack_pattern",
            "recommendation",
            "description",
            "llm_summary",
            "explanation",
            "mitre_techniques",

        ]

        for field in rich_fields:

            if not existing.get(field):

                if finding.get(field):

                    existing[field] = finding[field]

    return list(
        unique.values()
    )


# =========================================================
# 7. GENERATE THREAT EVIDENCE
# =========================================================

def generate_evidence(finding):
    """
    Generate standardized evidence for a finding.
    """

    evidence = finding.get(
        "evidence",
        []
    )

    if not isinstance(
        evidence,
        list
    ):

        evidence = (
            [evidence]
            if evidence
            else []
        )

    evidence = list(
        evidence
    )

    source_ip = finding.get(
        "source_ip"
    )

    threat_type = finding.get(
        "threat_type",
        "security threat"
    )

    if source_ip:

        message = (
            f"Source IP involved: {source_ip}"
        )

        if message not in evidence:

            evidence.append(
                message
            )

    # -----------------------------------------------------
    # Rule evidence
    # -----------------------------------------------------

    if finding.get(
        "rule_detected"
    ):

        message = (
            "Rule-based detection "
            "matched suspicious behavior."
        )

        if message not in evidence:

            evidence.append(
                message
            )

    # -----------------------------------------------------
    # ML evidence
    # -----------------------------------------------------

    ml_score = normalize_score(
        finding.get(
            "ml_score"
        )
    )

    if (
        finding.get("ml_detected")
        or ml_score >= 0.50
    ):

        message = (
            f"Machine-learning detection score: "
            f"{ml_score * 100:.1f}%."
        )

        if message not in evidence:

            evidence.append(
                message
            )

    # -----------------------------------------------------
    # Anomaly evidence
    # -----------------------------------------------------

    anomaly_score = normalize_score(
        finding.get(
            "anomaly_score"
        )
    )

    if (
        finding.get("anomaly_detected")
        or anomaly_score > 0
    ):

        message = (
            f"Anomaly detection score: "
            f"{anomaly_score * 100:.1f}%."
        )

        if message not in evidence:

            evidence.append(
                message
            )

    # -----------------------------------------------------
    # IOC evidence
    # -----------------------------------------------------

    if finding.get(
        "ioc_hit"
    ):

        message = (
            "Source matched a known "
            "threat-intelligence indicator."
        )

        if message not in evidence:

            evidence.append(
                message
            )

    # -----------------------------------------------------
    # Correlation evidence
    # -----------------------------------------------------

    if finding.get(
        "correlated"
    ):

        message = (
            "The event is associated with "
            "a correlated attack pattern."
        )

        if message not in evidence:

            evidence.append(
                message
            )

    # -----------------------------------------------------
    # Threat type fallback
    # -----------------------------------------------------

    if not evidence:

        evidence.append(
            (
                f"The detection engine identified "
                f"behavior associated with "
                f"{threat_type}."
            )
        )

    finding["evidence"] = evidence

    return evidence


# =========================================================
# 8. ATTACK PATTERN GENERATION
# =========================================================

def generate_attack_pattern(finding):
    """
    Generate an attack-pattern description if one does not
    already exist.
    """

    existing = finding.get(
        "attack_pattern"
    )

    if existing:

        return existing

    threat_type = str(
        finding.get(
            "threat_type",
            ""
        )
    ).lower()

    patterns = {

        "brute_force":
            (
                "Repeated authentication failures from "
                "the same source indicate a possible "
                "credential brute-force attack."
            ),

        "port_scan":
            (
                "Repeated connection attempts against "
                "multiple ports indicate reconnaissance "
                "or network scanning activity."
            ),

        "sql_injection":
            (
                "Input containing SQL-related attack "
                "patterns suggests an attempt to manipulate "
                "a database query."
            ),

        "command_injection":
            (
                "Suspicious command content indicates a "
                "possible attempt to execute attacker-controlled "
                "commands on the target system."
            ),

        "malware":
            (
                "Observed behavior or indicators are "
                "consistent with potentially malicious "
                "software activity."
            ),

        "malware_detected":
            (
                "Observed indicators are consistent with "
                "malicious software execution or delivery."
            ),

        "privilege_escalation":
            (
                "An account or process appears to have "
                "attempted to obtain elevated privileges."
            ),

        "suspicious_ip":
            (
                "Multiple security-related activities "
                "originated from the same source IP."
            ),

        "known_malicious_ip":
            (
                "Traffic originated from an IP address "
                "identified by the threat-intelligence system."
            ),

        "anomalous_behavior":
            (
                "Observed activity deviates significantly "
                "from the established behavioral baseline."
            ),

        "ml_flagged":
            (
                "Machine-learning models identified behavior "
                "that differs from expected traffic patterns."
            ),

        "correlated_attack":
            (
                "Multiple related security events indicate "
                "a possible multi-stage attack."
            ),
    }

    pattern = None

    for key, description in patterns.items():

        if key in threat_type:

            pattern = description

            break

    if not pattern:

        pattern = (
            "The detection engine identified behavior "
            "associated with a potential security threat."
        )

    finding[
        "attack_pattern"
    ] = pattern

    return pattern


# =========================================================
# 9. RECOMMENDATION GENERATION
# =========================================================

def generate_recommendation(finding):
    """
    Generate a remediation recommendation.
    """

    existing = finding.get(
        "recommendation"
    )

    if existing:

        return existing

    threat_type = str(
        finding.get(
            "threat_type",
            ""
        )
    ).lower()

    recommendations = {

        "brute_force":
            (
                "Investigate the targeted account, "
                "apply rate limiting or account lockout, "
                "consider blocking the source IP, and "
                "reset credentials if compromise is suspected."
            ),

        "port_scan":
            (
                "Investigate the source IP, restrict unnecessary "
                "network exposure, and monitor for follow-up "
                "exploitation attempts."
            ),

        "sql_injection":
            (
                "Review the affected application request, "
                "use parameterized queries, validate input, "
                "and investigate the source IP."
            ),

        "command_injection":
            (
                "Review the affected application or host, "
                "validate and sanitize input, restrict command "
                "execution privileges, and investigate the source."
            ),

        "malware":
            (
                "Isolate the affected host if necessary, "
                "perform malware analysis, remove malicious "
                "components, and investigate persistence mechanisms."
            ),

        "malware_detected":
            (
                "Isolate the affected system if appropriate, "
                "perform malware analysis, and investigate "
                "possible persistence or lateral movement."
            ),

        "privilege_escalation":
            (
                "Verify whether the privilege change was "
                "authorized, audit the affected account, "
                "and revoke unauthorized privileges."
            ),

        "suspicious_ip":
            (
                "Review all activity associated with the IP "
                "and consider blocking or rate-limiting it "
                "if malicious behavior is confirmed."
            ),

        "known_malicious_ip":
            (
                "Block or contain the malicious source where "
                "appropriate and investigate all associated "
                "events for possible compromise."
            ),

        "anomalous_behavior":
            (
                "Review the anomalous activity against the "
                "normal baseline and investigate related events."
            ),

        "ml_flagged":
            (
                "Review the ML-flagged activity alongside "
                "rule and anomaly evidence before taking "
                "containment action."
            ),

        "correlated_attack":
            (
                "Investigate the complete attack timeline, "
                "identify the initial access vector, contain "
                "affected systems, and review lateral movement."
            ),
    }

    recommendation = None

    for key, text in recommendations.items():

        if key in threat_type:

            recommendation = text

            break

    if not recommendation:

        recommendation = (
            "Investigate the detected activity, review "
            "supporting evidence, and monitor the affected "
            "source and target systems."
        )

    finding[
        "recommendation"
    ] = recommendation

    return recommendation


# =========================================================
# 10. MANDATORY EXPLANATION
# =========================================================

def generate_explanation(finding):
    """
    Generate a mandatory human-readable explanation.

    This is the fallback explanation used when the LLM
    cannot provide an explanation.

    IMPORTANT:
        This text must not claim that an LLM generated it.
    """

    existing = (
        finding.get("explanation")
        or finding.get("llm_summary")
    )

    if existing:

        existing_text = str(
            existing
        ).strip()

        if (
            existing_text
            and "unavailable" not in existing_text.lower()
            and "failed" not in existing_text.lower()
        ):

            finding[
                "explanation"
            ] = existing_text

            return existing_text

    threat_type = str(
        finding.get(
            "threat_type",
            "security threat"
        )
    ).replace(
        "_",
        " "
    ).strip()

    severity = str(
        finding.get(
            "severity",
            "MEDIUM"
        )
    ).upper()

    confidence = normalize_confidence(
        finding.get(
            "confidence"
        )
    )

    source_ip = finding.get(
        "source_ip"
    )

    evidence = finding.get(
        "evidence",
        []
    )

    if not isinstance(
        evidence,
        list
    ):

        evidence = (
            [evidence]
            if evidence
            else []
        )

    # -----------------------------------------------------
    # Threat-specific explanations
    # -----------------------------------------------------

    if (
        "brute"
        in threat_type.lower()
    ):

        if source_ip:

            explanation = (
                f"The system detected behavior consistent "
                f"with a brute-force attack involving source "
                f"IP {source_ip}. "
            )

        else:

            explanation = (
                "The system detected behavior consistent "
                "with a brute-force attack. "
            )

        explanation += (
            "Repeated authentication failures or related "
            "security indicators provided the primary "
            "detection evidence."
        )

    elif (
        "port"
        in threat_type.lower()
        and "scan"
        in threat_type.lower()
    ):

        explanation = (
            "The system detected network reconnaissance "
            "behavior consistent with port scanning. "
            "Repeated connection attempts across network "
            "ports provided the primary detection evidence."
        )

    elif (
        "sql"
        in threat_type.lower()
    ):

        explanation = (
            "The system detected input or request behavior "
            "consistent with SQL injection. The observed "
            "request matched indicators associated with "
            "database query manipulation."
        )

    elif (
        "command"
        in threat_type.lower()
        and "injection"
        in threat_type.lower()
    ):

        explanation = (
            "The system detected suspicious input consistent "
            "with command injection. The observed activity "
            "contained indicators associated with attacker-"
            "controlled command execution."
        )

    elif (
        "privilege"
        in threat_type.lower()
    ):

        explanation = (
            "The system detected activity associated with "
            "privilege escalation. Privileged commands, "
            "administrative changes, or elevated-access "
            "indicators were observed."
        )

    elif (
        "malware"
        in threat_type.lower()
    ):

        explanation = (
            "The system detected behavior or indicators "
            "consistent with potentially malicious software. "
            "The activity requires investigation to determine "
            "whether the host or process is compromised."
        )

    elif (
        "malicious"
        in threat_type.lower()
        and "ip"
        in threat_type.lower()
    ):

        explanation = (
            "The source IP matched a known malicious or "
            "threat-intelligence indicator. Traffic from "
            "this source should therefore be investigated "
            "as potentially hostile."
        )

    elif (
        "anomal"
        in threat_type.lower()
    ):

        explanation = (
            "The system detected activity that deviates "
            "significantly from the established behavioral "
            "baseline. The anomaly evidence indicates that "
            "the observed behavior requires investigation."
        )

    elif (
        "correlated"
        in threat_type.lower()
    ):

        explanation = (
            "Multiple related security events were correlated "
            "into a potential multi-stage attack pattern. "
            "The relationship between these events increases "
            "the importance of investigating the complete "
            "activity timeline."
        )

    else:

        explanation = (
            f"The autonomous detection system identified "
            f"activity associated with {threat_type}. "
            f"The finding was classified as {severity}."
        )

    # -----------------------------------------------------
    # Add confidence
    # -----------------------------------------------------

    explanation += (
        f" The current evidence-based confidence is "
        f"{confidence:.1f}%."
    )

    # -----------------------------------------------------
    # Add evidence count
    # -----------------------------------------------------

    if evidence:

        explanation += (
            f" {len(evidence)} supporting evidence item(s) "
            f"were recorded for this finding."
        )

    finding[
        "explanation"
    ] = explanation

    return explanation


# =========================================================
# 11. COMPLETE THREAT ENRICHMENT
# =========================================================

def enrich_threat(finding):
    """
    Fully enrich a threat finding.

    Does NOT replace the dynamic confidence calculated by
    threat_classifier.py.
    """

    if not isinstance(
        finding,
        dict
    ):

        return finding

    # -----------------------------------------------------
    # Normalize basic fields
    # -----------------------------------------------------

    finding.setdefault(
        "threat_type",
        "unknown_threat"
    )

    finding.setdefault(
        "title",
        str(
            finding.get(
                "threat_type"
            )
        ).replace(
            "_",
            " "
        ).title()
    )

    finding.setdefault(
        "description",
        "Suspicious activity detected."
    )

    finding.setdefault(
        "source_ip",
        None
    )

    finding.setdefault(
        "status",
        "OPEN"
    )

    # -----------------------------------------------------
    # Preserve confidence
    # -----------------------------------------------------

    existing_confidence = normalize_score(
        finding.get(
            "confidence"
        )
    )

    finding[
        "confidence"
    ] = round(
        existing_confidence,
        4
    )

    # -----------------------------------------------------
    # Detector flags
    # -----------------------------------------------------

    finding.setdefault(
        "rule_detected",
        False
    )

    finding.setdefault(
        "ml_detected",
        False
    )

    finding.setdefault(
        "anomaly_detected",
        False
    )

    finding.setdefault(
        "ioc_hit",
        False
    )

    finding.setdefault(
        "correlated",
        False
    )

    # -----------------------------------------------------
    # Detector scores
    # -----------------------------------------------------

    finding[
        "rule_score"
    ] = normalize_score(
        finding.get(
            "rule_score",
            0.0
        )
    )

    finding[
        "ml_score"
    ] = normalize_score(
        finding.get(
            "ml_score",
            0.0
        )
    )

    finding[
        "anomaly_score"
    ] = normalize_score(
        finding.get(
            "anomaly_score",
            0.0
        )
    )

    finding[
        "threat_intelligence_score"
    ] = normalize_score(
        finding.get(
            "threat_intelligence_score",
            0.98
            if finding.get("ioc_hit")
            else 0.0
        )
    )

    finding[
        "correlation_score"
    ] = normalize_score(
        finding.get(
            "correlation_score",
            0.80
            if finding.get("correlated")
            else 0.0
        )
    )

    finding[
        "llm_score"
    ] = normalize_score(
        finding.get(
            "llm_score",
            0.0
        )
    )

    # -----------------------------------------------------
    # Event count
    # -----------------------------------------------------

    try:

        event_count = int(
            finding.get(
                "event_count",
                1
            )
        )

    except (
        TypeError,
        ValueError
    ):

        event_count = 1

    finding[
        "event_count"
    ] = max(
        1,
        event_count
    )

    # -----------------------------------------------------
    # Severity
    # -----------------------------------------------------

    finding[
        "severity"
    ] = calculate_severity(
        threat_type=finding.get(
            "threat_type"
        ),
        event_count=finding.get(
            "event_count",
            1
        ),
        confidence=finding.get(
            "confidence"
        ),
        current_severity=finding.get(
            "severity"
        )
    )

    # -----------------------------------------------------
    # Evidence
    # -----------------------------------------------------

    generate_evidence(
        finding
    )

    # -----------------------------------------------------
    # Attack pattern
    # -----------------------------------------------------

    generate_attack_pattern(
        finding
    )

    # -----------------------------------------------------
    # Recommendation
    # -----------------------------------------------------

    generate_recommendation(
        finding
    )

    # -----------------------------------------------------
    # Mandatory explanation
    # -----------------------------------------------------

    generate_explanation(
        finding
    )

    # -----------------------------------------------------
    # Analysis status
    # -----------------------------------------------------

    if finding.get(
        "llm_summary"
    ):

        finding[
            "analysis_status"
        ] = "ANALYZED"

    else:

        finding[
            "analysis_status"
        ] = "FALLBACK_ANALYSIS"

    # -----------------------------------------------------
    # Investigation information
    # -----------------------------------------------------

    finding[
        "investigation"
    ] = {

        "username":
            (
                finding.get("username")
                or finding.get("user")
            ),

        "source_ip":
            finding.get(
                "source_ip"
            ),

        "destination_ip":
            finding.get(
                "dest_ip"
            ),

        "threat_type":
            finding.get(
                "threat_type"
            ),

        "severity":
            finding.get(
                "severity"
            ),

        "confidence":
            normalize_confidence(
                finding.get(
                    "confidence"
                )
            ),

        "timestamp":
            (
                finding.get("timestamp")
                or finding.get("created_at")
            ),

        "explanation":
            finding.get(
                "explanation"
            ),

        "attack_pattern":
            finding.get(
                "attack_pattern"
            ),

        "recommendation":
            finding.get(
                "recommendation"
            ),

        "evidence":
            finding.get(
                "evidence",
                []
            ),
    }

    return finding
