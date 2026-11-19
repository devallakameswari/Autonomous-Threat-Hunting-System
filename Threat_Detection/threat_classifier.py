"""
Threat_Detection/threat_classifier.py

Combines:
- Rule-based detection
- Machine Learning detection
- Statistical anomaly detection
- Threat Intelligence / IOC detection

into finalized threat findings with:
- Dynamic confidence score
- Dynamic severity
- Evidence fields
- Explainable anomaly information
- Deduplication
"""

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# =========================================================
# HELPERS
# =========================================================

def normalize_score(value, default=0.0):
    """
    Convert a score to a value between 0.0 and 1.0.

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
            value = value / 100.0

        return max(0.0, min(1.0, value))

    except (TypeError, ValueError):
        return default


def get_ml_score(ml_result):
    """
    Extract ML confidence from the actual ML result.

    Supports several common result-key names so the classifier
    remains compatible with different ModelManager versions.
    """

    if not isinstance(ml_result, dict):
        return 0.0

    possible_keys = [
        "rf_probability",
        "rf_confidence",
        "ml_probability",
        "ml_confidence",
        "probability",
        "confidence",
        "score",
    ]

    for key in possible_keys:

        value = ml_result.get(key)

        if value is not None:
            score = normalize_score(value)

            if score > 0:
                return score

    return 0.0


def anomaly_confidence(anomaly_result):
    """
    Convert the actual anomaly detector output into confidence.

    Your AnomalyDetector returns:

        is_anomaly
        max_zscore
        contributing_features

    Higher z-score = stronger anomaly evidence.
    """

    if not isinstance(anomaly_result, dict):
        return 0.0

    if not anomaly_result.get("is_anomaly"):
        return 0.0

    max_zscore = anomaly_result.get(
        "max_zscore",
        0.0
    )

    try:
        max_zscore = abs(float(max_zscore))
    except (TypeError, ValueError):
        return 0.0

    # Convert z-score into a confidence value.
    #
    # z = 2  -> 0.70
    # z = 3  -> 0.80
    # z = 4  -> 0.90
    # z >= 5 -> 0.95
    #
    score = 0.50 + (max_zscore / 10.0)

    return round(
        min(0.95, max(0.0, score)),
        2
    )


def threat_type_base_confidence(threat_type):
    """
    Base confidence for known threat types.
    """

    threat_type = str(
        threat_type or ""
    ).lower()

    scores = {
        "brute_force": 0.78,
        "port_scan": 0.75,
        "sql_injection": 0.88,
        "command_injection": 0.90,
        "malware": 0.90,
        "malware_detected": 0.90,
        "ransomware": 0.95,
        "privilege_escalation": 0.84,
        "suspicious_ip": 0.75,
        "known_malicious_ip": 0.98,
        "anomalous_behavior": 0.70,
        "ml_flagged": 0.65,
    }

    for key, score in scores.items():

        if key in threat_type:
            return score

    return 0.55


def bump_severity(current, minimum):
    """
    Increase severity only when the minimum severity is higher.
    """

    current = str(
        current or "MEDIUM"
    ).upper()

    minimum = str(
        minimum or "LOW"
    ).upper()

    if SEVERITY_ORDER.get(
        minimum,
        0
    ) > SEVERITY_ORDER.get(
        current,
        0
    ):
        return minimum

    return current


# =========================================================
# DYNAMIC CONFIDENCE
# =========================================================

def calculate_confidence(
    finding,
    ml_result=None,
    anomaly_result=None,
    ioc_hit=False
):
    """
    Calculate dynamic confidence using multiple independent
    detection signals.

    Evidence:
        Rule
        ML
        Anomaly
        IOC
        Threat type
        Correlation
        Severity
        Privilege escalation
        Suspicious IP
    """

    if not isinstance(finding, dict):
        return 0.0

    ml_result = (
        ml_result
        if isinstance(ml_result, dict)
        else {}
    )

    anomaly_result = (
        anomaly_result
        if isinstance(anomaly_result, dict)
        else {}
    )

    # -----------------------------------------------------
    # Existing confidence
    # -----------------------------------------------------

    existing = normalize_score(
        finding.get("confidence"),
        default=0.0
    )

    # -----------------------------------------------------
    # Threat type evidence
    # -----------------------------------------------------

    threat_type = str(
        finding.get(
            "threat_type",
            ""
        )
    ).lower()

    base_score = threat_type_base_confidence(
        threat_type
    )

    # -----------------------------------------------------
    # Rule evidence
    # -----------------------------------------------------

    rule_detected = bool(
        finding.get("rule_match")
        or finding.get("rule_detected")
        or finding.get("rule_triggered")
        or finding.get("matched_rule")
        or finding.get("detection_source", "").lower()
        in [
            "rule",
            "rule_engine"
        ]
    )

    rule_score = (
        0.72
        if rule_detected
        else 0.0
    )

    # -----------------------------------------------------
    # ML evidence
    # -----------------------------------------------------

    ml_score = get_ml_score(
        ml_result
    )

    # If classifier already attached ML score,
    # use that as fallback.
    if ml_score == 0:
        ml_score = normalize_score(
            finding.get("ml_score")
        )

    ml_detected = bool(
        ml_result.get("rf_label") == 1
        or ml_result.get("ml_label") == 1
        or ml_result.get("is_malicious")
        or ml_score >= 0.50
        or finding.get("ml_detected")
    )

    # -----------------------------------------------------
    # Anomaly evidence
    # -----------------------------------------------------

    anomaly_detected = bool(
        anomaly_result.get(
            "is_anomaly"
        )
        or finding.get(
            "anomaly_detected"
        )
    )

    anomaly_score = anomaly_confidence(
        anomaly_result
    )

    if anomaly_score == 0:
        anomaly_score = normalize_score(
            finding.get(
                "anomaly_score"
            )
        )

    # -----------------------------------------------------
    # IOC evidence
    # -----------------------------------------------------

    ioc_detected = bool(
        ioc_hit
        or finding.get("ioc_hit")
        or finding.get("ioc_match")
        or finding.get("known_malicious")
        or finding.get(
            "threat_intelligence"
        )
    )

    ioc_score = (
        0.98
        if ioc_detected
        else 0.0
    )

    # -----------------------------------------------------
    # Detection source evidence
    # -----------------------------------------------------

    source = str(
        finding.get(
            "detection_source",
            ""
        )
    ).lower()

    source_score = 0.0

    if "ioc" in source:
        source_score = 0.98

    elif "rule" in source:
        source_score = 0.72

    elif "ml" in source:
        source_score = ml_score or 0.65

    elif "anomaly" in source:
        source_score = anomaly_score or 0.70

    elif "privilege" in source:
        source_score = 0.84

    # -----------------------------------------------------
    # Select strongest evidence
    # -----------------------------------------------------

    evidence_scores = [
        base_score,
        existing,
        rule_score,
        ml_score,
        anomaly_score,
        ioc_score,
        source_score,
    ]

    evidence_scores = [
        score
        for score in evidence_scores
        if score > 0
    ]

    if evidence_scores:

        strongest = max(
            evidence_scores
        )

        confidence = strongest

    else:

        confidence = 0.0

    # -----------------------------------------------------
    # Multiple independent signals
    # -----------------------------------------------------

    signal_count = 0

    if rule_detected:
        signal_count += 1

    if ml_detected:
        signal_count += 1

    if anomaly_detected:
        signal_count += 1

    if ioc_detected:
        signal_count += 1

    if (
        finding.get("correlated")
        or finding.get("correlation")
        or finding.get("attack_chain")
        or finding.get("chain_id")
    ):
        signal_count += 1

    # Additional evidence increases confidence.
    if signal_count >= 2:
        confidence += 0.05

    if signal_count >= 3:
        confidence += 0.06

    if signal_count >= 4:
        confidence += 0.07

    # -----------------------------------------------------
    # Privilege escalation
    # -----------------------------------------------------

    if (
        "privilege" in threat_type
        and "escalation" in threat_type
    ):
        confidence += 0.05

    # -----------------------------------------------------
    # Suspicious IP
    # -----------------------------------------------------

    if (
        "suspicious" in threat_type
        and "ip" in threat_type
    ):
        confidence += 0.03

    # -----------------------------------------------------
    # Correlation
    # -----------------------------------------------------

    if (
        finding.get("correlated")
        or finding.get("correlation")
        or finding.get("attack_chain")
        or finding.get("chain_id")
    ):
        confidence += 0.05

    # -----------------------------------------------------
    # Severity contribution
    # -----------------------------------------------------

    severity = str(
        finding.get(
            "severity",
            ""
        )
    ).upper()

    severity_bonus = {
        "LOW": 0.00,
        "MEDIUM": 0.02,
        "HIGH": 0.04,
        "CRITICAL": 0.06,
    }

    confidence += severity_bonus.get(
        severity,
        0.0
    )

    # -----------------------------------------------------
    # IOC always produces very high confidence
    # -----------------------------------------------------

    if ioc_detected:

        confidence = max(
            confidence,
            0.95
        )

    # -----------------------------------------------------
    # Final bounds
    # -----------------------------------------------------

    confidence = max(
        0.0,
        min(
            1.0,
            confidence
        )
    )

    return round(
        confidence,
        2
    )


# =========================================================
# CLASSIFY IP
# =========================================================

def classify_ip(
    ip: str,
    feature_dict: dict,
    rule_findings: list,
    ml_result: dict,
    anomaly_result: dict,
    ioc_hit: bool
) -> list:
    """
    Combine rule, ML, anomaly and IOC signals.

    Returns finalized findings for the IP.
    """

    if not isinstance(
        rule_findings,
        list
    ):
        rule_findings = []

    if not isinstance(
        ml_result,
        dict
    ):
        ml_result = {}

    if not isinstance(
        anomaly_result,
        dict
    ):
        anomaly_result = {}

    findings = []

    # =====================================================
    # 1. RULE FINDINGS
    # =====================================================

    for original in rule_findings:

        finding = dict(
            original
        )

        finding.setdefault(
            "source_ip",
            ip
        )

        finding["rule_detected"] = True

        findings.append(
            finding
        )

    # =====================================================
    # 2. ML DETECTION
    # =====================================================

    ml_score = get_ml_score(
        ml_result
    )

    ml_flagged = bool(
        ml_result.get("rf_label") == 1
        or ml_result.get("ml_label") == 1
        or ml_result.get("is_malicious")
        or ml_result.get("iso_is_anomaly")
        or ml_result.get("ae_is_anomaly")
        or ml_score >= 0.50
    )

    # Only create a separate ML finding if
    # no rule already detected this IP.
    if ml_flagged and not rule_findings:

        severity = (
            "CRITICAL"
            if ml_score >= 0.90
            else "HIGH"
            if ml_score >= 0.75
            else "MEDIUM"
        )

        findings.append({

            "threat_type":
                "ml_flagged",

            "title":
                f"ML models flagged suspicious traffic from {ip}",

            "description":
                (
                    "Machine-learning analysis identified "
                    "behavior that differs from the expected "
                    "traffic pattern."
                ),

            "severity":
                severity,

            "confidence":
                ml_score,

            "detection_source":
                "ml",

            "source_ip":
                ip,

            "ml_score":
                ml_score,

            "ml_detected":
                True,

            "rule_detected":
                False,
        })

    # =====================================================
    # 3. ANOMALY DETECTION
    # =====================================================

    anomaly_flagged = bool(
        anomaly_result.get(
            "is_anomaly"
        )
    )

    anomaly_score = anomaly_confidence(
        anomaly_result
    )

    if anomaly_flagged and not rule_findings and not ml_flagged:

        contributing = (
            anomaly_result.get(
                "contributing_features",
                []
            )
        )

        contribution_text = ", ".join(
            f"{name} (z={z})"
            for name, z in contributing[:5]
        )

        findings.append({

            "threat_type":
                "anomalous_behavior",

            "title":
                f"Statistical anomaly detected for {ip}",

            "description":
                (
                    f"Behavior from {ip} deviates "
                    f"significantly from the observed "
                    f"baseline."
                ),

            "severity":
                (
                    "HIGH"
                    if anomaly_score >= 0.85
                    else "MEDIUM"
                ),

            "confidence":
                anomaly_score,

            "detection_source":
                "anomaly",

            "source_ip":
                ip,

            "anomaly_detected":
                True,

            "anomaly_score":
                anomaly_score,

            "max_zscore":
                anomaly_result.get(
                    "max_zscore",
                    0
                ),

            "contributing_features":
                contributing,

            "anomaly_evidence":
                contribution_text,

            "rule_detected":
                False,
        })

    # =====================================================
    # 4. IOC DETECTION
    # =====================================================

    if ioc_hit:

        findings.append({

            "threat_type":
                "known_malicious_ip",

            "title":
                f"Traffic from known-malicious IP {ip}",

            "description":
                (
                    f"{ip} appears in the current "
                    "threat-intelligence IOC feed."
                ),

            "severity":
                "CRITICAL",

            "confidence":
                0.98,

            "detection_source":
                "ioc",

            "source_ip":
                ip,

            "ioc_hit":
                True,

            "rule_detected":
                False,
        })

    # =====================================================
    # 5. ATTACH EVIDENCE TO EVERY FINDING
    # =====================================================

    for finding in findings:

        finding.setdefault(
            "source_ip",
            ip
        )

        finding["ml_score"] = (
            ml_score
        )

        finding["ml_detected"] = (
            ml_flagged
        )

        finding["anomaly_detected"] = (
            anomaly_flagged
        )

        finding["anomaly_score"] = (
            anomaly_score
        )

        finding["max_zscore"] = (
            anomaly_result.get(
                "max_zscore",
                0.0
            )
        )

        finding["anomaly_features"] = (
            anomaly_result.get(
                "contributing_features",
                []
            )
        )

        finding["ioc_hit"] = (
            bool(
                ioc_hit
                or finding.get(
                    "ioc_hit"
                )
            )
        )

        finding["rule_detected"] = (
            bool(
                finding.get(
                    "rule_detected"
                )
            )
        )

        # Calculate dynamic confidence.
        finding["confidence"] = (
            calculate_confidence(
                finding,
                ml_result,
                anomaly_result,
                ioc_hit
            )
        )

        # =================================================
        # DYNAMIC SEVERITY
        # =================================================

        current_severity = str(
            finding.get(
                "severity",
                "MEDIUM"
            )
        ).upper()

        # IOC
        if ioc_hit:
            current_severity = bump_severity(
                current_severity,
                "CRITICAL"
            )

        # Strong ML
        if ml_score >= 0.90:
            current_severity = bump_severity(
                current_severity,
                "CRITICAL"
            )

        elif ml_score >= 0.75:
            current_severity = bump_severity(
                current_severity,
                "HIGH"
            )

        # Strong anomaly
        if anomaly_score >= 0.90:
            current_severity = bump_severity(
                current_severity,
                "HIGH"
            )

        finding["severity"] = (
            current_severity
        )

    return findings


# =========================================================
# DEDUPLICATION
# =========================================================

def deduplicate_findings(
    findings: list
) -> list:
    """
    Remove duplicate findings using:

        source_ip + threat_type

    The strongest finding is preserved.

    Evidence from duplicate findings is merged.
    """

    if not findings:
        return []

    best = {}

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        source_ip = finding.get(
            "source_ip"
        )

        threat_type = finding.get(
            "threat_type"
        )

        key = (
            source_ip,
            threat_type
        )

        if key not in best:

            best[key] = dict(
                finding
            )

            continue

        existing = best[key]

        # -------------------------------------------------
        # Keep highest severity
        # -------------------------------------------------

        existing_severity = SEVERITY_ORDER.get(
            str(
                existing.get(
                    "severity",
                    "LOW"
                )
            ).upper(),
            0
        )

        new_severity = SEVERITY_ORDER.get(
            str(
                finding.get(
                    "severity",
                    "LOW"
                )
            ).upper(),
            0
        )

        if new_severity > existing_severity:

            best[key] = dict(
                finding
            )

            existing = best[key]

        # -------------------------------------------------
        # Keep highest confidence
        # -------------------------------------------------

        existing_confidence = normalize_score(
            existing.get(
                "confidence"
            )
        )

        new_confidence = normalize_score(
            finding.get(
                "confidence"
            )
        )

        if new_confidence > existing_confidence:

            existing["confidence"] = (
                new_confidence
            )

        # -------------------------------------------------
        # Merge evidence
        # -------------------------------------------------

        evidence_fields = [

            "rule_detected",
            "ml_detected",
            "anomaly_detected",
            "ioc_hit",
            "correlated",

        ]

        for field in evidence_fields:

            if finding.get(field):

                existing[field] = True

        # -------------------------------------------------
        # Keep strongest ML score
        # -------------------------------------------------

        existing_ml = normalize_score(
            existing.get(
                "ml_score"
            )
        )

        new_ml = normalize_score(
            finding.get(
                "ml_score"
            )
        )

        existing["ml_score"] = max(
            existing_ml,
            new_ml
        )

        # -------------------------------------------------
        # Keep strongest anomaly score
        # -------------------------------------------------

        existing_anomaly = normalize_score(
            existing.get(
                "anomaly_score"
            )
        )

        new_anomaly = normalize_score(
            finding.get(
                "anomaly_score"
            )
        )

        existing["anomaly_score"] = max(
            existing_anomaly,
            new_anomaly
        )

        # -------------------------------------------------
        # Keep maximum z-score
        # -------------------------------------------------

        try:

            existing_z = float(
                existing.get(
                    "max_zscore",
                    0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            existing_z = 0.0

        try:

            new_z = float(
                finding.get(
                    "max_zscore",
                    0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            new_z = 0.0

        existing["max_zscore"] = max(
            existing_z,
            new_z
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

        combined = (
            old_features
            + new_features
        )

        # Remove duplicates while preserving order.
        unique_features = []

        for feature in combined:

            if feature not in unique_features:

                unique_features.append(
                    feature
                )

        existing["anomaly_features"] = (
            unique_features
        )

    return list(
        best.values()
    )