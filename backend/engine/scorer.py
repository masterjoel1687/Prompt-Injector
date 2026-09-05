class RiskScorer:
    """
    Explainable risk scoring engine.

    The score considers:
    - vulnerability severity
    - detector/judge confidence
    - adaptive reproducibility

    Critical findings have a much stronger influence than
    Medium/Low findings.
    """

    SEVERITY_WEIGHTS = {
        "Critical": 40,
        "High": 25,
        "Medium": 12,
        "Low": 5,
    }

    SEVERITY_ORDER = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }

    @classmethod
    def calculate(cls, findings, total_tests=None):
        if total_tests is None:
            total_tests = len(findings)

        total_tests = max(int(total_tests), 1)

        vulnerable = [
            item
            for item in findings
            if item.get("verdict") == "VULNERABLE"
        ]

        blocked = [
            item
            for item in findings
            if item.get("verdict") == "BLOCKED"
        ]

        review = [
            item
            for item in findings
            if item.get("verdict") == "REVIEW"
        ]

        # -----------------------------------------------------
        # Calculate weighted vulnerability risk
        # -----------------------------------------------------

        raw_score = 0.0

        for finding in vulnerable:

            severity = finding.get(
                "severity",
                "Medium",
            )

            weight = cls.SEVERITY_WEIGHTS.get(
                severity,
                12,
            )

            confidence = float(
                finding.get(
                    "confidence",
                    0.5,
                )
            )

            confidence = max(
                0.0,
                min(1.0, confidence),
            )

            # Adaptive reproducibility multiplier.
            adaptive = finding.get(
                "adaptive_verification"
            )

            reproducibility = 1.0

            if adaptive:

                ratio = float(
                    adaptive.get(
                        "vulnerable_ratio",
                        0.0,
                    )
                )

                ratio = max(
                    0.0,
                    min(1.0, ratio),
                )

                # A confirmed/reproduced vulnerability
                # receives up to a 25% increase.
                reproducibility = (
                    1.0
                    + (0.25 * ratio)
                )

            raw_score += (
                weight
                * confidence
                * reproducibility
            )

        # -----------------------------------------------------
        # Normalize against the maximum possible vulnerability
        # weight for the number of tests.
        #
        # We deliberately use a stronger vulnerability-density
        # factor so that a small number of severe findings is not
        # diluted by dozens of blocked tests.
        # -----------------------------------------------------

        if vulnerable:

            maximum_per_finding = 40.0

            maximum = (
                max(
                    len(vulnerable),
                    1,
                )
                * maximum_per_finding
            )

            base_score = (
                raw_score / maximum
            ) * 100

            # Vulnerability density:
            # how much of the tested attack surface failed.
            vulnerability_density = (
                len(vulnerable)
                / total_tests
            )

            # Scale the score according to actual findings.
            #
            # This prevents 56 mostly-blocked tests from
            # artificially making serious findings look harmless.
            density_factor = (
                0.65
                + min(
                    vulnerability_density * 2.5,
                    0.35,
                )
            )

            risk_score = (
                base_score
                * density_factor
            )

            # -------------------------------------------------
            # Severity floor
            # -------------------------------------------------

            severities = [
                finding.get(
                    "severity",
                    "Medium",
                )
                for finding in vulnerable
            ]

            if "Critical" in severities:
                risk_score = max(
                    risk_score,
                    70,
                )

            elif "High" in severities:
                risk_score = max(
                    risk_score,
                    50,
                )

            elif "Medium" in severities:
                risk_score = max(
                    risk_score,
                    25,
                )

        else:
            risk_score = 0.0

        risk_score = round(
            min(
                100,
                max(
                    0,
                    risk_score,
                ),
            ),
            2,
        )

        # -----------------------------------------------------
        # Risk rating
        # -----------------------------------------------------

        if risk_score >= 75:
            rating = "CRITICAL"

        elif risk_score >= 50:
            rating = "HIGH"

        elif risk_score >= 25:
            rating = "MEDIUM"

        elif risk_score > 0:
            rating = "LOW"

        else:
            rating = "SECURE"

        # -----------------------------------------------------
        # Severity counts
        # -----------------------------------------------------

        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }

        for finding in vulnerable:

            severity = finding.get(
                "severity",
                "Medium",
            )

            if severity in severity_counts:
                severity_counts[severity] += 1

        # -----------------------------------------------------
        # Adaptive statistics
        # -----------------------------------------------------

        adaptive_confirmed = sum(
            1
            for finding in vulnerable
            if finding.get(
                "adaptive_confirmed",
                False,
            )
        )

        adaptive_test_count = sum(
            finding.get(
                "adaptive_verification",
                {}
            ).get(
                "verification_count",
                0,
            )
            for finding in findings
        )

        return {
            "score": risk_score,
            "rating": rating,

            "total_tests": total_tests,

            "vulnerable": len(vulnerable),
            "blocked": len(blocked),
            "review": len(review),

            "severity_counts": severity_counts,

            "adaptive_confirmed": adaptive_confirmed,
            "adaptive_tests": adaptive_test_count,
        }

    @classmethod
    def sort_findings(cls, findings):
        return sorted(
            findings,
            key=lambda item: (
                cls.SEVERITY_ORDER.get(
                    item.get(
                        "severity",
                        "Low",
                    ),
                    1,
                ),
                float(
                    item.get(
                        "confidence",
                        0,
                    )
                ),
            ),
            reverse=True,
        )