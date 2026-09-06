from typing import Any, Dict, List, Optional

from backend.engine.tester import PromptInjectionTester


class RetestEngine:
    """
    Attack -> Fix -> Retest comparison engine.

    Runs the same security assessment pipeline again and
    compares the new results with a previous baseline scan.
    """

    def __init__(
        self,
        provider="generic",
        endpoint=None,
        model=None,
        headers=None,
        api_key=None,
        suite=None,
    ):
        self.provider = provider
        self.endpoint = endpoint
        self.model = model
        self.headers = headers
        self.api_key = api_key
        self.suite = suite

        self.tester = PromptInjectionTester(
            provider=provider,
            endpoint=endpoint,
            model=model,
            headers=headers,
            api_key=api_key,
            suite=suite or "smoke",
        )

    # =========================================================
    # COMPLETE RETEST
    # =========================================================

    def run_retest(self, baseline: Dict[str, Any]):
        if not isinstance(baseline, dict):
            raise ValueError("Baseline scan must be a JSON object.")

        baseline_results = baseline.get("results", [])

        if not isinstance(baseline_results, list):
            raise ValueError(
                "Baseline scan results must be a JSON list."
            )

        # Inherit the exact test suite from baseline scan if available
        baseline_suite = baseline.get("target", {}).get("suite")
        if baseline_suite and not self.suite:
            self.tester.suite = baseline_suite
            self.tester.attacks = self.tester._filter_attacks(
                self.tester._load_attacks(),
                baseline_suite,
                self.tester.categories,
            )

        # Run the exact same scanner again.
        current_scan = self.tester.run_scan()

        comparison = self._compare_results(
            baseline_results,
            current_scan.get("results", []),
        )

        improvement = self._calculate_improvement(
            baseline.get("summary", {}),
            current_scan.get("summary", {}),
            comparison,
        )

        return {
            "status": "completed",

            "target": current_scan.get("target", {}),

            "before": {
                "summary": baseline.get("summary", {}),
                "adaptive": baseline.get("adaptive", {}),
            },

            "after": {
                "summary": current_scan.get("summary", {}),
                "adaptive": current_scan.get("adaptive", {}),
            },

            "comparison": comparison,

            "improvement": improvement,

            # Keep complete current results so the dashboard
            # can display the new security state.
            "results": current_scan.get("results", []),

            "findings": current_scan.get("findings", []),
        }

    # =========================================================
    # RESULT COMPARISON
    # =========================================================

    @staticmethod
    def _compare_results(
        baseline_results: List[Dict[str, Any]],
        current_results: List[Dict[str, Any]],
    ):
        before = {
            item.get("id"): item
            for item in baseline_results
            if item.get("id")
        }

        after = {
            item.get("id"): item
            for item in current_results
            if item.get("id")
        }

        fixed = []
        still_vulnerable = []
        reviewed = []
        regressions = []
        unchanged_safe = []

        all_ids = sorted(
            set(before.keys()) | set(after.keys())
        )

        for attack_id in all_ids:
            old = before.get(attack_id)
            new = after.get(attack_id)

            if not old or not new:
                continue

            old_verdict = old.get(
                "verdict",
                "REVIEW",
            )

            new_verdict = new.get(
                "verdict",
                "REVIEW",
            )

            item = {
                "id": attack_id,
                "title": new.get(
                    "title",
                    old.get("title", attack_id),
                ),
                "category": new.get(
                    "category",
                    old.get("category", ""),
                ),
                "severity": new.get(
                    "severity",
                    old.get("severity", "Medium"),
                ),
                "before_verdict": old_verdict,
                "after_verdict": new_verdict,
                "before_confidence": old.get(
                    "confidence",
                    0,
                ),
                "after_confidence": new.get(
                    "confidence",
                    0,
                ),
            }

            # -------------------------------------------------
            # Vulnerable -> Blocked
            # -------------------------------------------------

            if (
                old_verdict == "VULNERABLE"
                and new_verdict == "BLOCKED"
            ):
                item["status"] = "FIXED"
                fixed.append(item)

            # -------------------------------------------------
            # Vulnerable -> Still vulnerable
            # -------------------------------------------------

            elif (
                old_verdict == "VULNERABLE"
                and new_verdict == "VULNERABLE"
            ):
                item["status"] = "STILL_VULNERABLE"
                still_vulnerable.append(item)

            # -------------------------------------------------
            # Vulnerable -> Review/Error
            # -------------------------------------------------

            elif (
                old_verdict == "VULNERABLE"
                and new_verdict in (
                    "REVIEW",
                    "ERROR",
                )
            ):
                item["status"] = "REVIEW"
                reviewed.append(item)

            # -------------------------------------------------
            # Safe -> Vulnerable
            # -------------------------------------------------

            elif (
                old_verdict in (
                    "BLOCKED",
                    "REVIEW",
                    "ERROR",
                )
                and new_verdict == "VULNERABLE"
            ):
                item["status"] = "REGRESSION"
                regressions.append(item)

            # -------------------------------------------------
            # Everything else
            # -------------------------------------------------

            else:
                item["status"] = "UNCHANGED_SAFE"
                unchanged_safe.append(item)

        return {
            "total_compared": len(all_ids),

            "fixed": fixed,
            "fixed_count": len(fixed),

            "still_vulnerable": still_vulnerable,
            "still_vulnerable_count": len(
                still_vulnerable
            ),

            "reviewed": reviewed,
            "review_count": len(reviewed),

            "regressions": regressions,
            "regression_count": len(regressions),

            "unchanged_safe": unchanged_safe,
            "unchanged_safe_count": len(
                unchanged_safe
            ),
        }

    # =========================================================
    # SECURITY IMPROVEMENT
    # =========================================================

    @staticmethod
    def _calculate_improvement(
        before_summary: Dict[str, Any],
        after_summary: Dict[str, Any],
        comparison: Dict[str, Any],
    ):
        before_score = RetestEngine._number(
            before_summary.get("score")
        )

        after_score = RetestEngine._number(
            after_summary.get("score")
        )

        score_delta = round(
            after_score - before_score,
            2,
        )

        # Positive means security improved.
        risk_reduction = round(
            before_score - after_score,
            2,
        )

        if before_score > 0:
            risk_reduction_percent = round(
                (
                    (before_score - after_score)
                    / before_score
                )
                * 100,
                2,
            )
        else:
            risk_reduction_percent = 0.0

        before_findings = RetestEngine._number(
            before_summary.get("findings")
        )

        after_findings = RetestEngine._number(
            after_summary.get("findings")
        )

        finding_reduction = (
            before_findings - after_findings
        )

        if risk_reduction > 0:
            security_status = "IMPROVED"
        elif risk_reduction < 0:
            security_status = "DEGRADED"
        else:
            security_status = "UNCHANGED"

        if comparison.get("regression_count", 0) > 0:
            security_status = "REGRESSION_DETECTED"

        return {
            "security_status": security_status,

            "before_score": before_score,
            "after_score": after_score,

            "score_delta": score_delta,
            "risk_reduction": risk_reduction,
            "risk_reduction_percent": (
                risk_reduction_percent
            ),

            "before_findings": before_findings,
            "after_findings": after_findings,
            "finding_reduction": finding_reduction,

            "fixed": comparison.get(
                "fixed_count",
                0,
            ),

            "remaining": comparison.get(
                "still_vulnerable_count",
                0,
            ),

            "review_required": comparison.get(
                "review_count",
                0,
            ),

            "regressions": comparison.get(
                "regression_count",
                0,
            ),
        }

    # =========================================================
    # HELPERS
    # =========================================================

    @staticmethod
    def _number(value: Optional[Any]) -> float:
        try:
            return float(value or 0)
        except (
            TypeError,
            ValueError,
        ):
            return 0.0