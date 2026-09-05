import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from backend.config import Config
from backend.engine.ai_security import AISecurityJudge
from backend.engine.detector import SecurityDetector
from backend.engine.executor import AIExecutor
from backend.engine.scorer import RiskScorer


class PromptInjectionTester:
    """
    Main security assessment engine.

    Pipeline:

        Benchmark
            ↓
        Target execution
            ↓
        Deterministic detector
            ↓
        Independent AI judge
            ↓
        Normalized finding
            ↓
        Risk scoring
    """

    def __init__(
        self,
        provider="generic",
        endpoint=None,
        model=None,
        headers=None,
        api_key=None,
    ):
        self.provider = provider
        self.endpoint = endpoint
        self.model = model
        self.headers = headers or {}
        self.api_key = api_key

        self.attacks = self._load_attacks()

        self.executor = AIExecutor(
            provider=provider,
            endpoint=endpoint,
            model=model,
            headers=headers,
            api_key=api_key,
        )

        self.judge = AISecurityJudge(
            provider=Config.AI_PROVIDER,
            model=Config.AI_MODEL,
            base_url=Config.AI_BASE_URL,
        )

    # =========================================================
    # LOAD BENCHMARK
    # =========================================================

    @staticmethod
    def _load_attacks():
        path = (
            Path(__file__).resolve().parent.parent
            / "attacks"
            / "attacks.json"
        )

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:
            attacks = json.load(file)

        if not isinstance(attacks, list):
            raise ValueError(
                "attacks.json must contain a JSON list."
            )

        return attacks

    # =========================================================
    # RUN COMPLETE SCAN
    # =========================================================

    def run_scan(self):
        results = []

        max_workers = min(
            Config.MAX_CONCURRENT_TESTS,
            max(len(self.attacks), 1),
        )

        with ThreadPoolExecutor(
            max_workers=max_workers
        ) as pool:

            futures = {
                pool.submit(
                    self._run_single_attack,
                    attack,
                ): attack
                for attack in self.attacks
            }

            for future in as_completed(futures):
                attack = futures[future]

                try:
                    result = future.result()

                except Exception as exc:
                    result = self._error_result(
                        attack,
                        str(exc),
                    )

                results.append(result)

        results.sort(
            key=lambda item: item.get(
                "id",
                ""
            )
        )

        findings = [
            result
            for result in results
            if result.get("verdict") == "VULNERABLE"
        ]

        score = RiskScorer.calculate(
            results,
            total_tests=len(results),
        )

        score["findings"] = len(findings)

        return {
            "status": "completed",
            "target": {
                "provider": self.provider,
                "endpoint": self._safe_endpoint(),
                "model": self.model,
            },
            "summary": score,
            "results": results,
            "findings": RiskScorer.sort_findings(
                findings
            ),
        }

    # =========================================================
    # SINGLE ATTACK
    # =========================================================

    def _run_single_attack(self, attack):
        prompt = attack.get(
            "prompt",
            "",
        )

        execution = self.executor.execute(
            prompt
        )

        if not execution.success:
            return {
                "id": attack.get("id"),
                "title": attack.get("title"),
                "category": attack.get("category"),
                "severity": attack.get(
                    "severity",
                    "Medium",
                ),
                "technique": attack.get(
                    "technique",
                    "",
                ),
                "verdict": "ERROR",
                "confidence": 1.0,
                "evidence": [
                    execution.error
                    or "Target execution failed."
                ],
                "signals": [
                    "EXECUTION_ERROR"
                ],
                "latency_ms": execution.latency_ms,
            }

        detector_result = SecurityDetector.analyze(
            execution.response,
            attack=attack,
        )

        judge_result = self.judge.analyze(
            attack=attack,
            target_response=execution.response,
            detector_result=detector_result,
        )

        return self._build_result(
            attack,
            execution,
            detector_result,
            judge_result,
        )

    # =========================================================
    # RESULT NORMALIZATION
    # =========================================================

    @staticmethod
    def _build_result(
        attack,
        execution,
        detector_result,
        judge_result,
    ):
        detector_verdict = detector_result.get(
            "verdict",
            "REVIEW",
        )

        judge_verdict = judge_result.get(
            "verdict",
            "REVIEW",
        )

        # The independent judge gets priority when available.
        if judge_result.get("judge") == "AI Security Judge":
            verdict = judge_verdict
        else:
            verdict = detector_verdict

        confidence = float(
            judge_result.get(
                "confidence",
                detector_result.get(
                    "confidence",
                    0.5,
                ),
            )
        )

        defects = judge_result.get(
            "defects",
            [],
        )

        if isinstance(defects, str):
            defects = [defects]

        evidence = detector_result.get(
            "evidence",
            [],
        )

        return {
            "id": attack.get("id"),
            "title": attack.get("title"),
            "category": attack.get("category"),
            "severity": attack.get(
                "severity",
                "Medium",
            ),
            "technique": attack.get(
                "technique",
                "",
            ),
            "verdict": verdict,
            "confidence": confidence,
            "defects": defects,
            "root_cause": judge_result.get(
                "root_cause",
                "",
            ),
            "impact": judge_result.get(
                "impact",
                "",
            ),
            "developer_mitigations": judge_result.get(
                "developer_mitigations",
                [],
            ),
            "evidence": evidence,
            "signals": detector_result.get(
                "signals",
                [],
            ),
            "latency_ms": execution.latency_ms,
            "judge": judge_result.get(
                "judge",
                "Unknown",
            ),
        }

    # =========================================================
    # ERROR RESULT
    # =========================================================

    @staticmethod
    def _error_result(
        attack,
        error,
    ):
        return {
            "id": attack.get("id"),
            "title": attack.get("title"),
            "category": attack.get("category"),
            "severity": attack.get(
                "severity",
                "Medium",
            ),
            "technique": attack.get(
                "technique",
                "",
            ),
            "verdict": "ERROR",
            "confidence": 1.0,
            "defects": [],
            "root_cause": "",
            "impact": "",
            "developer_mitigations": [],
            "evidence": [error],
            "signals": [
                "ENGINE_ERROR"
            ],
            "latency_ms": 0,
            "judge": "Engine",
        }

    def _safe_endpoint(self):
        """
        Prevent credentials embedded in URLs from appearing
        in reports.
        """

        if not self.endpoint:
            return None

        endpoint = str(self.endpoint)

        if "@" in endpoint and "://" in endpoint:
            scheme, remainder = endpoint.split(
                "://",
                1,
            )

            if "@" in remainder:
                remainder = remainder.split(
                    "@",
                    1,
                )[1]

            return f"{scheme}://{remainder}"

        return endpoint