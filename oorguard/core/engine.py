"""Scan engine — orchestrates check execution with concurrency and error isolation.

The engine discovers registered checks, filters by config, runs them in a
ThreadPoolExecutor for I/O-bound performance, catches per-check exceptions
(so one failing check never crashes the whole scan), and aggregates results.
"""

from __future__ import annotations

import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity, sort_findings
from oorguard.core.registry import CheckInfo, get_all_checks


# Callback type for progress reporting: (check_name, status, elapsed_seconds)
ProgressCallback = Callable[[str, str, float], None] | None


class ScanEngine:
    """Orchestrates the execution of all registered security checks.

    Attributes:
        ctx: The shared ScanContext for this scan run.
        max_workers: Thread pool size (default: 8).
        on_progress: Optional callback for progress updates.
    """

    def __init__(
        self,
        ctx: ScanContext,
        max_workers: int = 8,
        on_progress: ProgressCallback = None,
    ) -> None:
        self.ctx = ctx
        self.max_workers = max_workers
        self.on_progress = on_progress

    def run(self) -> list[Finding]:
        """Execute all applicable checks and return aggregated findings."""
        checks = self._filter_checks(get_all_checks())

        if not checks:
            return [
                Finding(
                    severity=Severity.INFO,
                    category="Engine",
                    title="No checks to run",
                    description="All checks were disabled or excluded by configuration.",
                    recommendation="Review your .oorguard.yml or CLI flags.",
                )
            ]

        all_findings: list[Finding] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_check = {
                pool.submit(self._run_single_check, check): check
                for check in checks
            }
            for future in as_completed(future_to_check):
                check = future_to_check[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as exc:
                    # Should not happen since _run_single_check catches everything,
                    # but defense in depth
                    all_findings.append(
                        Finding(
                            severity=Severity.INFO,
                            category=check.category,
                            title=f"Check '{check.name}' failed unexpectedly",
                            description=str(exc),
                            recommendation="This is an internal error. Please report it.",
                        )
                    )

        return sort_findings(all_findings)

    def _run_single_check(self, check: CheckInfo) -> list[Finding]:
        """Run a single check with error isolation and progress reporting."""
        start = time.monotonic()
        self._report_progress(check.name, "running", 0.0)

        try:
            findings = check.func(self.ctx)
            elapsed = time.monotonic() - start
            self._report_progress(check.name, "done", elapsed)
            return findings
        except Exception as exc:
            elapsed = time.monotonic() - start
            self._report_progress(check.name, "error", elapsed)
            return [
                Finding(
                    severity=Severity.INFO,
                    category=check.category,
                    title=f"Check '{check.name}' encountered an error",
                    description=(
                        f"{type(exc).__name__}: {exc}\n"
                        f"{traceback.format_exc()}"
                    ),
                    recommendation=(
                        "This check could not complete. The error has been logged. "
                        "Ensure the project path is correct and accessible."
                    ),
                )
            ]

    def _filter_checks(self, checks: list[CheckInfo]) -> list[CheckInfo]:
        """Filter checks based on config: disabled checks, excluded categories."""
        disabled = self.ctx.config.disabled_checks
        excluded_cats = self.ctx.config.exclude_categories

        return [
            c for c in checks
            if c.name not in disabled and c.category not in excluded_cats
        ]

    def _report_progress(self, check_name: str, status: str, elapsed: float) -> None:
        """Invoke the progress callback if one is set."""
        if self.on_progress:
            self.on_progress(check_name, status, elapsed)
