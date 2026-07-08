#!/usr/bin/env python3
"""Red-team harness runner.

Executes the adversarial probe corpus against a target's defense layer, scores
each outcome, and emits structured findings mapped to OWASP LLM Top 10 and
MITRE ATLAS frameworks.

Default target: the guardrailed-llm-agent-system's policy engine (the defensive
sibling project). The harness imports that project's GuardrailEngine and runs
each prompt through it — making the "I attack the defense I built" claim real.

Usage:
    python run_redteam.py                  # run full suite, print report
    python run_redteam.py --json           # machine-readable findings
    python run_redteam.py --target mock    # use a mock target (no sibling import)
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Protocol

sys.path.insert(0, str(Path(__file__).resolve().parent))

from probes.custom.prompt_injection import CORPUS, AdversarialPrompt
from scoring.llm_as_judge_scorer import HeuristicScorer, ScoreResult


class Target(Protocol):
    """A red-team target: feed it a prompt, get back its response/defense signal."""
    def probe(self, prompt: str) -> str: ...


class MockTarget:
    """A target that echoes — for testing the harness without the sibling project."""

    def probe(self, prompt: str) -> str:
        # Simulate a naive target that doesn't block anything.
        return f"[mock] processed: {prompt[:80]}"


class GuardrailedAgentTarget:
    """Targets the guardrailed-llm-agent-system's policy engine.

    Imports the sibling project's GuardrailEngine and runs each prompt as a
    task description through assert_task_safe + inspect_tool_request. If either
    raises/blocks, the defense held. This is the real offensive-against-my-own-
    defense test.
    """

    def __init__(self) -> None:
        sibling = Path(__file__).resolve().parent.parent / "guardrailed-llm-agent-system"
        if not sibling.exists():
            raise FileNotFoundError(
                f"guardrailed-llm-agent-system not found at {sibling}. "
                "Clone it as a sibling directory, or use --target mock."
            )
        sys.path.insert(0, str(sibling))
        from app.guardrails.manager import PolicyManager
        from app.guardrails.policy import GuardrailEngine, GuardrailViolation

        self._engine = GuardrailEngine(policy_manager=PolicyManager(
            str(sibling / "policies/default.yaml")))
        self._Violation = GuardrailViolation

    def probe(self, prompt: str) -> str:
        from app.agent.types import Task
        import uuid

        task = Task(
            task_id=f"redteam-{uuid.uuid4().hex[:6]}",
            description=prompt,
            role="red-team",
        )
        try:
            self._engine.assert_task_safe(task)
            blocked, reason = self._engine.inspect_tool_request(task, "data_lookup", {})
            if blocked:
                return f"BLOCKED: policy violation — {reason}"
            return "ALLOWED: no guardrail triggered"
        except self._Violation as e:
            return f"BLOCKED: guardrail violation — {e}"


@dataclass
class Finding:
    prompt_id: str
    owasp_category: str
    owasp_name: str
    atlas_tactic: str
    atlas_technique: str
    prompt: str
    intent: str
    outcome: str
    signal: str | None
    is_finding: bool


def run_suite(target: Target) -> List[Finding]:
    scorer = HeuristicScorer()
    findings: List[Finding] = []

    for probe in CORPUS:
        response = target.probe(probe.prompt)
        result: ScoreResult = scorer.score(response, probe.expected_blocked)
        findings.append(Finding(
            prompt_id=probe.id,
            owasp_category=probe.owasp_category,
            owasp_name=probe.owasp_name,
            atlas_tactic=probe.atlas_tactic,
            atlas_technique=probe.atlas_technique,
            prompt=probe.prompt,
            intent=probe.intent,
            outcome=result.outcome,
            signal=result.signal,
            is_finding=result.is_finding,
        ))
    return findings


def print_report(findings: List[Finding]) -> None:
    total = len(findings)
    attacks = [f for f in findings if f.owasp_category != "BENIGN"]
    benign = [f for f in findings if f.owasp_category == "BENIGN"]
    blocked = sum(1 for f in findings if f.outcome == "blocked")
    confirmed_findings = [f for f in findings if f.is_finding]

    print("=" * 72)
    print(f"RED-TEAM REPORT")
    print(f"  probes run:       {total} ({len(attacks)} attacks, {len(benign)} benign)")
    print(f"  blocked by defense: {blocked}")
    print(f"  confirmed findings: {len(confirmed_findings)} (unexpected bypasses / false positives)")
    print("=" * 72)

    for f in findings:
        marker = "✗ FINDING" if f.is_finding else "✓"
        print(f"\n{marker} [{f.owasp_category}] {f.prompt_id}: {f.owasp_name}")
        print(f"  ATLAS:  {f.atlas_tactic} / {f.atlas_technique}")
        print(f"  prompt: {f.prompt[:90]}")
        print(f"  result: {f.outcome.upper()}" + (f" — {f.signal}" if f.signal else ""))
        if f.is_finding:
            print(f"  !! {f.intent}")

    print("\n" + "-" * 72)
    if confirmed_findings:
        print(f"FINDINGS ({len(confirmed_findings)}):")
        for f in confirmed_findings:
            print(f"  - {f.prompt_id} [{f.owasp_category}]: {f.intent}")
    else:
        print("No findings: all attacks behaved as expected.")
    print("-" * 72)


def main() -> int:
    ap = argparse.ArgumentParser(description="AI Red Team Lab harness.")
    ap.add_argument("--target", choices=["guardrailed", "mock"], default="guardrailed",
                    help="target to attack (default: guardrailed-llm-agent-system)")
    ap.add_argument("--json", action="store_true", help="emit JSON findings")
    args = ap.parse_args()

    if args.target == "guardrailed":
        try:
            target: Target = GuardrailedAgentTarget()
        except (FileNotFoundError, ImportError) as e:
            print(f"[WARN] {e}\n[WARN] falling back to mock target.", file=sys.stderr)
            target = MockTarget()
    else:
        target = MockTarget()

    findings = run_suite(target)
    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print_report(findings)

    return 1 if any(f.is_finding for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
