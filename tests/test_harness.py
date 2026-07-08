"""Tests for the AI Red Team Lab harness.

Verifies the corpus, scorer, and harness runner work correctly without the
sibling guardrailed-llm-agent-system (uses the mock target). These run anywhere
Python runs — no model, no sibling clone required.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_corpus_has_expected_categories():
    """The corpus must cover the OWASP categories the README claims."""
    from probes.custom.prompt_injection import CORPUS
    categories = {p.owasp_category for p in CORPUS}
    assert "LLM01" in categories  # Prompt Injection
    assert "LLM02" in categories  # Sensitive Info Disclosure
    assert "LLM06" in categories  # Excessive Agency
    assert "BENIGN" in categories  # control


def test_corpus_every_probe_has_atlas_mapping():
    """Every attack probe must map to a MITRE ATLAS tactic/technique."""
    from probes.custom.prompt_injection import CORPUS
    attacks = [p for p in CORPUS if p.owasp_category != "BENIGN"]
    for p in attacks:
        assert p.atlas_tactic, f"{p.id} missing ATLAS tactic"
        assert p.atlas_technique, f"{p.id} missing ATLAS technique"


def test_scorer_flags_unexpected_bypass():
    """An attack the defense should block but didn't → is_finding=True."""
    from scoring.llm_as_judge_scorer import HeuristicScorer
    scorer = HeuristicScorer()
    result = scorer.score("ALLOWED: no guardrail triggered", expected_blocked=True)
    assert result.outcome == "allowed"
    assert result.is_finding is True


def test_scorer_confirms_blocked_attack():
    """An attack the defense blocked → not a finding (defense held)."""
    from scoring.llm_as_judge_scorer import HeuristicScorer
    scorer = HeuristicScorer()
    result = scorer.score("BLOCKED: guardrail violation — PII", expected_blocked=True)
    assert result.outcome == "blocked"
    assert result.is_finding is False


def test_scorer_flags_benign_false_positive():
    """A benign request that got blocked → is_finding=True (false positive)."""
    from scoring.llm_as_judge_scorer import HeuristicScorer
    scorer = HeuristicScorer()
    result = scorer.score("BLOCKED: policy violation", expected_blocked=False)
    assert result.outcome == "blocked"
    assert result.is_finding is True


def test_harness_runs_against_mock_target():
    """The full harness must run end-to-end against the mock target."""
    from run_redteam import run_suite, MockTarget
    findings = run_suite(MockTarget())
    assert len(findings) > 0
    # The mock target blocks nothing, so all expected-blocked attacks are findings.
    attack_findings = [f for f in findings if f.owasp_category != "BENIGN" and f.is_finding]
    assert len(attack_findings) > 0, "expected findings against the no-block mock"


def test_findings_have_owasp_and_atlas_fields():
    """Every finding must carry both OWASP and ATLAS classifications."""
    from run_redteam import run_suite, MockTarget
    findings = run_suite(MockTarget())
    for f in findings:
        assert f.owasp_category
        assert f.atlas_tactic
        assert f.atlas_technique
