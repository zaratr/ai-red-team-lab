# MITRE ATLAS — Tactic/Technique Mappings

Each probe maps to MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
tactics and techniques. This grounds the red-team findings in a recognized
adversarial-AI taxonomy rather than ad-hoc categories.

## Tactic coverage

| ATLAS Tactic | Probes | Description |
|---|---|---|
| Defense Evasion (TA0005) | PI-001, PI-002, PI-003 | Evading the target's guardrail/policy layer |
| Collection (TA0009) | SID-001, SID-002, SPL-001 | Gathering sensitive data from the model |
| Execution (TA0002) | IOH-001, EA-001, EA-002 | Achieving unauthorized action via the model |

## Technique detail

| Probe | ATLAS Technique | ID |
|---|---|---|
| PI-001/002 | ML Prompt Injection | AML.T0051 |
| PI-003 | Crafting Adversarial Data | AML.T0020 |
| SID-001/002 | Information Discovery | AML.T0044 |
| IOH-001 | Crafting Adversarial Data | AML.T0020 |
| EA-001 | Valid Accounts (abuse of implied role) | AML.T0078 |
| EA-002 | Command and Scripting Interpreter | AML.T0056 |
| SPL-001 | Information Discovery | AML.T0044 |

## References

- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial Threat Landscape for AI Systems
- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) — MEASURE function

## Methodology alignment

This mapping follows the methodology described in Microsoft's *Lessons From Red
Teaming 100 Generative AI Products* (Jan 2025): every finding is categorized by
both the attacker's tactic (ATLAS) and the application-layer weakness (OWASP).
