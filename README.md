# AI Red Team Lab

An offensive AI security lab for running adversarial probes against LLM targets, mapping findings to standard frameworks, and publishing structured vulnerability reports. Built to demonstrate **demonstrated adversarial experience** — converting portfolio work into verifiable, taxonomy-aligned red-team findings.

## Purpose

This lab operationalizes the methodology described in Microsoft's *Lessons From Red Teaming 100 Generative AI Products* (Jan 2025) and the PyRIT framework. It is the offensive counterpart to my defensive projects:

- **[guardrailed-llm-agent-system](https://github.com/zaratr/guardrailed-llm-agent-system)** — the NeMo Guardrails defenses I both build and break here.
- **[AI-Observability-Monitoring-Service](https://github.com/zaratr/AI-Observability-Monitoring-Service)** — the LLM-as-a-Judge scorer used here to determine whether adversarial inputs succeeded.
- **[Zero-Trust-LLM-Access-Layer](https://github.com/zaratr/Zero-Trust-LLM-Access-Layer)** — a red-team target (the AI Security Gateway) I attack to find injection/sanitization failures.

## What it demonstrates

- Hands-on **Garak** and **PyRIT** against local LLM targets (Ollama/Gemma)
- **MITRE ATLAS** tactic/technique mapping for every finding
- **OWASP Top 10 for LLM Applications (2025)** category alignment (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses)
- Structured vulnerability reports (per target)
- CI-integrated red-teaming — scans run on push, findings published automatically

## Repository structure

```
ai-red-team-lab/
├── README.md                    # methodology + findings index
├── targets/
│   ├── local_models/            # Ollama/Gemma target configs
│   └── guardrailed_agent/       # the guardrailed-llm-agent-system as a target
├── probes/
│   ├── garak_scans/             # garak probe configs + results
│   ├── pyrit_attacks/           # PyRIT attack datasets (prompt injection, jailbreak)
│   └── custom/                  # hand-crafted adversarial prompts
├── scoring/
│   └── llm_as_judge_scorer.py   # uses LLM-as-a-Judge as the success scorer
├── findings/
│   ├── ATLAS_mapping.md         # each finding → MITRE ATLAS tactic/technique
│   ├── OWASP_LLM_mapping.md     # each finding → OWASP LLM Top 10 category
│   └── reports/                 # structured vulnerability reports (per target)
└── .github/workflows/
    └── redteam.yml              # CI runs scans on push → publishes findings
```

## Methodology

1. **Target selection** — local Ollama models (Gemma) and my own guardrailed agent (the defense I built, now the offense target).
2. **Probe execution** — run Garak vulnerability scans and PyRIT attack datasets; supplement with hand-crafted adversarial prompts (prompt injection, jailbreak, multi-turn manipulation).
3. **Success scoring** — LLM-as-a-Judge determines whether an adversarial input bypassed the target's guardrails or policy.
4. **Framework mapping** — each confirmed finding is mapped to MITRE ATLAS tactics/techniques and OWASP LLM Top 10 categories.
5. **Structured reporting** — findings documented in standardized vulnerability reports (target, attack vector, OWASP/ATLAS category, severity, recommended mitigation).

## Frameworks referenced

- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial Threat Landscape for AI Systems
- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) — MEASURE function
- [Garak](https://docs.nvidia.com/nemo/guardrails/evaluation/llm-vulnerability-scanning) — NVIDIA's LLM vulnerability scanner
- [PyRIT](https://github.com/Azure/PyRIT) — Microsoft's Python Risk Identification Toolkit

## Status

Work in progress — probe configs, initial findings, and CI workflow added incrementally.
