"""Prompt templates. The deterministic compliance engine's verdict is
always included as fact the model must not contradict -- the LLM explains
and recommends, it never re-adjudicates compliance (spec section 17, 24)."""
from __future__ import annotations

SYSTEM_PROMPT = (
    "You are a network security compliance assistant embedded in an audit platform. "
    "You explain findings and suggest remediation for network device configurations. "
    "You NEVER invent vendor commands you are not confident are correct for the stated "
    "vendor/platform/version. You NEVER change or contradict the compliance verdict you "
    "are given -- it is authoritative and produced by a separate deterministic engine. "
    "If you are not confident about a specific command, say so explicitly instead of guessing."
)


def finding_explanation_prompt(*, finding: dict, vendor: str, platform: str, rag_context: str) -> str:
    return f"""A deterministic compliance engine produced this finding. Explain it and recommend
remediation. Do not contradict the status or severity below.

Finding:
- Control: {finding.get('title')}
- Status: {finding.get('status')}
- Severity: {finding.get('severity')}
- Description: {finding.get('description')}
- Evidence: {finding.get('evidence')}

Device:
- Vendor: {vendor}
- Platform: {platform}

Relevant knowledge base context:
{rag_context or '(none retrieved)'}

Respond with two short sections: "Why it matters" and "Recommended remediation".
If you provide a vendor command, prefix it with the exact vendor/platform it applies to,
and say "not confident" instead of inventing one you are unsure about.
"""


def risk_summary_prompt(*, risk_score: float, risk_level: str, risk_factors: dict, top_findings: list[dict]) -> str:
    factors_lines = "\n".join(
        f"- {name.replace('_', ' ')}: score {info.get('score')} (weight {info.get('weight')})"
        for name, info in risk_factors.items()
    )
    findings_lines = "\n".join(
        f"- [{f.get('severity')}] {f.get('title')}: {f.get('description')}" for f in top_findings
    ) or "(no findings recorded)"

    return f"""A deterministic risk engine produced this score for a network device. Do not
contradict the score, level, or factor breakdown below -- explain it and recommend
priorities.

Overall risk score: {risk_score}/100 ({risk_level})

Risk factor breakdown:
{factors_lines}

Top contributing findings:
{findings_lines}

Respond with exactly three short sections, each starting with its heading on its own line:
"Problem" (what is actually wrong here, in plain language)
"Why it matters" (the realistic impact if left unaddressed)
"Recommended priorities" (an ordered list of what to fix first and why, referencing the
findings/factors above -- do not invent findings that were not given to you)"""


def optimizer_summary_prompt(*, strategies: dict, findings_by_id: dict) -> str:
    aco = strategies.get("aco") or next(iter(strategies.values()), {})
    sequence_lines = "\n".join(
        f"{i + 1}. [{findings_by_id.get(fid, {}).get('severity', '?')}] {findings_by_id.get(fid, {}).get('title', fid)}"
        for i, fid in enumerate(aco.get("sequence", []))
    ) or "(no remediation sequence)"
    strategy_lines = "\n".join(
        f"- {name}: residual risk {m.get('residual_risk')}, risk reduced {m.get('risk_reduction_percent')}%, "
        f"operational cost {m.get('operational_cost')}, attack paths removed {m.get('attack_paths_removed')}/{m.get('total_potential_paths')}"
        for name, m in strategies.items()
    )

    return f"""An Ant Colony Optimization (ACO) engine computed the best order to remediate a
set of security findings, and compared it against two baseline strategies. Do not
contradict the numeric metrics below -- explain what they mean and what to do next.

Strategy comparison:
{strategy_lines}

Recommended (ACO) remediation order:
{sequence_lines}

Respond with exactly three short sections, each starting with its heading on its own line:
"Problem" (what security gap this remediation sequence is closing, in plain language)
"Why this order" (why ACO's sequence beats the baselines, in terms of the metrics above)
"Suggested next step" (a concrete, practical recommendation for the team to act on first)"""


def unknown_syntax_prompt(*, raw_line: str, vendor: str) -> str:
    return f"""A configuration parser for vendor "{vendor}" encountered a line it does not
recognize:

    {raw_line}

Classify it into a security category (e.g. "Administrative Session Timeout",
"Logging", "Authentication", "Access Control", "Other/Unknown") and briefly explain
what the line likely controls. Respond as JSON with keys: category, meaning, confidence
(0.0-1.0, your genuine confidence, not always high)."""
