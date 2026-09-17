"""Per-device audit PDF report generation (spec section 49) using ReportLab.

Every section pulls from actual scan/compliance/risk/attack-graph/optimizer/
blockchain data passed in -- nothing here is a static template with
placeholder numbers. Sections the system genuinely could not produce (e.g.
AI recommendations when Ollama isn't connected) say so explicitly rather
than being silently omitted or faked.
"""
from __future__ import annotations

import io
import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Brand palette (matches frontend/src/app/globals.css) -- kept as module
# constants so the report visually matches the app rather than using
# ReportLab's default blues/greys.
_BLACK = colors.HexColor("#171717")
_ORANGE = colors.HexColor("#F25623")
_DARK_GRAY = colors.HexColor("#4D4D4D")
_LIGHT_GRAY = colors.HexColor("#DEDEDE")
_SURFACE = colors.HexColor("#FAFAFA")
_WHITE = colors.white

_STATUS_COLORS = {
    "PASS": colors.HexColor("#16a34a"),
    "FAIL": colors.HexColor("#dc2626"),
    "NOT_APPLICABLE": _DARK_GRAY,
    "INSUFFICIENT_EVIDENCE": colors.HexColor("#d97706"),
    "UNKNOWN": _DARK_GRAY,
}

_SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": _ORANGE,
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": _DARK_GRAY,
}

_LOGO_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "frontend", "public", "brand", "icon.png")
)

_styles = getSampleStyleSheet()
_title = ParagraphStyle("reportTitle", parent=_styles["Heading1"], fontSize=20, textColor=_BLACK, spaceAfter=2)
_h2 = ParagraphStyle(
    "sectionHeading",
    parent=_styles["Heading2"],
    fontSize=13,
    textColor=_BLACK,
    spaceBefore=14,
    spaceAfter=6,
    borderColor=_ORANGE,
)
_body = ParagraphStyle("reportBody", parent=_styles["BodyText"], fontSize=9.5, textColor=_BLACK, leading=14)
_small = ParagraphStyle("reportSmall", parent=_body, fontSize=8.5, textColor=_DARK_GRAY, leading=12)
_meta = ParagraphStyle("reportMeta", parent=_small, fontSize=8, textColor=_DARK_GRAY)


def _section_divider() -> HRFlowable:
    return HRFlowable(width="100%", thickness=1.2, color=_ORANGE, spaceBefore=0, spaceAfter=10)


def _kv_table(rows: list[tuple[str, str]]) -> Table:
    t = Table(rows, colWidths=[2.2 * inch, 4.3 * inch])
    t.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), _DARK_GRAY),
                ("TEXTCOLOR", (1, 0), (1, -1), _BLACK),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, _LIGHT_GRAY),
            ]
        )
    )
    return t


def _stat_cards(cards: list[tuple[str, str, colors.Color]]) -> Table:
    """A row of small labeled stat boxes (compliance score / risk level /
    findings count) -- replaces the old single dense paragraph with
    something scannable at a glance."""
    values = [Paragraph(f"<font color='{v_color.hexval()}'><b>{v}</b></font>", ParagraphStyle("v", fontSize=16)) for _, v, v_color in cards]
    labels = [Paragraph(f"<font color='#4D4D4D'>{label}</font>", _meta) for label, _, _ in cards]
    t = Table([values, labels], colWidths=[2.1 * inch] * len(cards))
    t.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, _LIGHT_GRAY),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, _LIGHT_GRAY),
                ("BACKGROUND", (0, 0), (-1, -1), _SURFACE),
                ("TOPPADDING", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )
    return t


def _status_severity_table(rows: list[list[str]]) -> Table:
    header = ["Control", "Status", "Severity"]
    data = [header] + rows
    t = Table(data, colWidths=[3.3 * inch, 1.7 * inch, 1.5 * inch], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _BLACK),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.4, _LIGHT_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _SURFACE]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, row in enumerate(rows, start=1):
        status_color = _STATUS_COLORS.get(row[1], _BLACK)
        severity_color = _SEVERITY_COLORS.get(row[2], _BLACK)
        style.append(("TEXTCOLOR", (1, i), (1, i), status_color))
        style.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
        style.append(("TEXTCOLOR", (2, i), (2, i), severity_color))
        style.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    return t


def _draw_header_footer(canvas, doc):
    """Runs on every page: a compact logo + report title in the header, and
    page numbers + report id in the footer -- makes a multi-page PDF read as
    one coherent document instead of the earlier bare, brand-less pages."""
    canvas.saveState()
    width, height = letter

    if os.path.exists(_LOGO_PATH):
        canvas.drawImage(
            _LOGO_PATH, 0.6 * inch, height - 0.55 * inch, width=0.22 * inch, height=0.28 * inch,
            preserveAspectRatio=True, mask="auto",
        )
    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(_BLACK)
    canvas.drawString(0.9 * inch, height - 0.45 * inch, "SurakshaSetu")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(_DARK_GRAY)
    canvas.drawRightString(width - 0.6 * inch, height - 0.45 * inch, "Security Compliance Audit Report")
    canvas.setStrokeColor(_LIGHT_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(0.6 * inch, height - 0.6 * inch, width - 0.6 * inch, height - 0.6 * inch)

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(_DARK_GRAY)
    canvas.line(0.6 * inch, 0.55 * inch, width - 0.6 * inch, 0.55 * inch)
    canvas.drawString(0.6 * inch, 0.4 * inch, doc._report_id if hasattr(doc, "_report_id") else "")
    canvas.drawRightString(width - 0.6 * inch, 0.4 * inch, f"Page {doc.page}")
    canvas.restoreState()


def generate_audit_report(
    *, scan: dict, device: dict, compliance: dict, risk: dict, attack_graph: dict, optimizer: dict | None, blockchain: dict,
    report_id: str = "",
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        topMargin=0.85 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
    )
    doc._report_id = report_id
    story = []

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # --- Title block ---
    if os.path.exists(_LOGO_PATH):
        story.append(Image(_LOGO_PATH, width=0.4 * inch, height=0.5 * inch))
        story.append(Spacer(1, 6))
    story.append(Paragraph("Network Security Compliance Audit Report", _title))
    story.append(Paragraph(f"Device: <b>{device.get('name')}</b> &nbsp;&bull;&nbsp; Generated {generated_at}", _meta))
    story.append(Spacer(1, 12))
    story.append(_section_divider())

    # --- Executive summary as scannable stat cards, not a dense paragraph ---
    compliance_score = compliance.get("compliance_score")
    score_text = f"{compliance_score}%" if compliance_score is not None else "N/A"
    risk_level = risk.get("risk_level", "N/A")
    fail_count = compliance["status_counts"].get("FAIL", 0)

    score_color = colors.HexColor("#16a34a") if (compliance_score or 0) >= 70 else _SEVERITY_COLORS.get("HIGH", _ORANGE)
    risk_color = _SEVERITY_COLORS.get(risk_level, _BLACK)
    fail_color = colors.HexColor("#16a34a") if fail_count == 0 else colors.HexColor("#dc2626")

    story.append(
        _stat_cards(
            [
                ("Compliance Score", score_text, score_color),
                (f"Risk Level (score {risk.get('risk_score')}/100)", risk_level, risk_color),
                ("Findings Requiring Remediation", str(fail_count), fail_color),
            ]
        )
    )
    story.append(Spacer(1, 14))

    # --- Device Identification ---
    story.append(Paragraph("Device Identification", _h2))
    story.append(
        _kv_table(
            [
                ["Device Name", device.get("name", "")],
                ["Vendor", device.get("vendor") or "Unknown"],
                ["Platform", device.get("platform") or "Unknown"],
                ["Configuration Version", str(scan.get("configuration_version"))],
                ["Asset Criticality", (device.get("asset_context", {}).get("criticality", "") or "").title()],
                ["Environment", (device.get("asset_context", {}).get("environment", "") or "").title()],
            ]
        )
    )
    story.append(Spacer(1, 16))

    # --- Compliance Results ---
    story.append(Paragraph("Compliance Results", _h2))
    counts = compliance["status_counts"]
    story.append(
        Paragraph(
            f"<font color='#16a34a'><b>PASS {counts.get('PASS', 0)}</b></font> &nbsp;&nbsp; "
            f"<font color='#dc2626'><b>FAIL {counts.get('FAIL', 0)}</b></font> &nbsp;&nbsp; "
            f"<font color='#4D4D4D'><b>NOT APPLICABLE {counts.get('NOT_APPLICABLE', 0)}</b></font> &nbsp;&nbsp; "
            f"<font color='#d97706'><b>INSUFFICIENT EVIDENCE {counts.get('INSUFFICIENT_EVIDENCE', 0)}</b></font>",
            _body,
        )
    )
    story.append(Spacer(1, 8))

    framework_rows = [["Framework", "Implemented", "Coverage"]]
    for cov in compliance["framework_coverage"].values():
        coverage_text = f"{cov['coverage_percent']}%" if cov["coverage_percent"] is not None else "N/A"
        total_text = str(cov["total_controls"]) if cov["total_controls"] is not None else "not enumerated"
        framework_rows.append([cov["framework"], f"{cov['implemented_controls']} / {total_text}", coverage_text])
    fw_table = Table(framework_rows, colWidths=[3 * inch, 2 * inch, 1.5 * inch])
    fw_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _LIGHT_GRAY),
                ("TEXTCOLOR", (0, 0), (-1, 0), _BLACK),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.4, _LIGHT_GRAY),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(fw_table)
    story.append(Spacer(1, 10))

    control_rows = [[c["title"], c["status"], c["severity"]] for c in compliance["controls"]]
    story.append(_status_severity_table(control_rows))
    story.append(Spacer(1, 16))

    # --- Risk Analysis ---
    story.append(Paragraph("Risk Analysis", _h2))
    story.append(
        _kv_table(
            [
                ["Risk Score", f"{risk.get('risk_score')} / 100"],
                ["Risk Level", risk.get("risk_level", "")],
                ["Calculation Version", risk.get("calculation_version", "")],
            ]
        )
    )
    story.append(Spacer(1, 8))
    factor_rows = [["Risk Factor", "Score", "Weight"]]
    for factor, data in risk.get("risk_factors", {}).items():
        factor_rows.append([factor.replace("_", " ").title(), str(data["score"]), str(data["weight"])])
    factor_table = Table(factor_rows, colWidths=[3 * inch, 1.75 * inch, 1.75 * inch])
    factor_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _LIGHT_GRAY),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.4, _LIGHT_GRAY),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(factor_table)
    story.append(Spacer(1, 16))

    # --- Potential Attack Paths ---
    story.append(Paragraph("Potential Attack Paths", _h2))
    paths = attack_graph.get("potential_attack_paths", [])
    if not paths:
        story.append(Paragraph("No potential attack path could be derived from this configuration and asset context.", _body))
    else:
        for p in paths[:10]:
            story.append(
                KeepTogether(
                    [
                        Paragraph(f"<b>{p['label']}</b>: {' &rarr; '.join(p['steps'])}", _body),
                        Paragraph(
                            f"Exposed services on path: {', '.join(p['exposed_services']) or 'none identified'}",
                            _small,
                        ),
                        Spacer(1, 6),
                    ]
                )
            )
    story.append(Spacer(1, 16))

    # --- ACO Remediation Plan ---
    story.append(Paragraph("ACO Remediation Sequencing", _h2))
    if optimizer:
        story.append(Paragraph(f"Optimization budget: {optimizer.get('budget')} finding(s) per cycle.", _small))
        story.append(Spacer(1, 6))
        strategy_rows = [["Strategy", "Residual Risk", "Risk Reduced", "Cost", "Paths Removed", "Runtime"]]
        strategy_labels = {"aco": "ACO", "severity_only": "Severity Only", "greedy_risk": "Greedy Risk"}
        for strategy, m in optimizer.get("strategies", {}).items():
            strategy_rows.append(
                [
                    strategy_labels.get(strategy, strategy.replace("_", " ").title()),
                    str(m["residual_risk"]),
                    f"{m['risk_reduced']} ({m['risk_reduction_percent']}%)",
                    str(m["operational_cost"]),
                    str(m["attack_paths_removed"]),
                    f"{m['runtime_ms']}ms",
                ]
            )
        strategy_table = Table(strategy_rows, colWidths=[1.3 * inch, 1 * inch, 1.2 * inch, 0.7 * inch, 1 * inch, 1.1 * inch])
        strategy_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), _LIGHT_GRAY),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.8),
                    ("GRID", (0, 0), (-1, -1), 0.4, _LIGHT_GRAY),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("BACKGROUND", (0, 1), (-1, -1), _SURFACE),
                ]
            )
        )
        story.append(strategy_table)
    else:
        story.append(Paragraph("No findings required remediation sequencing for this scan.", _body))
    story.append(Spacer(1, 16))

    # --- AI Recommendations ---
    story.append(Paragraph("AI Recommendations", _h2))
    story.append(
        Paragraph(
            "AI-generated explanations/remediation were not requested or the local LLM (Ollama) was not "
            "connected at report time. This report never fabricates AI output &mdash; see the platform's AI "
            "Assistant for live explanations once Ollama is configured.",
            _body,
        )
    )
    story.append(Spacer(1, 16))

    # --- Blockchain Provenance ---
    story.append(Paragraph("Blockchain Provenance", _h2))
    story.append(
        _kv_table(
            [
                ["Configuration SHA-256", scan.get("configuration_hash", "")],
                ["Compliance SHA-256", blockchain.get("compliance_hash", "N/A")],
                ["Risk SHA-256", blockchain.get("risk_hash", "N/A")],
                ["Blockchain Status", blockchain.get("status", "UNKNOWN")],
                ["Fabric Transaction ID", blockchain.get("transaction_id") or "N/A"],
            ]
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            "Hashes above are recomputed at report-generation time from the current MongoDB evidence and "
            "committed to the Hyperledger Fabric ledger as tamper-evident provenance. Use the Blockchain "
            "Integrity dashboard's Verify action to confirm they still match the ledger.",
            _small,
        )
    )

    doc.build(story, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    return buf.getvalue()
