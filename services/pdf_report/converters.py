"""
PDF Report Data Converters

Functions for converting various data formats to HTML for PDF generation.
"""

import json
import logging

import markdown2

logger = logging.getLogger(__name__)


def convert_markdown_to_html(markdown_text: str) -> str:
    """Convert basic markdown text to HTML."""
    return markdown2.markdown(markdown_text)


def convert_markdown_to_html_desc(markdown_text: str) -> str:
    """Convert markdown to HTML with extended formatting."""
    return markdown2.markdown(
        markdown_text,
        extras=["fenced-code-blocks", "tables", "strike", "cuddled-lists"],
    )


def convert_mitre_attack_to_html(mitre_markdown: str) -> str:
    """Convert MITRE ATT&CK markdown to HTML with specific formatting."""
    mitre_markdown = '<h2 id="mitre-attack">MITRE ATT&CK</h2>' + mitre_markdown
    html = markdown2.markdown(
        mitre_markdown,
        extras=["fenced-code-blocks", "tables", "strike", "cuddled-lists"],
    )
    html = html.replace(
        "<strong>Potential Impact</strong>",
        "<br><strong>Potential Impact</strong>",
    )
    return f'<div style="page-break-inside: avoid; page-break-before: always;">{html}</div>'


def convert_json_to_html(json_data) -> str:
    """Convert JSON data to HTML (lists become bullet points)."""
    if isinstance(json_data, list):
        items = "".join(f"<li>{item}</li>" for item in json_data)
        return f"<ul>{items}</ul>"
    return "<pre>" + json.dumps(json_data, indent=4) + "</pre>"


def convert_stride_to_html_table(stride_data_list: list[dict]) -> str:
    """Convert STRIDE threat model data to an HTML table."""
    html = '<table border="1" cellpadding="4" cellspacing="0" style="font-size: 12px;">'
    headers = ["Threat Type", "Scenario", "Assumptions", "Potential Impact"]
    html += "<tr>" + "".join(f"<th style='text-align: left;'>{h}</th>" for h in headers) + "</tr>"

    for stride_data in stride_data_list:
        html += "<tr style='page-break-inside: avoid;'>"
        html += f"<td style='vertical-align: top;'>{stride_data['Threat Type']}</td>"
        html += f"<td style='vertical-align: top;'>{stride_data['Scenario']}</td>"
        assumptions = "<ul>"
        for a in stride_data.get("Assumptions", []):
            assumptions += f"<li>{a.get('Assumption', '')} (Role: {a.get('Role', 'N/A')}, Condition: {a.get('Condition', 'N/A')})</li>"
        assumptions += "</ul>"
        html += f"<td style='vertical-align: top;'>{assumptions}</td>"
        html += f"<td style='vertical-align: top;'>{stride_data['Potential Impact']}</td>"
        html += "</tr>"

    return html + "</table>"


def _parse_markdown_table_rows(markdown_text: str) -> list[list[str]]:
    """Parse a markdown table into rows, skipping separator lines."""
    if not isinstance(markdown_text, str):
        return []
    lines = markdown_text.strip().split("\n")
    rows = []
    for line in lines:
        if "|" in line:
            cells = [c.strip() for c in line.split("|")[1:-1]]
            # Skip separator lines (---|----|---)
            if rows or not all(c.replace("-", "").strip() == "" for c in cells):
                if not all(c.replace("-", "").strip() == "" for c in cells):
                    rows.append(cells)
    return rows


def convert_mitigations_to_html_table(mitigations_markdown: str) -> str:
    """Convert mitigations markdown table to HTML."""
    rows = _parse_markdown_table_rows(mitigations_markdown)
    html = """
    <table border="1" cellpadding="4" cellspacing="0" style="font-size: 12px; width: 100%; table-layout: fixed;">
        <colgroup><col style="width: 20%;"><col style="width: 40%;"><col style="width: 40%;"></colgroup>
        <tr><th>Threat Type</th><th>Scenario</th><th>Suggested Mitigation(s)</th></tr>
    """
    for row in rows:
        if len(row) == 3 and row[0] != "Threat Type":
            cells = "".join(f'<td style="vertical-align: top; word-wrap: break-word;">{c}</td>' for c in row)
            html += f'<tr style="page-break-inside: avoid;">{cells}</tr>'
    return html + "</table>"


def convert_dread_to_html_table(dread_markdown: str) -> str:
    """Convert DREAD assessment markdown table to HTML."""
    rows = _parse_markdown_table_rows(dread_markdown)
    html = """
    <table border="1" cellpadding="4" cellspacing="0" style="font-size: 12px; width: 100%; table-layout: fixed;">
        <colgroup>
            <col style="width: 17%;"><col style="width: 28%;"><col style="width: 10%;">
            <col style="width: 9%;"><col style="width: 9%;"><col style="width: 9%;">
            <col style="width: 9%;"><col style="width: 9%;">
        </colgroup>
        <tr>
            <th>Threat Type</th><th>Scenario</th><th>Damage Potential</th>
            <th>Reproducibility</th><th>Exploitability</th><th>Affected Users</th>
            <th>Discoverability</th><th>Risk Score</th>
        </tr>
    """
    for row in rows:
        if len(row) == 8 and row[0] != "Threat Type":
            cells = "".join(f'<td style="vertical-align: top; word-wrap: break-word;">{c}</td>' for c in row)
            html += f'<tr style="page-break-inside: avoid;">{cells}</tr>'
    return html + "</table>"


def format_gherkin_tests(gherkin_text: str) -> str:
    """Format Gherkin test cases with styled HTML."""
    clean_text = gherkin_text.replace("```gherkin", "").replace("```", "").strip()
    test_cases = clean_text.split("### ")
    formatted = ""

    for test_case in test_cases:
        if not test_case.strip():
            continue
        header = test_case.splitlines()[0]
        formatted += f"<hr style='border: 1px solid lightgray; width: 50%; margin: 20px auto;'><strong>{header}</strong><br/>"
        formatted += "<div style='font-family: Courier; font-size: 10px; max-width: 90%; padding: 5px;'>"
        for step in test_case.splitlines()[1:]:
            if step.strip().startswith(("Feature", "Scenario", "Given", "When", "Then", "And")):
                parts = step.split()
                keyword, rest = parts[0], " ".join(parts[1:])
                formatted += f"<strong style='color: darkred;'>{keyword}</strong> {rest}<br/>"
            else:
                formatted += f"{step}<br/>"
        formatted += "</div>"

    return formatted
