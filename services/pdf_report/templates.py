"""
PDF Report HTML Template

Builds the complete HTML document for PDF generation.
"""

from services.pdf_report.styles import PDF_STYLES


def build_pdf_html(
    encoded_logo: str,
    timestamp: str,
    app_type: str,
    industry_sector: str,
    sensitive_data: str,
    internet_facing: str,
    num_employees: str,
    compliance_requirements: str,
    technical_ability: str,
    authentication: str,
    selected_technologies: str,
    selected_versions: str,
    html_description: str,
    improvement_suggestions_html: str,
    stride_table_html: str,
    mitre_attack_html: str,
    mitigations_html: str,
    dread_table_html: str,
    attack_tree_code: str,
    gherkin_tests_html: str,
) -> str:
    """Build the complete HTML document for the PDF report."""
    return f"""
    <html>
    <head><style>{PDF_STYLES}</style></head>
    <body>
    <h1 style="text-align: center;">AegisShield Security Report</h1>
    <div style="text-align: center;">
        <br><br>
        <img src="data:image/png;base64,{encoded_logo}" alt="Aegis Shield Logo" style="width: 500px; height: auto; margin-bottom: 20px;">
    </div>
    <div class="footer">Created: {timestamp}</div>

    <!-- Table of Contents -->
    <div class="page-break"></div>
    <div class="toc">
        <h2>Table of Contents</h2>
        <ul>
            <li><a href="#app-description">Application Description</a></li>
            <li><a href="#improvement-suggestions">Improvement Suggestions</a></li>
            <li><a href="#stride-threat-model">STRIDE Threat Model</a></li>
            <li><a href="#mitre-attack">MITRE ATT&CK</a></li>
            <li><a href="#mitigations">Mitigations</a></li>
            <li><a href="#dread-risk-assessment">DREAD Risk Assessment</a></li>
            <li><a href="#attack-tree">Attack Tree</a></li>
            <li><a href="#test-cases">Test Cases</a></li>
        </ul>
    </div>

    <div class="page-break"></div>
    <h2 id="app-description">Application Description</h2>
    <ul>
        <li><strong>Application Type:</strong> {app_type or 'N/A'}</li>
        <li><strong>Industry Sector:</strong> {industry_sector or 'N/A'}</li>
        <li><strong>Sensitive Data:</strong> {sensitive_data or 'N/A'}</li>
        <li><strong>Internet Facing:</strong> {internet_facing or 'N/A'}</li>
        <li><strong>Number of Employees:</strong> {num_employees or 'N/A'}</li>
        <li><strong>Compliance Requirements:</strong> {compliance_requirements or 'N/A'}</li>
        <li><strong>Technical Ability:</strong> {technical_ability or 'N/A'}</li>
        <li><strong>Authentication Method:</strong> {authentication or 'N/A'}</li>
        <li><strong>Selected Technologies:</strong> {selected_technologies or 'N/A'}</li>
        <li><strong>Selected Versions:</strong> {selected_versions or 'N/A'}</li>
    </ul>
    <div>{html_description}</div>

    <div class="page-break"></div>
    <h2 id="improvement-suggestions">Improvement Suggestions</h2>
    {improvement_suggestions_html}

    <div class="page-break"></div>
    <h2 id="stride-threat-model">STRIDE Threat Model</h2>
    {stride_table_html}

    {mitre_attack_html}

    <div class="page-break"></div>
    <h2 id="mitigations">Mitigations</h2>
    {mitigations_html}

    <div class="page-break"></div>
    <h2 id="dread-risk-assessment">DREAD Risk Assessment</h2>
    {dread_table_html}

    <div class="page-break">
        <h2 id="attack-tree">Attack Tree</h2>
        <p><strong>Attack Tree diagram instructions</strong>: Copy the below code and paste it into https://mermaid.live/</p>
        <pre class="mermaid-code">{attack_tree_code}</pre>
    </div>

    <div class="page-break">
        <h2 id="test-cases">Test Cases</h2>
        <p style='font-size: 11px;'>For the history of Behavior Driven Development (BDD) and Gherkin syntax, see: https://cucumber.io/docs/bdd/history/</p>
        <pre class="gherkin-code">{gherkin_tests_html}</pre>
    </div>

    </body>
    </html>
    """
