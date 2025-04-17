"""
Step 7: PDF Generation Module

This module handles the final step of the threat modeling process, generating a comprehensive
PDF report that compiles all the information from previous steps. The PDF includes:
- Application description and technology details
- STRIDE threat model
- MITRE ATT&CK mappings
- Mitigation strategies
- DREAD risk assessment
- Attack tree visualization
- Test cases in Gherkin format

The module converts various markdown and JSON data into HTML format and combines them
into a single, well-formatted PDF document with proper page breaks and styling.

Dependencies:
    - streamlit: For UI components
    - xhtml2pdf: For PDF generation
    - markdown2: For markdown to HTML conversion
    - json: For data handling
    - datetime: For timestamp generation
    - base64: For file encoding
    - error_handler: For consistent error handling

Session State Variables Used:
    - step6_completed: Boolean indicating if previous steps are complete
    - session_test_cases_markdown: Markdown content of test cases
    - session_dread_assessment_markdown: Markdown content of DREAD assessment
    - session_mitigations_markdown: Markdown content of mitigations
    - session_threat_model_json: JSON data of threat model
    - mitre_attack_markdown: Markdown content of MITRE ATT&CK data
    - attack_tree_code: Code representation of attack tree
    - app_details: Application details dictionary
    - app_input: User input data
    - improvement_suggestions_json: JSON data of improvement suggestions
"""

import streamlit as st
from xhtml2pdf import pisa
import io
import markdown2
import json
from datetime import datetime
import base64
import logging
from error_handler import handle_exception  # Import the error handler

# Configure logging
logger = logging.getLogger(__name__)

# UI text constants
UI_TEXT = {
    'title': "Generate PDF Report",
    'description': """
    This PDF compiles all the information generated in the previous steps and packages it into a single downloadable file.
    The PDF includes the application description, technology details, threat model, attack tree, mitigations, DREAD risk assessment, and test cases.
    """,
    'step_warning': "Please complete Steps 1 through 6 first.",
    'button_label': "Generate PDF Report",
    'spinner_text': "Generating PDF Report...",
    'error_message': "Please complete all previous steps before generating a PDF report.",
    'pdf_error': "Error generating PDF Document."
}

def render():
    """
    Render the PDF generation tab.
    
    This function creates the UI for the PDF generation step and handles the PDF creation process.
    It checks if all previous steps are completed, then provides a button to generate the PDF report.
    When the button is clicked, it converts all the collected data into HTML format and generates
    a downloadable PDF file.
    
    The function includes several helper functions for converting different data types to HTML:
    - convert_markdown_to_html: Basic markdown to HTML conversion
    - convert_markdown_to_html_desc: Markdown to HTML with additional formatting
    - convert_mitre_attack_to_html: Special formatting for MITRE ATT&CK data
    - convert_json_to_html: JSON data to HTML format
    - parse_markdown_table: Parse markdown tables into structured data
    - convert_table_to_html: Convert table data to HTML
    - convert_stride_to_html_table: Convert STRIDE threat model to HTML table
    - convert_mitigations_to_html_table: Convert mitigations to HTML table
    - convert_dread_to_html_table: Convert DREAD assessment to HTML table
    - format_gherkin_tests: Format Gherkin test cases with specific styling
    
    Returns:
        None
    """
    logger.info("Rendering PDF generation tab")
    
    if not st.session_state['step6_completed']:
        logger.warning("User attempted to access PDF generation before completing previous steps")
        st.warning(UI_TEXT['step_warning'])
        return

    st.markdown(UI_TEXT['description'])
    st.markdown("""---""")

    # Helper functions
    def convert_markdown_to_html(markdown_text):
        """
        Convert basic markdown text to HTML.
        
        Args:
            markdown_text (str): The markdown text to convert
            
        Returns:
            str: The converted HTML content
        """
        logger.debug("Converting basic markdown to HTML")
        return markdown2.markdown(markdown_text)

    def convert_markdown_to_html_desc(markdown_text):
        """
        Convert markdown text to HTML with additional formatting options.
        
        Args:
            markdown_text (str): The markdown text to convert
            
        Returns:
            str: The converted HTML content with additional formatting
        """
        logger.debug("Converting markdown description to HTML with extras")
        return markdown2.markdown(markdown_text, extras=["fenced-code-blocks", "tables", "strike", "cuddled-lists"])

    def convert_mitre_attack_to_html(mitre_markdown):
        """
        Convert MITRE ATT&CK markdown to HTML with specific formatting.
        
        Args:
            mitre_markdown (str): The MITRE ATT&CK markdown content
            
        Returns:
            str: The converted HTML content with MITRE ATT&CK specific formatting
        """
        logger.debug("Converting MITRE ATT&CK markdown to HTML")
        # Add the MITRE ATT&CK header to the markdown content
        mitre_markdown = '<h2 id="mitre-attack">MITRE ATT&CK</h2>' + mitre_markdown

        # Convert Markdown to HTML with robust handling of nested elements
        html = markdown2.markdown(mitre_markdown, extras=["fenced-code-blocks", "tables", "strike", "cuddled-lists"])

        # Add a line break only before Potential Impact within the same paragraph
        html = html.replace('<strong>Potential Impact</strong>', '<br><strong>Potential Impact</strong>')

        # Wrap the entire content (including the header) in a div with specific styles
        html = f'<div style="page-break-inside: avoid; page-break-before: always;">{html}</div>'

        return html

    def convert_json_to_html(json_data):
        """
        Convert JSON data to HTML format.
        
        Args:
            json_data (Union[List[str], Dict[str, Any]]): The JSON data to convert
            
        Returns:
            str: The converted HTML content
        """
        logger.debug("Converting JSON data to HTML")
        if isinstance(json_data, list):  # Handle lists as bullet points
            html = "<ul>"
            for item in json_data:
                html += f"<li>{item}</li>"
            html += "</ul>"
            return html
        else:
            return "<pre>" + json.dumps(json_data, indent=4) + "</pre>"

    def parse_markdown_table(markdown_text):
        """
        Parse markdown table text into a list of lists.
        
        Args:
            markdown_text (str): The markdown table text to parse
            
        Returns:
            List[List[str]]: A list of lists containing the table data
        """
        logger.debug("Parsing markdown table")
        if isinstance(markdown_text, str):
            lines = markdown_text.strip().split('\n')
            data = [line.split('|')[1:-1] for line in lines if '|' in line]
            data = [[cell.strip() for cell in row] for row in data]
            return data
        else:
            logger.error("Expected markdown text but received a different data type")
            st.error("Expected markdown text but received a different data type.")
            return []

    def convert_table_to_html(table_data):
        """
        Convert table data to HTML format.
        
        Args:
            table_data (List[List[str]]): A list of lists containing the table data
            
        Returns:
            str: The HTML table markup
        """
        logger.debug("Converting table data to HTML")
        html = '<table border="1" cellpadding="4" cellspacing="0">'
        for row in table_data:
            html += '<tr>'
            for cell in row:
                html += f'<td>{cell}</td>'
            html += '</tr>'
        html += '</table>'
        return html

    def convert_stride_to_html_table(stride_data_list):
        """
        Convert STRIDE threat model data to HTML table format.
        
        Args:
            stride_data_list (List[Dict[str, Any]]): List of STRIDE threat model entries
            
        Returns:
            str: The HTML table markup for the STRIDE threat model
        """
        logger.debug("Converting STRIDE data to HTML table")
        html = '<table border="1" cellpadding="4" cellspacing="0" style="font-size: 12px;">'
        headers = ["Threat Type", "Scenario", "Assumptions", "Potential Impact"]
        html += "<tr>"
        for header in headers:
            html += f"<th style='text-align: left;'>{header}</th>"
        html += "</tr>"
        for stride_data in stride_data_list:
            html += "<tr style='page-break-inside: avoid;'>"
            html += f"<td style='vertical-align: top;'>{stride_data['Threat Type']}</td>"
            html += f"<td style='vertical-align: top;'>{stride_data['Scenario']}</td>"
            assumptions = "<ul>"
            for assumption in stride_data['Assumptions']:
                assumptions += f"<li>{assumption['Assumption']} (Role: {assumption['Role']}, Condition: {assumption['Condition']})</li>"
            assumptions += "</ul>"
            html += f"<td style='vertical-align: top;'>{assumptions}</td>"
            html += f"<td style='vertical-align: top;'>{stride_data['Potential Impact']}</td>"
            html += "</tr>"
        html += '</table>'
        return html

    def convert_mitigations_to_html_table(mitigations_markdown):
        """
        Convert mitigations markdown to HTML table format.
        
        Args:
            mitigations_markdown (str): The mitigations data in markdown format
            
        Returns:
            str: The HTML table markup for the mitigations
        """
        logger.debug("Converting mitigations to HTML table")
        lines = mitigations_markdown.strip().split('\n')
        rows = []
        for line in lines:
            if '|' in line:
                if len(rows) == 0 or not all(char == '-' for char in line.replace('|', '').strip()):
                    rows.append([cell.strip() for cell in line.split('|')[1:-1]])

        html = '''
        <table border="1" cellpadding="4" cellspacing="0" style="font-size: 12px; width: 100%; table-layout: fixed;">
            <colgroup>
                <col style="width: 20%;">
                <col style="width: 40%;">
                <col style="width: 40%;">
            </colgroup>
            <tr>
                <th>Threat Type</th>
                <th>Scenario</th>
                <th>Suggested Mitigation(s)</th>
            </tr>
        '''
        for row in rows:
            if len(row) == 3 and row[0] != 'Threat Type':
                html += '<tr style="page-break-inside: avoid;">'
                for cell in row:
                    html += f'<td style="vertical-align: top; word-wrap: break-word;">{cell}</td>'
                html += '</tr>'
        html += '</table>'
        return html

    def convert_dread_to_html_table(dread_markdown):
        """
        Convert DREAD assessment markdown to HTML table format.
        
        Args:
            dread_markdown (str): The DREAD assessment data in markdown format
            
        Returns:
            str: The HTML table markup for the DREAD assessment
        """
        logger.debug("Converting DREAD assessment to HTML table")
        lines = dread_markdown.strip().split('\n')
        rows = []
        for line in lines:
            if '|' in line:
                if len(rows) == 0 or not all(char == '-' for char in line.replace('|', '').strip()):
                    rows.append([cell.strip() for cell in line.split('|')[1:-1]])

        html = '''
        <table border="1" cellpadding="4" cellspacing="0" style="font-size: 12px; width: 100%; table-layout: fixed;">
            <colgroup>
                <col style="width: 17%;">
                <col style="width: 28%;">
                <col style="width: 10%;">
                <col style="width: 9%;">
                <col style="width: 9%;">
                <col style="width: 9%;">
                <col style="width: 9%;">
                <col style="width: 9%;">
            </colgroup>
            <tr>
                <th>Threat Type</th>
                <th>Scenario</th>
                <th>Damage Potential</th>
                <th>Reproducibility</th>
                <th>Exploitability</th>
                <th>Affected Users</th>
                <th>Discoverability</th>
                <th>Risk Score</th>
            </tr>
        '''
        for row in rows:
            if len(row) == 8 and row[0] != 'Threat Type':
                html += '<tr style="page-break-inside: avoid;">'
                for cell in row:
                    html += f'<td style="vertical-align: top; word-wrap: break-word;">{cell}</td>'
                html += '</tr>'
        html += '</table>'
        return html

    def format_gherkin_tests(gherkin_text):
        """
        Format Gherkin test cases with specific styling.
        
        Args:
            gherkin_text (str): The Gherkin test cases in text format
            
        Returns:
            str: The formatted HTML content for the Gherkin test cases
        """
        logger.debug("Formatting Gherkin test cases")
        # Remove the ```gherkin blocks from the text
        clean_text = gherkin_text.replace("```gherkin", "").replace("```", "").strip()

        # Split the cleaned Gherkin text into individual test cases
        test_cases = clean_text.split("### ")
        formatted = ""

        for test_case in test_cases:
            if test_case.strip():
                # Header (bold)
                header = test_case.splitlines()[0]
                formatted += f"<hr style='border: 1px solid lightgray; width: 50%; margin: 20px auto;'><strong>{header}</strong><br/>"

                # Add the steps formatted as code
                steps = test_case.splitlines()[1:]
                formatted += "<div style='font-family: Courier; font-size: 10px; max-width: 90%; padding: 5px;'>"
                for step in steps:
                    # Check if the line starts with a Gherkin keyword and make it bold
                    if step.strip().startswith(("Feature", "Scenario", "Given", "When", "Then", "And")):
                        keyword = step.split()[0]
                        rest_of_line = ' '.join(step.split()[1:])
                        formatted += f"<strong style='color: darkred;'>{keyword}</strong> {rest_of_line}<br/>"
                    else:
                        formatted += f"{step}<br/>"
                formatted += "</div>"

        return formatted

    # Create a submit button for PDF generation
    pdf_submit_button = st.button(label=UI_TEXT['button_label'])

    # If the Generate PDF Report button is clicked
    if pdf_submit_button:
        logger.info("PDF generation button clicked")
        if (st.session_state.get('session_test_cases_markdown') and 
            st.session_state.get('session_dread_assessment_markdown') and 
            st.session_state.get('session_mitigations_markdown') and 
            st.session_state.get('session_threat_model_json') and 
            st.session_state.get('mitre_attack_markdown') and  # Corrected line
            st.session_state.get('attack_tree_code') and 
            st.session_state.get('app_details') and
            st.session_state.get('app_input')):

            logger.info("All required session state variables are present, proceeding with PDF generation")

            if isinstance(st.session_state['app_details'], dict):
                app_details_str = json.dumps(st.session_state['app_details'], indent=4)
            else:
                app_details_str = st.session_state['app_details']

            # Extract the application details
            app_type = st.session_state['app_details'].get('app_type')
            industry_sector = st.session_state['app_details'].get('industry_sector')
            sensitive_data = st.session_state['app_details'].get('sensitive_data')
            internet_facing = st.session_state['app_details'].get('internet_facing')
            num_employees = st.session_state['app_details'].get('num_employees')
            compliance_requirements = st.session_state['app_details'].get('compliance_requirements')
            technical_ability = st.session_state['app_details'].get('technical_ability')
            authentication = st.session_state['app_details'].get('authentication')
            selected_technologies = st.session_state['app_details'].get('selected_technologies')
            selected_versions = st.session_state['app_details'].get('selected_versions')

            with st.spinner(UI_TEXT['spinner_text']):
                try:
                    logger.info("Converting data to HTML format")
                    stride_table_html = convert_stride_to_html_table(st.session_state['session_threat_model_json'])
                    mitigations_html = convert_mitigations_to_html_table(st.session_state['session_mitigations_markdown'])
                    dread_table_html = convert_dread_to_html_table(st.session_state['session_dread_assessment_markdown'])
                    gherkin_tests_html = format_gherkin_tests(st.session_state['session_test_cases_markdown'])
                    mitre_attack_html = convert_mitre_attack_to_html(st.session_state['mitre_attack_markdown'])

                    # Prepare the content to be written to the text file
                    #file_content = f"MITRE ATT&CK Markdown ):\n\n{st.session_state['mitre_attack_markdown']}\n\n" \
                                #f"MITRE ATT&CK HTML (Converted from Markdown):\n\n{mitre_attack_html}"

                    # Write the content to a text file on the local drive
                    #with open("mitre_attack_html_comparison.txt", "w") as file:
                        #file.write(file_content)

                    # Optional: Print confirmation to the console or Streamlit app
                    #print("MITRE ATT&CK HTML comparison saved to mitre_attack_html_comparison.txt")

                    logger.info("Loading logo image")
                    with open("aegisshield-bw.png", "rb") as image_file:
                        encoded_string = base64.b64encode(image_file.read()).decode('utf-8')

                    # Get the current timestamp
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    logger.info("Converting application description to HTML")
                    html_description = convert_markdown_to_html_desc(st.session_state['app_input'])

                    logger.info("Generating HTML content for PDF")
                    html_content = f"""
                    <html>
                    <head>
                        <style>
                            @page {{
                                size: landscape;
                                margin: 1cm;
                            }}

                            @page portrait {{
                                size: portrait;
                                margin: 1cm;
                            }}

                            body {{ font-family: 'Helvetica', sans-serif; font-size: 14px; }}
                            h1, h2, h3 {{ color: #333; }}
                            table {{ width: 100%; border-collapse: collapse; }}
                            th, td {{ border: 1px solid #ddd; padding: 8px; }}
                            th {{ background-color: #f2f2f2; text-align: left; }}
                            .page-break {{ page-break-before: always; }}
                            tr {{ page-break-inside: avoid; }}
                            p {{ font-size: 14px; }}
                            .landscape-section {{
                                page: landscape;
                            }}
                            .mermaid-code {{
                                font-size: 10px; /* Set the font size */
                                font-family: 'Courier New', Courier, monospace; /* Use the same font */
                            }}
                            .gherkin-code {{
                                font-size: 10px; /* Set the font size */
                                font-family: 'Courier New', Courier, monospace; /* Use the same font */
                            }}
                            .footer {{
                                position: absolute;
                                bottom: 0;
                                width: 100%;
                                text-align: center;
                                font-size: 12px;
                                color: #555;
                            }}
                            .toc {{
                                margin-bottom: 2cm;
                            }}
                            .toc h2 {{
                                font-size: 18px;
                                text-align: center;
                                text-decoration: underline;
                            }}
                            .toc ul {{
                                list-style-type: none;
                                padding-left: 0;
                            }}
                            .toc li {{
                                margin-bottom: 8px;
                                font-size: 14px;
                            }}
                            .toc a {{
                                text-decoration: none;
                                color: #333;
                            }}
                            .toc a:hover {{
                                text-decoration: underline;
                            }}
                            ul {{
                                line-height: 1.0; /* Adjusts the line spacing within each <li> */
                                margin: 0;
                                padding: 0;
                            }}

                            ul li {{
                                margin-bottom: 8px; /* Adds space between each list item */
                            }}
                        </style>
                    </head>
                    <body>
                    <h1 style="text-align: center;">AegisShield Security Report</h1>
                    <div style="text-align: center;">
                        <br><br>
                        <img src="data:image/png;base64,{encoded_string}" alt="Aegis Shield Logo" style="width: 500px; height: auto; margin-bottom: 20px;">
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
                    <h2 id="app-description">Application Description</h2>
                    <ul>
                        <li><strong>Application Type:</strong> {app_type if app_type else 'N/A'}</li>
                        <li><strong>Industry Sector:</strong> {industry_sector if industry_sector else 'N/A'}</li>
                        <li><strong>Sensitive Data:</strong> {sensitive_data if sensitive_data else 'N/A'}</li>
                        <li><strong>Internet Facing:</strong> {internet_facing if internet_facing else 'N/A'}</li>
                        <li><strong>Number of Employees:</strong> {num_employees if num_employees else 'N/A'}</li>
                        <li><strong>Compliance Requirements:</strong> {compliance_requirements if compliance_requirements else 'N/A'}</li>
                        <li><strong>Technical Ability:</strong> {technical_ability if technical_ability else 'N/A'}</li>
                        <li><strong>Authentication Method:</strong> {authentication if authentication else 'N/A'}</li>
                        <li><strong>Selected Technologies:</strong> {', '.join(selected_technologies) if selected_technologies else 'N/A'}</li>
                        <li><strong>Selected Versions:</strong> {', '.join(selected_versions) if selected_versions else 'N/A'}</li>
                    </ul>
                    <div>{html_description}</div>


                    <div class="page-break"></div>
                    <h2 id="improvement-suggestions">Improvement Suggestions</h2>
                    {convert_json_to_html(st.session_state['improvement_suggestions_json'])}

                    <div class="page-break"></div>
                    <h2 id="stride-threat-model">STRIDE Threat Model</h2>
                    {stride_table_html}


                    <!-- MITRE ATT&CK Section: Wrap header and content together -->
                    {mitre_attack_html}


                    <div class="page-break"></div>
                    <h2 id="mitigations">Mitigations</h2>
                    {mitigations_html}

                    <div class="page-break"></div>
                    <h2 id="dread-risk-assessment">DREAD Risk Assessment</h2>
                    {dread_table_html}

                    <div class="page-break">
                        <h2 id="attack-tree">Attack Tree</h2>
                        <p><strong>Attack Tree diagram instructions</strong>:  Copy the below code and paste it into https://mermaid.live/</p>
                        <pre class="mermaid-code">{st.session_state['attack_tree_code']}</pre>
                    </div>

                    <div class="page-break">
                        <h2 id="test-cases">Test Cases</h2>
                        <p style='font-size: 11px;'>For the history of Behavior Driven Development (BDD) and Gherkin syntax, see: https://cucumber.io/docs/bdd/history/</p>
                        <pre class="gherkin-code">{gherkin_tests_html}</pre>
                    </div>

                    </body>
                    </html>
                    """

                    logger.info("Creating PDF from HTML content")
                    pdf_file = io.BytesIO()
                    pisa.CreatePDF(html_content, dest=pdf_file)
                    pdf_file.seek(0)

                    filetimestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    file_name = f"threat_model_report_{filetimestamp}.pdf"

                    logger.info(f"PDF generation complete, offering download as {file_name}")
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf_file,
                        file_name=file_name,
                        mime="application/pdf"
                    )

                except Exception as e:
                    logger.error(f"Error generating PDF: {str(e)}")
                    handle_exception(e, UI_TEXT['pdf_error'])

        else:
            logger.warning("User attempted to generate PDF without completing all previous steps")
            st.error(UI_TEXT['error_message'])