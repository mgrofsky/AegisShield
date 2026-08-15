[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)  
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)  
[![codecov](https://codecov.io/gh/mgrofsky/AegisShield/graph/badge.svg?token=W91TRNEP92)](https://codecov.io/gh/mgrofsky/AegisShield)
[![NIST SP 800-53](https://img.shields.io/badge/NIST%20SP%20800--53-15%20Controls-green.svg)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
[![NIST SP 800-53](https://img.shields.io/badge/NIST%20SP%20800--53%20Rev.%205-Aligned-blue.svg)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

### Coverage Overview
[![Coverage Grid](https://codecov.io/gh/mgrofsky/AegisShield/graphs/tree.svg?token=W91TRNEP92)](https://codecov.io/gh/mgrofsky/AegisShield)


# AegisShield Threat Modeler


![AegisShield](aegisshield.png)

AegisShield is a threat modeling tool designed to democratize the threat modeling process while supporting federal and enterprise compliance programs. It leverages GPT-4o and integrates with multiple threat intelligence sources to provide comprehensive threat analysis aligned with **NIST SP 800-53 Rev. 5 controls**.

## Table of Contents

- [Core Features](#core-features)
- [NIST SP 800-53 Rev. 5 Compliance](#nist-sp-800-53-rev-5-compliance)
- [Technology Coverage](#technology-coverage)
- [Requirements](#requirements)
- [Enterprise Integration](#enterprise-integration)
- [Setup](#setup)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [FAQ](#faq)
- [Research Context](#artifact-overview-research-context)
- [License](#license)
- [Compliance Documentation](#compliance-documentation)

## Core Features

- **AI-Powered Analysis**: Utilizes GPT-4o for generating threat models, attack trees, and security test cases
- **Threat Intelligence Integration**:
  - MITRE ATT&CK Framework: Direct integration with STIX repository for threat tactics and techniques
  - National Vulnerability Database (NVD): Real-time vulnerability scanning with CPE-based version tracking
  - AlienVault OTX: Industry-specific threat intelligence
- **Interactive Interface**:
  - Seven-step guided process through application description, technology stack, and threat modeling
  - Two-column layout with comprehensive error handling
  - Support for architecture diagram analysis
- **Threat Analysis**:
  - STRIDE-based threat modeling with roles and assumptions
  - DREAD risk assessment
  - Attack tree generation
  - Security test case generation
- **Documentation**: Generates comprehensive PDF reports including threat models, attack trees, and test cases

## NIST SP 800-53 Rev. 5 Compliance

AegisShield implements **15 NIST SP 800-53 Rev. 5 security controls** across 6 control families, making it suitable for federal and enterprise environments requiring compliance with cybersecurity frameworks.

### Implemented Control Families

- **Access Control (AC)**: API key validation and access enforcement
- **Identification and Authentication (IA)**: Secure authenticator management and external service authentication
- **System and Communications Protection (SC)**: Boundary protection and cryptographic key management
- **System and Information Integrity (SI)**: Continuous monitoring, error handling, and vulnerability assessment
- **Audit and Accountability (AU)**: Comprehensive logging, audit storage, and review capabilities
- **Risk Assessment (RA)**: Vulnerability scanning and threat intelligence integration
- **Program Management (PM)**: Threat awareness program implementation

### Compliance Benefits

- ✅ **NIST SP 800-53 Rev. 5 Aligned**: 15 self-assessed control implementations across 6 control families
- ✅ **Federal Framework Mapping**: Machine-readable control mappings that support FedRAMP and FISMA compliance programs
- ✅ **Enterprise Security**: Demonstrates industry-standard security practices
- ✅ **Audit Trail**: Complete traceability with machine-readable control mappings

### Machine-Readable Control Mapping

AegisShield includes a comprehensive JSON mapping file (`nist-sp-800-53-controls-mapping.json`) for automated compliance integration:

```bash
# Load controls into GRC tools
curl -X POST "https://your-grc-tool.com/api/controls" \
     -H "Content-Type: application/json" \
     -d @nist-sp-800-53-controls-mapping.json

# Extract specific control families
jq '.controls[] | select(.control_family_abbreviation == "AU")' nist-sp-800-53-controls-mapping.json

# Generate compliance summary
jq '.assessment_summary' nist-sp-800-53-controls-mapping.json
```

For detailed control implementation documentation, see:
- [`NIST-SP-800-53-CONTROLS.md`](NIST-SP-800-53-CONTROLS.md) - Human-readable control documentation
- [`nist-sp-800-53-controls-mapping.json`](nist-sp-800-53-controls-mapping.json) - Machine-readable control mappings

## Technology Coverage

- **Application Types**: Web, mobile, desktop, cloud, IoT, ICS/SCADA, AI/ML systems, and more
- **Technology Stack**: Common databases, operating systems, programming languages, and web frameworks
- **Industry Support**: Finance, healthcare, government, technology, and others
- **Security & Compliance**: 
  - **NIST SP 800-53 Rev. 5**: 15 implemented security controls with full traceability
  - **FedRAMP & FISMA**: Machine-readable control mappings that support federal compliance programs
  - **Authentication methods**: Secure API key management and multi-factor authentication support
  - **Compliance standards**: HIPAA, GDPR, SOC 2, and other regulatory framework alignment
  - **Data sensitivity classification**: High/Medium/Low with appropriate handling controls
  - **Internet exposure assessment**: Boundary protection and secure communications
  - **Organization size categorization**: Scalable security controls for enterprises
  - **Technical capability evaluation**: Automated vulnerability assessment and monitoring

## Requirements

- Python 3.12
- Streamlit
- OpenAI API (GPT-4o access)
- OTXv2
- nvdlib
- markdown2
- xhtml2pdf
- setuptools

API keys required:
- OpenAI API key
- NVD API key
- AlienVault OTX API key

## Enterprise Integration

### GRC Tool Integration

AegisShield provides machine-readable control mappings for integration with enterprise GRC (Governance, Risk, and Compliance) tools:

**ServiceNow Integration:**
```bash
# Import NIST controls into ServiceNow
curl -X POST "https://your-instance.servicenow.com/api/now/table/sn_grc_control" \
     -H "Authorization: Bearer $SERVICENOW_TOKEN" \
     -H "Content-Type: application/json" \
     -d @nist-sp-800-53-controls-mapping.json
```

**RSA Archer Integration:**
```python
import json
import requests

# Load AegisShield control mappings
with open('nist-sp-800-53-controls-mapping.json') as f:
    controls = json.load(f)

# Transform for Archer API
for control in controls['controls']:
    archer_payload = {
        'control_id': control['control_id'],
        'implementation_status': control['implementation_status'],
        'evidence': control['evidence']
    }
    # Post to Archer API
```

**Custom Dashboard Integration:**
```javascript
// Load into compliance dashboard
fetch('nist-sp-800-53-controls-mapping.json')
  .then(response => response.json())
  .then(data => {
    console.log(`Implemented Controls: ${data.assessment_summary.total_controls_implemented}`);
    console.log(`Compliance Coverage: ${data.assessment_summary.implementation_coverage}`);
  });
```

### Automated Compliance Queries

```bash
# Find all Access Control implementations
jq '.controls[] | select(.control_family_abbreviation == "AC")' nist-sp-800-53-controls-mapping.json

# Extract evidence for specific control
jq '.controls[] | select(.control_id == "AU-3") | .evidence' nist-sp-800-53-controls-mapping.json

# Generate control implementation matrix
jq '.controls[] | {control_id, status: .implementation_status, file: .primary_file}' nist-sp-800-53-controls-mapping.json

# List all enhancement controls implemented
jq '.controls[] | select(has("enhancement_implemented")) | {control_id, enhancement: .enhancement_implemented}' nist-sp-800-53-controls-mapping.json
```

## Setup

1. **Install Dependencies**:
   ```sh
   pip install -r requirements.txt
   ```

2. **Configure API Keys**:
   Copy `local_config.example.py` to `local_config.py` and fill in your keys:
   ```python
   default_nvd_api_key="YOUR_NVD_KEY"
   default_openai_api_key="YOUR_OPENAI_KEY"
   default_alienvault_api_key="YOUR_ALIENVAULT_KEY"
   ```

3. **Run Application**:
   ```sh
   streamlit run main.py
   ```

## Usage

### Quick Start
1. **Launch the application**: `streamlit run main.py`
2. **Access the interface**: Navigate to `http://localhost:8501`
3. **Follow the 7-step process**:
   - **Step 1**: Describe your application (or upload architecture diagram)
   - **Step 2**: Select technology stack and versions
   - **Step 3**: Generate threat model with MITRE ATT&CK mapping
   - **Step 4**: Review security mitigations
   - **Step 5**: Conduct DREAD risk assessment
   - **Step 6**: Generate security test cases
   - **Step 7**: Export comprehensive PDF report

### Sample Output
- **Threat Model**: 18 STRIDE-based threats with MITRE ATT&CK mappings
- **Risk Assessment**: DREAD scores with prioritized recommendations
- **Test Cases**: Gherkin-formatted security test scenarios
- **PDF Report**: Comprehensive 20-40 page threat model document

### Example Workflow
The application guides you through a systematic threat modeling process:

1. **Application Description**: Provide detailed description or upload architecture diagrams
2. **Technology Selection**: Choose from 100+ technologies with version-specific vulnerability data
3. **Threat Generation**: AI analyzes your application against STRIDE methodology
4. **Intelligence Integration**: Automatic integration with MITRE ATT&CK, NVD, and OTX
5. **Risk Assessment**: DREAD methodology for threat prioritization
6. **Test Case Generation**: Automated security test scenarios in Gherkin format
7. **Report Generation**: Professional PDF with executive summary and technical details

## Troubleshooting

### Common Issues

**API Key Errors**
```bash
# Error: OpenAI API key is required
# Solution: Ensure API key is set in local_config.py or Streamlit secrets
echo 'default_openai_api_key="your-key-here"' >> local_config.py
```

**Missing MITRE Data**
```bash
# Error: No MITRE ATT&CK data found
# Solution: Ensure MITRE_ATTACK_DATA/ directory contains required JSON files
ls MITRE_ATTACK_DATA/  # Should show: enterprise-attack.json, mobile-attack.json, ics-attack.json
```

**Memory Issues with Large Models**
```bash
# Error: Out of memory during threat model generation
# Solution: Reduce concurrent processing or use batch processing
# Check available memory: free -h (Linux) or Activity Monitor (macOS)
```

**Port Already in Use**
```bash
# Error: Port 8501 is already in use
# Solution: Use different port or kill existing process
streamlit run main.py --server.port 8502
# Or kill existing: lsof -ti:8501 | xargs kill
```

### Performance Optimization
- **API Rate Limits**: Built-in exponential backoff for all external APIs
- **Memory Management**: Streaming JSON processing for large MITRE datasets
- **Caching Strategy**: No caching of sensitive data (security-first design)
- **Concurrent Processing**: Configurable worker threads for batch operations

### Debug Mode
```bash
# Run with debug logging
streamlit run main.py --logger.level debug

# Check log files
tail -f logs/error.log
```

## Contributing

### Development Setup
1. **Fork the repository**: Click "Fork" on the GitHub repository
2. **Clone your fork**: `git clone https://github.com/YOUR_USERNAME/AegisShield.git`
3. **Create a feature branch**: `git checkout -b feature/amazing-feature`
4. **Install development dependencies**: `pip install -r requirements.txt`
5. **Run tests**: `pytest --cov=.`
6. **Follow code quality standards**: `ruff check . && pylint *.py`

### Code Standards
- **Security First**: No sensitive data caching or logging
- **NIST Compliance**: All changes must maintain security control implementations
- **Testing**: Comprehensive test coverage for new features
- **Documentation**: Update both code comments and NIST control mappings when applicable
- **Type Hints**: Use Python type hints for all new code
- **Error Handling**: Use centralized error handling patterns

### Pull Request Process
1. **Update tests**: Ensure all tests pass and add tests for new features
2. **Update documentation**: Update NIST control documentation if security-relevant
3. **Code quality**: Run `ruff format .` and `pylint *.py`
4. **Security review**: Ensure no sensitive data in commits or logs
5. **Semantic commits**: Use conventional commit messages
6. **NIST compliance**: Verify security control implementations remain intact

### Development Guidelines
- **Streamlit patterns**: Follow established session state and UI patterns
- **API integration**: Use retry logic and proper error handling for external APIs
- **Threat intelligence**: Maintain data quality and validation for MITRE/NVD/OTX
- **Performance**: Consider memory usage for large dataset processing

## FAQ

### General Usage

**Q: What types of applications can I threat model with AegisShield?**
A: AegisShield supports web applications, mobile apps, desktop software, cloud services, IoT devices, ICS/SCADA systems, and AI/ML applications across all industries including finance, healthcare, government, and technology.

**Q: Do I need cybersecurity expertise to use AegisShield?**
A: No! AegisShield is designed to democratize threat modeling. The AI guides you through the process with minimal security knowledge required. However, security expertise helps in interpreting and implementing the recommendations.

**Q: How long does it take to generate a threat model?**
A: Typically 15-30 minutes for a complete threat model, depending on application complexity and API response times. The interactive interface allows you to work through steps at your own pace.

**Q: Can I use AegisShield for multiple applications?**
A: Yes! Each session generates a complete threat model for one application. You can run multiple sessions for different applications and compare results.

### Compliance & Enterprise

**Q: Is AegisShield suitable for federal environments?**
A: AegisShield implements 15 self-assessed NIST SP 800-53 Rev. 5 security controls with comprehensive audit trails and machine-readable mappings that support federal compliance programs. Note that FedRAMP authorization applies to cloud service offerings; AegisShield itself has not been through a formal authorization or third-party assessment.

**Q: Can I integrate AegisShield with existing GRC tools?**
A: Absolutely! The machine-readable JSON control mappings support ServiceNow, RSA Archer, and custom dashboard integrations. See the Enterprise Integration section for examples.

**Q: Does AegisShield store or transmit sensitive data?**
A: AegisShield follows a security-first design with no caching of sensitive threat model data. API keys are managed securely, and all processing is done locally or through encrypted API calls.

**Q: What compliance frameworks does AegisShield support?**
A: Primary alignment with NIST SP 800-53 Rev. 5, with control mappings that support FedRAMP and FISMA programs. The flexible architecture also supports HIPAA, GDPR, SOC 2, and other regulatory frameworks through customizable mappings.

### Technical

**Q: How does the AI-powered threat analysis work?**
A: AegisShield uses GPT-4o with carefully crafted prompts, combined with real-time threat intelligence from MITRE ATT&CK (tactics/techniques), NVD (vulnerabilities), and AlienVault OTX (industry threats). The AI applies STRIDE methodology for systematic threat identification.

**Q: What's the difference between main.py and main-batch.py?**
A: `main.py` is the interactive Streamlit interface for individual threat modeling sessions. `main-batch.py` is designed for research and bulk processing, allowing automated generation of multiple threat models for comparative analysis.

**Q: Can I customize the threat model templates?**
A: Yes! The prompts and validation logic can be customized. The modular architecture allows for easy extension of threat categories, risk assessment methods, and output formats.

**Q: What if an API service is unavailable?**
A: AegisShield includes comprehensive retry logic and graceful degradation. If MITRE ATT&CK is unavailable, it continues with NVD and OTX data. The system logs all issues and provides clear user feedback.

### Data & Security

**Q: Where is my threat model data stored?**
A: Threat models are stored locally in your session and exported as PDF reports. No sensitive application data is transmitted to external services except for the anonymized prompts sent to OpenAI for threat generation.

**Q: Can I run AegisShield in an air-gapped environment?**
A: Partially. The core threat modeling logic works offline, but you'll need internet access for OpenAI API, NVD, and OTX threat intelligence. Consider using cached threat intelligence data for air-gapped deployments.

**Q: How often is the threat intelligence data updated?**
A: MITRE ATT&CK data is loaded from local JSON files (update manually), NVD provides real-time vulnerability data, and OTX delivers current threat intelligence. We recommend updating MITRE data quarterly.

## Disclaimer

This project is not affiliated with or endorsed by MITRE, AlienVault, NIST, or any other organization mentioned.

- MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation
- AlienVault® is a registered trademark of 2024 LEVELBLUE, INC
- National Vulnerability Database (NVD) is a product of NIST
- NIST SP 800-53 Rev. 5 is a publication of the National Institute of Standards and Technology
- FedRAMP® is a registered trademark of the General Services Administration

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

## Acknowledgements

Portions of code adapted from Matt Adams' [stride-gpt](https://github.com/mrwadams/stride-gpt) under MIT license.

---

## Artifact Overview (Research Context)

AegisShield was created as part of praxis research aimed at democratizing threat modeling. Its effectiveness was empirically validated by comparing generated threat models against expert-developed models across diverse case studies.

### Batch Threat Model Generation (`main-batch.py`)

For research purposes, the `main-batch.py` script was developed to facilitate large-scale generation of threat models. It programmatically mimics the interactive UI-based workflow of AegisShield, enabling comprehensive data collection for research validation.

Specifically, it allowed researchers to:

- Automate the creation of multiple threat models for each case study.
- Generate **30 batches of threat models** across **15 distinct scenarios**.
- Systematically produce structured outputs for rigorous comparative analysis.

> **Note:** The `main-batch.py` script is included solely for research transparency and reproducibility; general users of AegisShield do not need to use this script.

### Research Definitions

- **Batch Inputs**: Structured JSON files containing detailed descriptions and parameters for each case study, replicating user input submitted through AegisShield's interactive UI.
- **Batch Outputs**: The resulting data set, consisting of **540 generated threat models**, each comprehensively documenting threats, assumptions, impacts, and corresponding MITRE ATT&CK data.
- **Case Studies**: Markdown files summarizing data systematically extracted from domain-diverse academic sources, structured to include application descriptions, inferred technical attributes, and rubric-based quality evaluations. These files were used to generate structured JSON batch inputs for threat modeling and provided the baseline for rigorous comparative analysis of AegisShield's performance.

## Compliance Documentation

AegisShield provides comprehensive compliance documentation for enterprise and federal environments:

### Security Control Documentation

| Document | Purpose | Format |
|----------|---------|--------|
| [`NIST-SP-800-53-CONTROLS.md`](NIST-SP-800-53-CONTROLS.md) | Human-readable control implementation guide | Markdown |
| [`nist-sp-800-53-controls-mapping.json`](nist-sp-800-53-controls-mapping.json) | Machine-readable control mappings for automation | JSON |

### Control Implementation Summary

- **Total Controls**: 15 NIST SP 800-53 Rev. 5 controls
- **Control Families**: 6 families (AC, IA, SC, SI, AU, RA, PM)
- **Implementation Coverage**: 100% of identified applicable controls
- **Enhancement Controls**: IA-5(1), SC-12(2) implemented
- **Compliance Frameworks**: Mappings support FedRAMP and FISMA programs

### Assessment and Auditing

All implemented controls include:
- **Traceability**: Direct code references and line numbers
- **Evidence**: Implementation artifacts and documentation
- **Assessment Methods**: Examine, Interview, Test methodologies
- **Responsible Roles**: Clear ownership and accountability

For compliance assessments, auditors can reference the machine-readable mappings to automatically extract evidence and verify control implementations.
