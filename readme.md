[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)  
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)  
[![codecov](https://codecov.io/gh/mgrofsky/AegisShield/branch/main/graph/badge.svg?token=FDBPY65ZYP)](https://codecov.io/gh/mgrofsky/AegisShield)  

### Coverage Overview
[![Coverage Sunburst](https://codecov.io/gh/mgrofsky/AegisShield/graphs/sunburst.svg?token=FDBPY65ZYP)](https://codecov.io/gh/mgrofsky/AegisShield)


# AegisShield Threat Modeler


![AegisShield](aegisshield.png)

AegisShield is a threat modeling tool designed to democratize the threat modeling process, making it more accessible and affordable. It leverages GPT-4o and integrates with multiple threat intelligence sources to provide comprehensive threat analysis.

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

## Technology Coverage

- **Application Types**: Web, mobile, desktop, cloud, IoT, ICS/SCADA, AI/ML systems, and more
- **Technology Stack**: Common databases, operating systems, programming languages, and web frameworks
- **Industry Support**: Finance, healthcare, government, technology, and others
- **Security & Compliance**: 
  - Authentication methods and compliance standards (HIPAA, GDPR, etc.)
  - Data sensitivity classification (High/Medium/Low)
  - Internet exposure assessment
  - Organization size categorization
  - Technical capability evaluation

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

## Setup

1. **Install Dependencies**:
   ```sh
   pip install -r requirements.txt
   ```

2. **Configure API Keys**:
   Create a `local_config.py` file with:
   ```python
   default_nvd_api_key="YOUR_NVD_KEY"
   default_openai_api_key="YOUR_OPENAI_KEY"
   default_alienvault_api_key="YOUR_ALIENVAULT_KEY"
   ```

3. **Run Application**:
   ```sh
   streamlit run main.py
   ```

## Disclaimer

This project is not affiliated with or endorsed by MITRE, AlienVault, NIST, or any other organization mentioned.

- MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation
- AlienVault® is a registered trademark of 2024 LEVELBLUE, INC
- National Vulnerability Database (NVD) is a product of NIST

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