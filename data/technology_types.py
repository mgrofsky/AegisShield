"""
Technology Type Definitions and CPE Mappings

Contains all option lists and CPE identifiers for the technology selection step.
Extracted from tabs/step2_technology.py for reuse and maintainability.
"""

# Application type options
APP_TYPE_OPTIONS = [
    "5G/Wireless System",
    "AI/ML Systems",
    "Blockchain and Cryptocurrency Systems",
    "Cloud application",
    "Cyber-Physical System (CPS)",
    "Desktop application",
    "Drone as a Service (DaaS) Application",
    "Embedded systems",
    "Fog Computing",
    "HPC System",
    "ICS or SCADA System",
    "Industrial Internet of Things (IIoT)",
    "IoT application",
    "Mobile application",
    "Messaging application",
    "Network application",
    "SaaS application",
    "Smart Grid Systems",
    "Vehicular Fog Computing (VFC)",
    "VoIP/Telephony System",
    "Wearable Devices",
    "Web application",
]

# Industry sector options
INDUSTRY_SECTOR_OPTIONS = [
    "Agriculture", "Aerospace", "Automotive", "Biotechnology", "Chemical",
    "Commercial", "Communications", "Construction", "Dams", "Defense",
    "Education", "Emergency", "Energy", "Entertainment", "Financial",
    "Food and Beverage", "Government", "Healthcare", "Hospitality",
    "Information Technology", "Logistics", "Manufacturing", "Marine",
    "Miscellaneous", "Nuclear", "Pharmaceuticals", "Retail",
    "Telecommunications", "Transportation", "Utilities", "Water",
]

# Data sensitivity options
DATA_SENSITIVITY_OPTIONS = ["High", "Medium", "Low", "None"]

# Internet facing options
INTERNET_FACING_OPTIONS = ["Yes", "No"]

# Number of employees options
NUM_EMPLOYEES_OPTIONS = ["Unknown", "0-10", "11-100", "101-1000", "Over 1000"]

# Compliance requirements options
COMPLIANCE_REQUIREMENTS_OPTIONS = [
    "3GPP TS 33.501", "HIPAA", "PCI DSS", "COPPA", "CCPA", "GDPR",
    "FAA Regulations", "FISMA", "SOX", "IEC 62443", "ISO 27001",
    "ISO/IEC 30141", "ISO/SAE 21434", "SOC 2", "FedRAMP", "GLBA",
    "FERPA", "FDA", "ISO 13485", "ITAR",
]

# Authentication methods options
AUTHENTICATION_OPTIONS = [
    "Active Directory (AD)", "API Key", "Basic", "Biometrics",
    "Firebase Authentication", "Hardware Tokens", "MFA",
    "Mutual TLS (mTLS)", "None", "OAUTH2", "Passwords", "Pins",
    "Public/Private Key Pairs", "SSO", "Smart Cards",
]

# Technology types with their CPE identifiers
TECHNOLOGY_TYPES: dict[str, dict[str, str]] = {
    "Databases": {
        "Google Firestore": "cpe:2.3:a:google:cloud_firestore:",
        "MySQL": "cpe:2.3:a:mysql:mysql:",
        "MS SQL Server": "cpe:2.3:a:microsoft:sql_server:",
        "Oracle Database": "cpe:2.3:a:oracle:database:",
        "PostgreSQL": "cpe:2.3:a:postgresql:postgresql:",
        "Scylla": "cpe:2.3:a:scylladb:scylla:",
        "Snowflake": "cpe:2.3:a:snowflake:snowflake:",
        "Redis": "cpe:2.3:a:redislabs:redis:",
    },
    "Operating Systems": {
        "Windows": "cpe:2.3:o:microsoft:windows:",
        "macOS": "cpe:2.3:o:apple:macos:",
        "CentOS": "cpe:2.3:o:centos:centos:",
        "Ubuntu": "cpe:2.3:o:canonical:ubuntu_linux:",
        "Debian": "cpe:2.3:o:debian:debian_linux:",
        "Fedora": "cpe:2.3:o:fedora:fedora:",
        "RHEL": "cpe:2.3:o:redhat:enterprise_linux:",
        "SUSE": "cpe:2.3:o:suse:suse_linux:",
        "Android": "cpe:2.3:o:google:android:",
        "iOS": "cpe:2.3:o:apple:iphone_os:",
        "iPadOS": "cpe:2.3:o:apple:ipados:",
        "tvOS": "cpe:2.3:o:apple:tvos:",
        "Linux Kernel": "cpe:2.3:o:linux:linux_kernel:",
        "Raspbian": "cpe:2.3:o:raspberrypi:raspbian:",
    },
    "Programming Languages": {
        "Python": "cpe:2.3:a:python:python:",
        "JavaScript": "cpe:2.3:a:ecmascript:ecmascript:",
        "Java": "cpe:2.3:a:oracle:jdk:",
        "C#": "cpe:2.3:a:microsoft:.net_framework:",
        "Go": "cpe:2.3:a:golang:go:",
        "Ruby": "cpe:2.3:a:ruby-lang:ruby:",
        "PHP": "cpe:2.3:a:php:php:",
        "Swift": "cpe:2.3:a:swift:swift:",
        "Kotlin": "cpe:2.3:a:jetbrains:kotlin:",
        "Dart": "cpe:2.3:a:dartlang:dart:",
        "Flutter": "cpe:2.3:a:google:flutter:",
    },
    "Web Frameworks": {
        "Django": "cpe:2.3:a:django:django:",
        "Flask": "cpe:2.3:a:palletsprojects:flask:",
        "React": "cpe:2.3:a:facebook:react:",
        "Angular": "cpe:2.3:a:google:angular:",
        "Vue.js": "cpe:2.3:a:vue:vue.js:",
        "Spring": "cpe:2.3:a:pivotal:spring_framework:",
        "Express": "cpe:2.3:a:expressjs:express:",
        "Laravel": "cpe:2.3:a:laravel:laravel:",
        "Ruby on Rails": "cpe:2.3:a:rubyonrails:ruby_on_rails:",
    },
}

# MITRE ATT&CK application type classifications
MOBILE_APP_TYPES = ["Mobile application", "5G/Wireless System"]

ENTERPRISE_APP_TYPES = [
    "Desktop application", "Web application", "SaaS application",
    "Cloud application", "Network application", "AI/ML Systems",
    "Blockchain and Cryptocurrency Systems", "Messaging application",
    "HPC System", "Drone as a Service (DaaS) Application",
    "VoIP/Telephony System",
]

ICS_APP_TYPES = [
    "ICS or SCADA System", "Smart Grid Systems",
    "Industrial Internet of Things (IIoT)", "Cyber-Physical System (CPS)",
    "Vehicular Fog Computing (VFC)", "Embedded systems",
    "IoT application", "Fog Computing", "Wearable Devices",
]
