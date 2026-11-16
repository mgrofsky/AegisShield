"""Option lists and fixed copy for the threat-model wizard.

The lists merge this repo's old Streamlit steps (``tabs/step2_technology.py``)
with a second, larger set of lists. Where both name the same thing, the
spelling and CPE prefix checked against the NVD dictionary are kept. Every
sector is an ordinary entry; nothing is selected for the visitor by default.

Strings that drive logic downstream keep the exact spelling the pipeline
expects: application types pick the ATT&CK mobile and ICS catalogs
(``catalog_service``) and, with the patterns, whether the application is an AI
system that gets MITRE ATLAS (``pipeline.ai_system``), pattern values match
``pattern_detection_service.supported_patterns()``, and each technology maps
to the CPE prefix ``workflow_service`` sends to NVD. Tests pin all three.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TypedDict

from aegisshield.pipeline import ai_system, schemas

__all__ = [
    "APP_TYPE_OPTIONS",
    "AUTHENTICATION_OPTIONS",
    "COMPLIANCE_OPTIONS",
    "DATA_SENSITIVITY_OPTIONS",
    "EXAMPLE_DESCRIPTION",
    "INDUSTRY_OPTIONS",
    "INTERNET_FACING_OPTIONS",
    "MAX_DESCRIPTION_CHARS",
    "MAX_DIAGRAM_TEXT_CHARS",
    "MAX_IMAGE_BYTES",
    "MAX_VERSION_CHARS",
    "MIN_DESCRIPTION_CHARS",
    "NUM_EMPLOYEES_OPTIONS",
    "PATTERN_OPTIONS",
    "TECHNICAL_ABILITY_OPTIONS",
    "TECHNOLOGY_CATALOG",
    "AI_PATTERNS",
    "PatternOption",
    "TechChoice",
    "TechEntry",
    "form_catalog",
    "technology_choices",
    "validate_version",
]

# The wizard asks for at least 50 characters so the model has enough to
# work with; the request model's own floor is lower (20).
MIN_DESCRIPTION_CHARS = 50
# The most the request accepts (pipeline.schemas), repeated here for the pages.
MAX_DESCRIPTION_CHARS = schemas.MAX_DESCRIPTION_CHARS
MAX_DIAGRAM_TEXT_CHARS = schemas.MAX_DIAGRAM_TEXT_CHARS
# A version is numbers and wildcards in at most four segments; no real one
# is longer than this.
MAX_VERSION_CHARS = 32

# Architecture image cap (PNG or JPEG, 10 MB).
MAX_IMAGE_BYTES = 10 * 1024 * 1024

# A general example the visitor can insert (an online retail checkout).
EXAMPLE_DESCRIPTION = (
    "An online checkout service for a mid-sized retailer. Shoppers browse the catalog in a "
    "React single-page app, sign in with email and password or a Google account, and pay "
    "by card through a third-party payment provider. A Python FastAPI backend stores "
    "orders and saved addresses in PostgreSQL and caches carts in Redis. Support staff use "
    "an internal admin site behind single sign-on to issue refunds. Everything runs in "
    "containers on a public cloud; data is encrypted in transit and at rest."
)

# The 31 general sectors from this repo's old Streamlit steps.
INDUSTRY_OPTIONS: tuple[str, ...] = (
    "Agriculture", "Aerospace", "Automotive", "Biotechnology", "Chemical",
    "Commercial", "Communications", "Construction", "Dams", "Defense",
    "Education", "Emergency", "Energy", "Entertainment", "Financial",
    "Food and Beverage", "Government", "Healthcare", "Hospitality",
    "Information Technology", "Logistics", "Manufacturing", "Marine",
    "Miscellaneous", "Nuclear", "Pharmaceuticals", "Retail",
    "Telecommunications", "Transportation", "Utilities", "Water",
)

DATA_SENSITIVITY_OPTIONS: tuple[str, ...] = ("High", "Medium", "Low", "None")
INTERNET_FACING_OPTIONS: tuple[str, ...] = ("Yes", "No")
NUM_EMPLOYEES_OPTIONS: tuple[str, ...] = ("Unknown", "0-10", "11-100", "101-1000", "Over 1000")
# ``AppProfile.technical_ability`` accepts exactly these three.
TECHNICAL_ABILITY_OPTIONS: tuple[str, ...] = ("Low", "Medium", "High")


@dataclass(frozen=True)
class PatternOption:
    """One architecture pattern toggle (sent as ``app_pattern``)."""

    value: str
    label: str
    description: str


PATTERN_OPTIONS: tuple[PatternOption, ...] = (
    PatternOption("GenAI", "Uses an LLM (GenAI)",
                  "Any chat, classification, or generation step backed by an LLM."),
    PatternOption("RAG", "Retrieval-augmented generation (RAG)",
                  "A vector store or retrieval step feeds the model's prompt."),
    PatternOption("Agentic", "Agentic or multi-step planning",
                  "Autonomous agents, multi-agent loops, or tool-driven planning."),
    PatternOption("Tool Use", "Tool or function calls",
                  "The model invokes tools, plugins, or MCP servers."),
    PatternOption("Code Execution", "Code execution sandbox",
                  "A code interpreter or sandboxed code-running tool."),
    PatternOption("ML", "Trains or serves an ML model",
                  "Custom-trained models, fine-tunes, or inference endpoints."),
)

# Patterns that make an application an AI system (one definition, in
# ``pipeline.ai_system``): ATLAS mapping, the ATLAS card, and the EU AI Act view.
AI_PATTERNS = ai_system.AI_PATTERNS


class _Cpe(TypedDict):
    cpe: str


class TechEntry(TypedDict, total=False):
    """A catalog entry: its CPE prefix and, for frameworks, common libraries."""

    cpe: str
    libraries: dict[str, _Cpe]


APP_TYPE_OPTIONS: tuple[str, ...] = (
    "5G/Wireless System",
    "AI/ML Systems",
    "API/Microservices",
    "AR/VR Application",
    "Autonomous Vehicle System",
    "Backend/Worker Service",
    "Blockchain and Cryptocurrency Systems",
    "CLI Tool",
    "Cloud application",
    "Container Platform",
    "Content Management System (CMS)",
    "Cyber-Physical System (CPS)",
    "Data Lake / Warehouse",
    "Data Pipeline / ETL",
    "Desktop application",
    "DevOps/CI-CD Tooling",
    "Drone as a Service (DaaS) Application",
    "E-commerce Platform",
    "Edge Computing System",
    "Embedded systems",
    "Federated Learning System",
    "Fog Computing",
    "Game Server / Gaming Platform",
    "GraphQL Service",
    "HPC System",
    "Healthcare/EHR System",
    "Identity / Access Management Service",
    "ICS or SCADA System",
    "Industrial Internet of Things (IIoT)",
    "IoT application",
    "Kubernetes Operator/Controller",
    "Machine Learning Inference Service",
    "Messaging application",
    "Mobile application",
    "Network application",
    "Observability/Logging Pipeline",
    "Payment Processing System",
    "Public-Sector / Government System",
    "Quantum Computing System",
    "Real-Time Streaming Platform",
    "Robotic Process Automation (RPA)",
    "SaaS application",
    "Search Service",
    "Serverless Application",
    "Smart Grid Systems",
    "Smart Home / Building Automation",
    "Vehicular Fog Computing (VFC)",
    "VoIP/Telephony System",
    "Wearable Devices",
    "Web application",
    "Web3 / DeFi Application",
)


COMPLIANCE_OPTIONS: tuple[str, ...] = (
    "3GPP TS 33.501",
    "23 NYCRR 500 (NYDFS)",
    "ASD Essential Eight (Australia)",
    "BSI C5 (Germany)",
    "CCPA",
    "CIS Controls v8",
    "CJIS Security Policy",
    "CMMC 2.0",
    "COPPA",
    "CPRA",
    "DORA (EU Digital Operational Resilience Act)",
    "EU AI Act",
    "FAA Regulations",
    "FDA 21 CFR Part 11",
    "FedRAMP",
    "FERPA",
    "FFIEC IT Handbook",
    "FIPS 140-3",
    "FISMA",
    "GDPR",
    "GLBA",
    "HIPAA",
    "HITRUST CSF",
    "IEC 62304 (Medical Device Software)",
    "IEC 62443",
    "IRS Publication 1075",
    "ISO 13485",
    "ISO 22301 (BCM)",
    "ISO 27001",
    "ISO 27017 (Cloud)",
    "ISO 27018 (Cloud PII)",
    "ISO 27701 (Privacy)",
    "ISO/IEC 30141",
    "ISO/SAE 21434",
    "ITAR",
    "LGPD (Brazil)",
    "MAS TRM (Singapore)",
    "MITRE ATT&CK Mapping",
    "NERC CIP",
    "NIS2 Directive (EU)",
    "NIST AI RMF",
    "NIST CSF 2.0",
    "NIST SP 800-171",
    "NIST SP 800-53 Rev. 5",
    "NIST SP 800-63 (Digital Identity)",
    "OWASP ASVS",
    "PCI DSS v4.0",
    "PIPEDA (Canada)",
    "PIPL (China)",
    "POPIA (South Africa)",
    "SOC 1",
    "SOC 2",
    "SOC 3",
    "SOX",
    "StateRAMP",
    "TISAX (Automotive)",
    "TX-RAMP",
    "UK Cyber Essentials Plus",
)


AUTHENTICATION_OPTIONS: tuple[str, ...] = (
    "Active Directory (AD)",
    "Apple Sign In",
    "API Key",
    "Auth0",
    "AWS Cognito",
    "AWS IAM Roles",
    "Azure AD / Entra ID",
    "Basic Authentication",
    "Biometrics (Face/Fingerprint)",
    "Certificate-Based Authentication",
    "CIBA (Client-Initiated Backchannel Auth)",
    "Device Authorization Grant",
    "Federated Identity (SAML)",
    "Firebase Authentication",
    "FIDO2 / WebAuthn",
    "GCP IAM / Workload Identity",
    "Google Sign In",
    "Hardware Tokens (YubiKey, etc.)",
    "JWT Bearer Tokens",
    "Kerberos",
    "Keycloak",
    "LDAP",
    "Magic Links",
    "MFA (TOTP / Push)",
    "Mutual TLS (mTLS)",
    "None",
    "OAuth 2.0",
    "OAuth 2.0 PKCE",
    "Okta",
    "OneLogin",
    "OpenID Connect (OIDC)",
    "Passkeys",
    "Passwords",
    "PINs",
    "Ping Identity",
    "Public/Private Key Pairs",
    "RADIUS",
    "Risk-Based / Adaptive Authentication",
    "SCIM (Provisioning)",
    "Service Account Keys",
    "Single Sign-On (SSO)",
    "Smart Cards / PIV / CAC",
    "SMS One-Time Password (OTP)",
    "Social Login",
    "Step-Up Authentication",
    "TACACS+",
    "Token Exchange (RFC 8693)",
)


TECHNOLOGY_CATALOG: dict[str, dict[str, TechEntry]] = {
    "Databases": {
        "MySQL": {"cpe": "cpe:2.3:a:oracle:mysql:"},
        "MariaDB": {"cpe": "cpe:2.3:a:mariadb:mariadb:"},
        "PostgreSQL": {"cpe": "cpe:2.3:a:postgresql:postgresql:"},
        "MS SQL Server": {"cpe": "cpe:2.3:a:microsoft:sql_server:"},
        "Oracle Database": {"cpe": "cpe:2.3:a:oracle:database_server:"},
        "MongoDB": {"cpe": "cpe:2.3:a:mongodb:mongodb:"},
        "Redis": {"cpe": "cpe:2.3:a:redis:redis:"},
        "Memcached": {"cpe": "cpe:2.3:a:memcached:memcached:"},
        "SQLite": {"cpe": "cpe:2.3:a:sqlite:sqlite:"},
        "Elasticsearch": {"cpe": "cpe:2.3:a:elastic:elasticsearch:"},
        "OpenSearch": {"cpe": "cpe:2.3:a:amazon:opensearch:"},
        "Cassandra": {"cpe": "cpe:2.3:a:apache:cassandra:"},
        "Scylla": {"cpe": "cpe:2.3:a:scylladb:scylla:"},
        "CouchDB": {"cpe": "cpe:2.3:a:apache:couchdb:"},
        "Couchbase": {"cpe": "cpe:2.3:a:couchbase:couchbase_server:"},
        "Neo4j": {"cpe": "cpe:2.3:a:neo4j:neo4j:"},
        "InfluxDB": {"cpe": "cpe:2.3:a:influxdata:influxdb:"},
        "ClickHouse": {"cpe": "cpe:2.3:a:clickhouse:clickhouse:"},
        "Snowflake (JDBC driver)": {"cpe": "cpe:2.3:a:snowflake:snowflake_jdbc:"},
        "Google Firestore": {"cpe": "cpe:2.3:a:google:cloud_firestore:"},
        "DB2": {"cpe": "cpe:2.3:a:ibm:db2:"},
        "Sybase ASE": {"cpe": "cpe:2.3:a:sap:adaptive_server_enterprise:"},
        "Firebird": {"cpe": "cpe:2.3:a:firebirdsql:firebird:"},
        "ArangoDB": {"cpe": "cpe:2.3:a:arangodb:arangodb:"},
        "TimescaleDB": {"cpe": "cpe:2.3:a:timescale:timescaledb:"},
        "etcd": {"cpe": "cpe:2.3:a:etcd:etcd:"},
    },
    "Operating Systems": {
        "Windows": {"cpe": "cpe:2.3:o:microsoft:windows:"},
        "Windows Server": {"cpe": "cpe:2.3:o:microsoft:windows_server:"},
        "macOS": {"cpe": "cpe:2.3:o:apple:macos:"},
        "iOS": {"cpe": "cpe:2.3:o:apple:iphone_os:"},
        "iPadOS": {"cpe": "cpe:2.3:o:apple:ipados:"},
        "tvOS": {"cpe": "cpe:2.3:o:apple:tvos:"},
        "watchOS": {"cpe": "cpe:2.3:o:apple:watchos:"},
        "Android": {"cpe": "cpe:2.3:o:google:android:"},
        "ChromeOS": {"cpe": "cpe:2.3:o:google:chrome_os:"},
        "Linux Kernel": {"cpe": "cpe:2.3:o:linux:linux_kernel:"},
        "Ubuntu": {"cpe": "cpe:2.3:o:canonical:ubuntu_linux:"},
        "Debian": {"cpe": "cpe:2.3:o:debian:debian_linux:"},
        "Fedora": {"cpe": "cpe:2.3:o:fedoraproject:fedora:"},
        "RHEL": {"cpe": "cpe:2.3:o:redhat:enterprise_linux:"},
        "CentOS": {"cpe": "cpe:2.3:o:centos:centos:"},
        "AlmaLinux": {"cpe": "cpe:2.3:o:almalinux:almalinux:"},
        "Rocky Linux": {"cpe": "cpe:2.3:o:rockylinux:rocky_linux:"},
        "openSUSE Leap": {"cpe": "cpe:2.3:o:opensuse:leap:"},
        "SUSE Linux Enterprise": {"cpe": "cpe:2.3:o:suse:linux_enterprise_server:"},
        "Amazon Linux": {"cpe": "cpe:2.3:o:amazon:amazon_linux:"},
        "Amazon Linux 2": {"cpe": "cpe:2.3:o:amazon:amazon_linux:"},
        "Oracle Linux": {"cpe": "cpe:2.3:o:oracle:linux:"},
        "Alpine Linux": {"cpe": "cpe:2.3:o:alpinelinux:alpine_linux:"},
        "Arch Linux": {"cpe": "cpe:2.3:o:archlinux:arch_linux:"},
        "Gentoo": {"cpe": "cpe:2.3:o:gentoo:linux:"},
        "FreeBSD": {"cpe": "cpe:2.3:o:freebsd:freebsd:"},
        "OpenBSD": {"cpe": "cpe:2.3:o:openbsd:openbsd:"},
        "NetBSD": {"cpe": "cpe:2.3:o:netbsd:netbsd:"},
        "Solaris": {"cpe": "cpe:2.3:o:oracle:solaris:"},
        "AIX": {"cpe": "cpe:2.3:o:ibm:aix:"},
        "HP-UX": {"cpe": "cpe:2.3:o:hp:hp-ux:"},
        "VxWorks": {"cpe": "cpe:2.3:o:windriver:vxworks:"},
        "FreeRTOS": {"cpe": "cpe:2.3:o:amazon:freertos:"},
    },
    "Programming Languages": {
        "Python": {"cpe": "cpe:2.3:a:python:python:"},
        "Node.js": {"cpe": "cpe:2.3:a:nodejs:node.js:"},
        "Java (OpenJDK)": {"cpe": "cpe:2.3:a:oracle:openjdk:"},
        "Java (Oracle JDK)": {"cpe": "cpe:2.3:a:oracle:jdk:"},
        "Java (JRE)": {"cpe": "cpe:2.3:a:oracle:jre:"},
        ".NET": {"cpe": "cpe:2.3:a:microsoft:.net:"},
        ".NET Framework": {"cpe": "cpe:2.3:a:microsoft:.net_framework:"},
        ".NET Core": {"cpe": "cpe:2.3:a:microsoft:.net_core:"},
        "Go": {"cpe": "cpe:2.3:a:golang:go:"},
        "Rust": {"cpe": "cpe:2.3:a:rust-lang:rust:"},
        "Ruby": {"cpe": "cpe:2.3:a:ruby-lang:ruby:"},
        "PHP": {"cpe": "cpe:2.3:a:php:php:"},
        "Perl": {"cpe": "cpe:2.3:a:perl:perl:"},
        "Swift": {"cpe": "cpe:2.3:a:apple:swift:"},
        "Kotlin": {"cpe": "cpe:2.3:a:jetbrains:kotlin:"},
        "Scala": {"cpe": "cpe:2.3:a:scala-lang:scala:"},
        "Erlang/OTP": {"cpe": "cpe:2.3:a:erlang:erlang\\/otp:"},
        "Lua": {"cpe": "cpe:2.3:a:lua:lua:"},
        "R": {"cpe": "cpe:2.3:a:r-project:r:"},
        "Dart": {"cpe": "cpe:2.3:a:dart:dart_software_development_kit:"},
        "TypeScript": {"cpe": "cpe:2.3:a:microsoft:typescript:"},
        "Julia": {"cpe": "cpe:2.3:a:julialang:julia:"},
    },
    "Web Frameworks": {
        "Django": {
            "cpe": "cpe:2.3:a:djangoproject:django:",
            "libraries": {
                "Celery": {"cpe": "cpe:2.3:a:celeryproject:celery:"},
                "Gunicorn": {"cpe": "cpe:2.3:a:gunicorn:gunicorn:"},
                "Pillow": {"cpe": "cpe:2.3:a:python:pillow:"},
                "Requests": {"cpe": "cpe:2.3:a:python-requests:requests:"},
                "SQLAlchemy": {"cpe": "cpe:2.3:a:sqlalchemy:sqlalchemy:"},
            },
        },
        "Flask": {
            "cpe": "cpe:2.3:a:palletsprojects:flask:",
            "libraries": {
                "Werkzeug": {"cpe": "cpe:2.3:a:palletsprojects:werkzeug:"},
                "Jinja2": {"cpe": "cpe:2.3:a:palletsprojects:jinja:"},
                "Flask-CORS": {"cpe": "cpe:2.3:a:flask-cors_project:flask-cors:"},
                "Flask-AppBuilder": {"cpe": "cpe:2.3:a:dpgaspar:flask-appbuilder:"},
                "Gunicorn": {"cpe": "cpe:2.3:a:gunicorn:gunicorn:"},
                "SQLAlchemy": {"cpe": "cpe:2.3:a:sqlalchemy:sqlalchemy:"},
                "Pillow": {"cpe": "cpe:2.3:a:python:pillow:"},
                "Requests": {"cpe": "cpe:2.3:a:python-requests:requests:"},
            },
        },
        "FastAPI": {
            "cpe": "cpe:2.3:a:tiangolo:fastapi:",
            "libraries": {
                "Starlette": {"cpe": "cpe:2.3:a:encode:starlette:"},
                "Uvicorn": {"cpe": "cpe:2.3:a:encode:uvicorn:"},
                "Pydantic": {"cpe": "cpe:2.3:a:pydantic:pydantic:"},
                "SQLAlchemy": {"cpe": "cpe:2.3:a:sqlalchemy:sqlalchemy:"},
                "Requests": {"cpe": "cpe:2.3:a:python-requests:requests:"},
            },
        },
        "Tornado": {"cpe": "cpe:2.3:a:tornadoweb:tornado:"},
        "Bottle": {"cpe": "cpe:2.3:a:bottlepy:bottle:"},
        "Pyramid": {"cpe": "cpe:2.3:a:agendaless:pyramid:"},
        "Express": {
            "cpe": "cpe:2.3:a:openjsf:express:",
            "libraries": {
                "jsonwebtoken": {"cpe": "cpe:2.3:a:auth0:jsonwebtoken:"},
                "lodash": {"cpe": "cpe:2.3:a:lodash:lodash:"},
                "axios": {"cpe": "cpe:2.3:a:axios:axios:"},
            },
        },
        "Koa": {"cpe": "cpe:2.3:a:koajs:koa:"},
        "NestJS": {"cpe": "cpe:2.3:a:nestjs:nest:"},
        "Hapi": {"cpe": "cpe:2.3:a:hapijs:hapi:"},
        "Next.js": {"cpe": "cpe:2.3:a:vercel:next.js:"},
        "Nuxt": {"cpe": "cpe:2.3:a:nuxt:nuxt:"},
        "React": {
            "cpe": "cpe:2.3:a:facebook:react:",
            "libraries": {
                "Next.js": {"cpe": "cpe:2.3:a:vercel:next.js:"},
                "axios": {"cpe": "cpe:2.3:a:axios:axios:"},
                "lodash": {"cpe": "cpe:2.3:a:lodash:lodash:"},
            },
        },
        "Angular (legacy AngularJS)": {"cpe": "cpe:2.3:a:angularjs:angular.js:"},
        "Vue.js": {"cpe": "cpe:2.3:a:vuejs:vue.js:"},
        "Svelte": {"cpe": "cpe:2.3:a:svelte:svelte:"},
        "SvelteKit": {"cpe": "cpe:2.3:a:svelte:sveltekit:"},
        "Spring Framework": {
            "cpe": "cpe:2.3:a:vmware:spring_framework:",
            "libraries": {
                "Spring Boot": {"cpe": "cpe:2.3:a:vmware:spring_boot:"},
                "Spring Security": {"cpe": "cpe:2.3:a:vmware:spring_security:"},
                "Hibernate ORM": {"cpe": "cpe:2.3:a:hibernate:hibernate_orm:"},
                "Log4j": {"cpe": "cpe:2.3:a:apache:log4j:"},
                "Logback": {"cpe": "cpe:2.3:a:logback:logback:"},
                "Jackson Databind": {"cpe": "cpe:2.3:a:fasterxml:jackson-databind:"},
            },
        },
        "Spring Boot": {"cpe": "cpe:2.3:a:vmware:spring_boot:"},
        "Quarkus": {"cpe": "cpe:2.3:a:quarkus:quarkus:"},
        "Struts": {"cpe": "cpe:2.3:a:apache:struts:"},
        "Tomcat": {"cpe": "cpe:2.3:a:apache:tomcat:"},
        "Jetty": {"cpe": "cpe:2.3:a:eclipse:jetty:"},
        "ASP.NET": {"cpe": "cpe:2.3:a:microsoft:asp.net:"},
        "ASP.NET Core (incl. Blazor)": {"cpe": "cpe:2.3:a:microsoft:asp.net_core:"},
        "Laravel": {
            "cpe": "cpe:2.3:a:laravel:laravel:",
            "libraries": {
                "Symfony": {"cpe": "cpe:2.3:a:sensiolabs:symfony:"},
                "Twig": {"cpe": "cpe:2.3:a:symfony:twig:"},
                "Guzzle": {"cpe": "cpe:2.3:a:guzzlephp:guzzle:"},
            },
        },
        "Symfony": {
            "cpe": "cpe:2.3:a:sensiolabs:symfony:",
            "libraries": {
                "Twig": {"cpe": "cpe:2.3:a:symfony:twig:"},
            },
        },
        "CodeIgniter": {"cpe": "cpe:2.3:a:codeigniter:codeigniter:"},
        "CakePHP": {"cpe": "cpe:2.3:a:cakefoundation:cakephp:"},
        "Yii": {"cpe": "cpe:2.3:a:yiiframework:yii:"},
        "WordPress": {"cpe": "cpe:2.3:a:wordpress:wordpress:"},
        "Drupal": {"cpe": "cpe:2.3:a:drupal:drupal:"},
        "Joomla": {"cpe": "cpe:2.3:a:joomla:joomla\\!:"},
        "Magento": {"cpe": "cpe:2.3:a:magento:magento:"},
        "Ruby on Rails": {
            "cpe": "cpe:2.3:a:rubyonrails:rails:",
            "libraries": {
                "Devise": {"cpe": "cpe:2.3:a:plataformatec:devise:"},
                "Sidekiq": {"cpe": "cpe:2.3:a:contribsys:sidekiq:"},
                "Nokogiri": {"cpe": "cpe:2.3:a:nokogiri:nokogiri:"},
                "Puma": {"cpe": "cpe:2.3:a:puma:puma:"},
                "Rack": {"cpe": "cpe:2.3:a:rack_project:rack:"},
            },
        },
        "Sinatra": {"cpe": "cpe:2.3:a:sinatrarb:sinatra:"},
        "Phoenix (Elixir)": {"cpe": "cpe:2.3:a:phoenixframework:phoenix:"},
        "Gin (Go)": {"cpe": "cpe:2.3:a:gin-gonic:gin:"},
        "Echo (Go)": {"cpe": "cpe:2.3:a:labstack:echo:"},
        "Fiber (Go)": {"cpe": "cpe:2.3:a:gofiber:fiber:"},
        "Actix Web (Rust)": {"cpe": "cpe:2.3:a:actix:actix-web:"},
        "Rocket (Rust)": {"cpe": "cpe:2.3:a:rocket:rocket:"},
        "jQuery": {"cpe": "cpe:2.3:a:jquery:jquery:"},
        "Bootstrap": {"cpe": "cpe:2.3:a:getbootstrap:bootstrap:"},
    },
    "Web Servers": {
        "Apache HTTP Server": {"cpe": "cpe:2.3:a:apache:http_server:"},
        "nginx": {"cpe": "cpe:2.3:a:f5:nginx:"},
        "Microsoft IIS": {"cpe": "cpe:2.3:a:microsoft:internet_information_services:"},
        "OpenSSL": {"cpe": "cpe:2.3:a:openssl:openssl:"},
    },
}

_VERSION_RE = re.compile(r"^(\d+|\*)(\.(\d+|\*))*$")
_MAX_VERSION_SEGMENTS = 4


@dataclass(frozen=True)
class TechChoice:
    """One selectable technology: a catalog entry or a framework's library."""

    category: str
    name: str
    cpe: str
    parent: str | None = None

    @property
    def key(self) -> str:
        """A stable id, unique even when two frameworks list the same library."""
        parts = [self.category, self.parent or "", self.name]
        return re.sub(r"[^A-Za-z0-9]+", "_", "__".join(parts)).strip("_")


def technology_choices() -> Iterator[TechChoice]:
    """Every catalog entry and library, in catalog order."""
    for category, items in TECHNOLOGY_CATALOG.items():
        for name, entry in items.items():
            yield TechChoice(category, name, entry["cpe"])
            for lib, lib_entry in entry.get("libraries", {}).items():
                yield TechChoice(category, lib, lib_entry["cpe"], parent=name)


def form_catalog() -> dict[str, dict[str, TechEntry]]:
    """The catalog in the shape ``vuln_lookup.prefill_from_lookup`` reads."""
    return TECHNOLOGY_CATALOG


def validate_version(version: str) -> str | None:
    """None when ``version`` is acceptable, else the sentence to show.

    Empty is fine (it means any version); otherwise numbers or ``*``
    separated by dots, at most four segments.
    """
    text = (version or "").strip()
    if not text:
        return None
    if len(text) > MAX_VERSION_CHARS:
        return f"Version should be at most {MAX_VERSION_CHARS} characters."
    if not _VERSION_RE.match(text):
        return ("Version should be numbers or wildcards separated by dots "
                "(for example: 1.2.3, 1.2.*, 1.*, *).")
    if len(text.split(".")) > _MAX_VERSION_SEGMENTS:
        return "Version should not have more than 4 segments."
    return None
