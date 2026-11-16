"""Built-in policy catalog: a SOC 2 / NIST CSF 2.0 baseline for any organization.

Six general policies, plus general entries where those six leave a gap:

- sensitive data handling (minimum necessary use, de-identification,
  approved channels, access logs);
- breach notification, written for any regime;
- connected device and operational technology security (inventory,
  segmentation, unpatchable equipment).

There is no business associate policy, because the vendor management policy
already covers third-party contracts and oversight. The catalog is not tied
to any one sector.

Each entry has:
  key                   matches the ``policy_key`` stored with a policy
  title                 document title
  summary               one line shown in the catalog picker
  csf_baseline          NIST CSF 2.0 category ids the policy addresses
  prompt_outline        section headings and guidance sent to the model
  citations_by_driver   citations per compliance driver. Kept internal:
                        ``get_catalog`` and ``get_entry`` leave it out, and
                        ``citations_for`` returns only the drivers an
                        organization selected, so nothing regime-specific
                        appears by default

Citations name the framework's own clause or requirement numbers. The
framework names here are selectable compliance drivers, not defaults.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterable
from typing import Any

CATALOG: list[dict[str, Any]] = [
    {
        "key": "information_security_policy",
        "title": "Information Security Policy",
        "summary": "Top-level governance charter establishing the security program, executive accountability, and program oversight.",
        "csf_baseline": ["GV.OC", "GV.RM", "GV.RR", "GV.PO", "GV.OV", "ID.IM"],
        "citations_by_driver": {
            "SOC 2": ["TSC CC1.1-CC1.5 Control environment", "TSC CC5.3 Policies and procedures"],
            "ISO 27001": [
                "ISO/IEC 27001:2022 clause 5.2 Information security policy",
                "ISO/IEC 27001:2022 Annex A 5.1 Policies for information security",
            ],
            "PCI DSS": ["PCI DSS v4.0.1 Requirement 12.1 Information security policy"],
            "GDPR": [
                "GDPR Art. 24 Responsibility of the controller",
                "GDPR Art. 32 Security of processing",
            ],
            "HIPAA": [
                "45 CFR 164.308(a)(2) Assigned security responsibility",
                "45 CFR 164.316 Policies and procedures and documentation requirements",
            ],
            "CCPA": ["Cal. Civ. Code 1798.100(e) Reasonable security procedures"],
            "FedRAMP": ["NIST SP 800-53 Rev. 5 PL control family and the policy and procedures control of each family (FedRAMP baseline)"],
        },
        "prompt_outline": """
Write a formal Information Security Policy for {legal_name} (doing business as {dba_name}).
Industry: {industry}. Leadership: {leadership_text}.
Compliance drivers: {compliance_drivers}.
{regulatory_notes}

The document must include these sections, in order:
1. Purpose - Why this policy exists; tie it to the organization's mission and to NIST CSF 2.0 Govern (GV) function.
2. Scope - Who and what is covered (all employees, contractors, systems, data).
3. Roles & Responsibilities - Name the {ciso_or_exec} as policy owner; list specific duties for IT, HR, and department managers.
4. Policy Statements - 8-12 clear, enforceable statements covering: executive commitment, annual risk assessment, security awareness training, acceptable use, data classification, incident reporting obligation, third-party oversight, and continuous improvement.
5. Enforcement - Disciplinary actions for non-compliance.
6. Review Cadence - Annual review; immediate update on material change or incident.
7. Approvals - Signature block for {ceo_or_exec} and {ciso_or_exec} with effective date.

Frame all controls as a path to SOC 2 Type II and NIST CSF 2.0 compliance.
Use formal, plain-English language suitable for a {employee_count}-person {industry} organization.
Output clean Markdown only (no preamble, no code fences).
""",
    },
    {
        "key": "access_control_policy",
        "title": "Access Control Policy",
        "summary": "Identity, least-privilege, MFA, and access lifecycle controls mapped to NIST CSF PR.AA.",
        "csf_baseline": ["PR.AA", "GV.PO", "DE.CM", "ID.IM"],
        "citations_by_driver": {
            "SOC 2": ["TSC CC6.1-CC6.3 Logical access"],
            "ISO 27001": [
                "ISO/IEC 27001:2022 Annex A 5.15 Access control",
                "ISO/IEC 27001:2022 Annex A 5.18 Access rights",
                "ISO/IEC 27001:2022 Annex A 8.2 Privileged access rights",
                "ISO/IEC 27001:2022 Annex A 8.5 Secure authentication",
            ],
            "PCI DSS": [
                "PCI DSS v4.0.1 Requirement 7 Restrict access to system components and cardholder data by business need to know",
                "PCI DSS v4.0.1 Requirement 8 Identify users and authenticate access",
            ],
            "GDPR": ["GDPR Art. 32 Security of processing"],
            "HIPAA": [
                "45 CFR 164.308(a)(4) Information access management",
                "45 CFR 164.312(a) Access control",
                "45 CFR 164.312(d) Person or entity authentication",
            ],
            "FedRAMP": ["NIST SP 800-53 Rev. 5 AC and IA control families (FedRAMP baseline)"],
        },
        "prompt_outline": """
Write a formal Access Control Policy for {legal_name}.
Industry: {industry}. Leadership: {leadership_text}.
Compliance drivers: {compliance_drivers}.
{regulatory_notes}

Sections:
1. Purpose - Protect systems and data via identity verification and least privilege; reference NIST CSF 2.0 PR.AA.
2. Scope - All user accounts, service accounts, privileged access, and remote access.
3. Roles & Responsibilities - {ciso_or_exec} owns; IT/DevOps implements; managers approve access requests.
4. Policy Statements covering:
   a. Unique account per individual; no shared credentials.
   b. Role-based access control (RBAC); least privilege.
   c. Multi-factor authentication (MFA) required for all remote access and privileged accounts.
   d. Access provisioning and de-provisioning within defined SLAs (e.g. same-day offboarding).
   e. Quarterly access reviews for privileged accounts; annual for general users.
   f. Password complexity, rotation, and prohibited reuse.
   g. Privileged Access Management (PAM) for admin credentials.
   h. Session timeout and automatic screen lock.
5. Enforcement.
6. Review Cadence - Annual or after material access-control incident.
7. Approvals - {ceo_or_exec} and {ciso_or_exec}.

Frame as a path to SOC 2 CC6.x and NIST CSF 2.0 PR.AA.
Output clean Markdown only.
""",
    },
    {
        "key": "data_protection_policy",
        "title": "Data Protection Policy",
        "summary": "Data classification, encryption at rest and in transit, retention, and disposal mapped to NIST CSF PR.DS.",
        "csf_baseline": ["PR.DS", "PR.PS", "GV.PO", "ID.AM", "DE.CM"],
        "citations_by_driver": {
            "SOC 2": ["TSC C1.1-C1.2 Confidentiality", "TSC CC6.7 Transmission of information"],
            "ISO 27001": [
                "ISO/IEC 27001:2022 Annex A 5.12 Classification of information",
                "ISO/IEC 27001:2022 Annex A 8.10 Information deletion",
                "ISO/IEC 27001:2022 Annex A 8.13 Information backup",
                "ISO/IEC 27001:2022 Annex A 8.24 Use of cryptography",
            ],
            "PCI DSS": [
                "PCI DSS v4.0.1 Requirement 3 Protect stored account data",
                "PCI DSS v4.0.1 Requirement 4 Protect cardholder data with strong cryptography during transmission over open, public networks",
            ],
            "GDPR": [
                "GDPR Art. 5 Principles relating to processing of personal data",
                "GDPR Art. 25 Data protection by design and by default",
                "GDPR Art. 32 Security of processing",
            ],
            "HIPAA": [
                "45 CFR 164.310(d) Device and media controls",
                "45 CFR 164.312(a)(2)(iv) Encryption and decryption",
                "45 CFR 164.312(e) Transmission security",
            ],
            "CCPA": ["Cal. Civ. Code 1798.100(e) Reasonable security procedures"],
            "FedRAMP": ["NIST SP 800-53 Rev. 5 SC and MP control families (FedRAMP baseline)"],
        },
        "prompt_outline": """
Write a formal Data Protection Policy for {legal_name}.
Industry: {industry}. Leadership: {leadership_text}.
Compliance drivers: {compliance_drivers}.
{regulatory_notes}

Sections:
1. Purpose - Protect the confidentiality, integrity, and availability of {legal_name} data assets; reference NIST CSF 2.0 PR.DS.
2. Scope - All data created, processed, stored, or transmitted by {legal_name} employees, contractors, and systems.
3. Data Classification - Define tiers (e.g. Public, Internal, Confidential, Restricted) with handling requirements for each.
4. Roles & Responsibilities - {ciso_or_exec} or designated Data Protection Officer owns; data owners classify; IT enforces controls.
5. Policy Statements covering:
   a. Encryption in transit (TLS 1.2+) and at rest (AES-256 or equivalent) for Confidential and Restricted data.
   b. Data minimization and purpose limitation.
   c. Retention schedules aligned to {compliance_drivers} requirements.
   d. Secure disposal (cryptographic erasure, physical destruction).
   e. Backup and recovery requirements.
   f. Data loss prevention (DLP) controls.
   g. Privacy by design for new systems handling personal data.
6. Enforcement.
7. Review Cadence.
8. Approvals - {ceo_or_exec} and {ciso_or_exec}.

Frame as a path to SOC 2 CC9 / NIST CSF 2.0 PR.DS.
Output clean Markdown only.
""",
    },
    {
        "key": "incident_response_policy",
        "title": "Incident Response Policy",
        "summary": "Detection, containment, eradication, and recovery procedures mapped to NIST CSF RS and RC functions.",
        "csf_baseline": ["RS.MA", "RS.AN", "RS.CO", "RS.MI", "RC.RP", "RC.CO", "DE.AE", "DE.CM"],
        "citations_by_driver": {
            "SOC 2": ["TSC CC7.3-CC7.5 Security incident evaluation, response, and recovery"],
            "ISO 27001": [
                "ISO/IEC 27001:2022 Annex A 5.24-5.28 Information security incident management",
                "ISO/IEC 27001:2022 Annex A 6.8 Information security event reporting",
            ],
            "PCI DSS": ["PCI DSS v4.0.1 Requirement 12.10 Incident response"],
            "GDPR": ["GDPR Art. 33 Notification of a personal data breach to the supervisory authority"],
            "HIPAA": [
                "45 CFR 164.308(a)(6) Security incident procedures",
                "45 CFR 164.308(a)(7) Contingency plan (recovery)",
            ],
            "FedRAMP": ["NIST SP 800-53 Rev. 5 IR control family (FedRAMP baseline)"],
        },
        "prompt_outline": """
Write a formal Incident Response Policy for {legal_name}.
Industry: {industry}. Leadership: {leadership_text}.
Compliance drivers: {compliance_drivers}.
{regulatory_notes}

Sections:
1. Purpose - Establish a structured capability to detect, contain, eradicate, and recover from cybersecurity incidents; reference NIST CSF 2.0 RS and RC functions.
2. Scope - All information systems, personnel, and third parties operating on behalf of {legal_name}.
3. Definitions - Incident vs. event; severity tiers (Critical, High, Medium, Low).
4. Roles & Responsibilities - Incident Response Team (IRT) composition; name {ciso_or_exec} as IRT lead; escalation to {ceo_or_exec} for Critical.
5. Incident Response Phases:
   a. Preparation - Training, runbooks, communication channels, legal/PR contacts.
   b. Detection & Analysis - SIEM/logging, IOC identification, severity classification.
   c. Containment - Short-term and long-term containment strategies.
   d. Eradication - Root-cause removal, patching.
   e. Recovery - Service restoration, validation, monitoring.
   f. Post-Incident Review - Within 14 days; lessons-learned documentation.
6. Communication & Notification - Internal escalation timelines; regulatory notification obligations under {compliance_drivers}.
7. Evidence Preservation - Chain-of-custody requirements.
8. Enforcement.
9. Review Cadence - Annual tabletop exercise; policy updated within 30 days of any Major incident.
10. Approvals - {ceo_or_exec} and {ciso_or_exec}.

Output clean Markdown only.
""",
    },
    {
        "key": "risk_management_policy",
        "title": "Risk Management Policy",
        "summary": "Risk assessment cadence, risk register, treatment options, and executive risk acceptance mapped to NIST CSF ID.RA and GV.RM.",
        "csf_baseline": ["ID.RA", "GV.RM", "GV.OV", "ID.IM", "GV.PO"],
        "citations_by_driver": {
            "SOC 2": ["TSC CC3.1-CC3.4 Risk assessment", "TSC CC9.1 Risk mitigation (business disruption)"],
            "ISO 27001": [
                "ISO/IEC 27001:2022 clause 6.1.2 Information security risk assessment",
                "ISO/IEC 27001:2022 clause 6.1.3 Information security risk treatment",
            ],
            "PCI DSS": ["PCI DSS v4.0.1 Requirement 12.3 Risks to the cardholder data environment are formally identified, evaluated, and managed"],
            "GDPR": [
                "GDPR Art. 32 Security of processing",
                "GDPR Art. 35 Data protection impact assessment",
            ],
            "HIPAA": [
                "45 CFR 164.308(a)(1)(ii)(A) Risk analysis",
                "45 CFR 164.308(a)(1)(ii)(B) Risk management",
            ],
            "FedRAMP": ["NIST SP 800-53 Rev. 5 RA control family (FedRAMP baseline)"],
        },
        "prompt_outline": """
Write a formal Risk Management Policy for {legal_name}.
Industry: {industry}. Leadership: {leadership_text}.
Compliance drivers: {compliance_drivers}.
{regulatory_notes}

Sections:
1. Purpose - Define how {legal_name} identifies, analyzes, evaluates, and treats cybersecurity risk; reference NIST CSF 2.0 ID.RA and GV.RM.
2. Scope - All technology assets, processes, and third parties.
3. Risk Management Framework - Reference to NIST CSF 2.0 as the control framework; risk scoring methodology (likelihood x impact, 5x5 matrix).
4. Roles & Responsibilities - {ciso_or_exec} owns the risk register; {ceo_or_exec} approves risk acceptance above defined threshold; department heads own operational risks.
5. Policy Statements covering:
   a. Annual enterprise risk assessment; ad-hoc for material changes.
   b. Risk register maintenance and quarterly review.
   c. Risk treatment options: accept, mitigate, transfer (insurance/contract), avoid.
   d. Risk acceptance requires written sign-off by {ceo_or_exec} for High/Critical risks.
   e. Third-party risk assessments prior to onboarding and annually thereafter.
   f. Integration with business continuity and disaster recovery planning.
6. Risk Appetite Statement - Describe {legal_name}'s tolerance for security risk given its {industry} context and {compliance_drivers} obligations.
7. Enforcement.
8. Review Cadence - Annual; triggered by significant organizational or threat-landscape changes.
9. Approvals - {ceo_or_exec} and {ciso_or_exec}.

Output clean Markdown only.
""",
    },
    {
        "key": "vendor_management_policy",
        "title": "Vendor Management Policy",
        "summary": "Third-party and supply-chain security risk controls mapped to NIST CSF GV.SC.",
        "csf_baseline": ["GV.SC", "ID.RA", "PR.AA", "PR.DS", "RS.CO"],
        "citations_by_driver": {
            "SOC 2": ["TSC CC9.2 Vendor and business partner risk"],
            "ISO 27001": [
                "ISO/IEC 27001:2022 Annex A 5.19-5.23 Supplier relationships and cloud services",
            ],
            "PCI DSS": ["PCI DSS v4.0.1 Requirement 12.8 Third-party service provider management"],
            "GDPR": ["GDPR Art. 28 Processor"],
            "HIPAA": [
                "45 CFR 164.308(b) Business associate contracts and other arrangements",
                "45 CFR 164.504(e) Business associate contract requirements",
            ],
            "FedRAMP": ["NIST SP 800-53 Rev. 5 SR control family (FedRAMP baseline)"],
        },
        "prompt_outline": """
Write a formal Vendor Management Policy for {legal_name}.
Industry: {industry}. Leadership: {leadership_text}.
Compliance drivers: {compliance_drivers}.
{regulatory_notes}

Sections:
1. Purpose - Manage cybersecurity risk introduced by third-party vendors, suppliers, and service providers; reference NIST CSF 2.0 GV.SC (Cybersecurity Supply Chain Risk Management).
2. Scope - All vendors with access to {legal_name} systems, data, facilities, or that provide critical services.
3. Vendor Tiers - Critical (direct access to Confidential/Restricted data or infrastructure), Standard, Low-risk. Tiering drives due-diligence depth.
4. Roles & Responsibilities - {ciso_or_exec} owns vendor security program; Procurement/Legal manage contracts; data owners tier vendors.
5. Policy Statements covering:
   a. Pre-onboarding security questionnaire and risk assessment for Critical/Standard vendors.
   b. Contractual security requirements (DPA, right-to-audit, breach notification SLA <= 72h).
   c. Annual re-assessment for Critical vendors; biennial for Standard.
   d. Vendor access granted on least-privilege and revoked within SLA on termination.
   e. Software supply chain: verify integrity of third-party components (SBOMs, CVE monitoring).
   f. Concentration risk: maintain alternative vendors for single-source Critical dependencies.
   g. Incident notification: vendor must notify {legal_name} within stated SLA for any breach affecting {legal_name} data.
6. Vendor Offboarding - Data return/destruction certification requirements.
7. Enforcement.
8. Review Cadence - Annual; updated within 30 days of a vendor-related incident.
9. Approvals - {ceo_or_exec} and {ciso_or_exec}.

Output clean Markdown only.
""",
    },
    {
        "key": "sensitive_data_handling_policy",
        "title": "Sensitive Data Handling Policy",
        "summary": "Day-to-day handling of personal, financial, and other regulated data: need-to-know use, de-identification, approved channels, and access logging, mapped to NIST CSF PR.DS.",
        "csf_baseline": ["PR.DS", "PR.AA", "GV.PO", "ID.AM", "DE.CM", "PR.PS"],
        "citations_by_driver": {
            "SOC 2": ["TSC C1.1-C1.2 Confidentiality", "TSC P4.1-P4.3 Use, retention, and disposal"],
            "ISO 27001": [
                "ISO/IEC 27001:2022 Annex A 5.12 Classification of information",
                "ISO/IEC 27001:2022 Annex A 5.14 Information transfer",
                "ISO/IEC 27001:2022 Annex A 5.34 Privacy and protection of PII",
                "ISO/IEC 27001:2022 Annex A 8.11 Data masking",
            ],
            "PCI DSS": [
                "PCI DSS v4.0.1 Requirement 3 Protect stored account data",
                "PCI DSS v4.0.1 Requirement 7 Restrict access to system components and cardholder data by business need to know",
                "PCI DSS v4.0.1 Requirement 10 Log and monitor all access",
            ],
            "GDPR": [
                "GDPR Art. 5(1)(c) Data minimisation",
                "GDPR Art. 9 Processing of special categories of personal data",
                "GDPR Art. 25 Data protection by design and by default",
                "GDPR Art. 32 Security of processing",
            ],
            "HIPAA": [
                "45 CFR 164.502(b) Minimum necessary",
                "45 CFR 164.514(a)-(b) De-identification of protected health information",
                "45 CFR 164.312(b) Audit controls",
            ],
            "CCPA": [
                "Cal. Civ. Code 1798.100(e) Reasonable security procedures",
            ],
            "FedRAMP": ["NIST SP 800-53 Rev. 5 AC, AU, and SC control families (FedRAMP baseline)"],
        },
        "prompt_outline": """
Write a formal Sensitive Data Handling Policy for {legal_name} (doing business as {dba_name}).
Industry: {industry}. Leadership: {leadership_text}.
Compliance drivers: {compliance_drivers}.
{regulatory_notes}

This policy governs how workforce members use and move sensitive data day to day. It builds on
the classification tiers in the Data Protection Policy; refer to that policy rather than repeating it.
Sensitive data means personal data, financial and payment data, credentials and secrets, and any
category that the compliance drivers above treat as regulated or special.

Sections, in order:
1. Purpose - Protect sensitive data in everyday use; reference NIST CSF 2.0 PR.DS and PR.AA.
2. Scope - All sensitive data created, received, maintained, or transmitted by {legal_name} workforce members, contractors, and systems, in any medium.
3. Definitions - Sensitive data and the categories that apply to a {industry} organization under {compliance_drivers}; data owner; data custodian.
4. Roles & Responsibilities - Name {ciso_or_exec} as owner; data owners approve access and uses; IT enforces controls; workforce members handle data per need to know.
5. Policy Statements covering:
   a. Need to know and data minimization - use and disclose only the sensitive data a task requires.
   b. Access control - unique accounts, role-based least privilege, and approval by the data owner.
   c. Encryption of sensitive data at rest and in transit, per the Data Protection Policy.
   d. Access logging - log access to sensitive data and review the logs on a defined cadence.
   e. De-identification, pseudonymization, or masking before data is used for testing, analytics, or any secondary purpose.
   f. Approved channels only - no sensitive data in personal email, consumer messaging, public AI tools, or unmanaged devices.
   g. Secure printing, removable media, and disposal of sensitive data.
   h. Reporting of suspected misuse or exposure under the Incident Response Policy.
6. Enforcement - Sanctions for workforce members who violate this policy.
7. Review Cadence - Annual; immediate update on material change or a reportable incident.
8. Approvals - {ceo_or_exec} and {ciso_or_exec} with effective date.

Use formal, plain-English language suitable for a {employee_count}-person {industry} organization.
Output clean Markdown only (no preamble, no code fences).
""",
    },
    {
        "key": "breach_notification_policy",
        "title": "Breach Notification Policy",
        "summary": "How a suspected data breach is assessed, who must be notified, by when, and what the notice says, mapped to NIST CSF RS and RC.",
        "csf_baseline": ["RS.CO", "RS.MA", "RS.AN", "RC.CO", "GV.OV", "DE.AE"],
        "citations_by_driver": {
            "SOC 2": [
                "TSC CC2.3 Communication with external parties",
                "TSC CC7.3-CC7.5 Security incident evaluation, response, and recovery",
            ],
            "ISO 27001": [
                "ISO/IEC 27001:2022 Annex A 5.24-5.28 Information security incident management",
            ],
            "PCI DSS": ["PCI DSS v4.0.1 Requirement 12.10 Incident response"],
            "GDPR": [
                "GDPR Art. 33 Notification of a personal data breach to the supervisory authority",
                "GDPR Art. 34 Communication of a personal data breach to the data subject",
            ],
            "HIPAA": [
                "45 CFR 164.400-414 Breach notification",
                "45 CFR 164.402 Definitions (breach and risk assessment)",
                "45 CFR 164.404 Notification to individuals",
                "45 CFR 164.406 Notification to the media",
                "45 CFR 164.408 Notification to the Secretary",
            ],
            "CCPA": [
                "Cal. Civ. Code 1798.82 Data breach notification (California customer records law)",
                "Cal. Civ. Code 1798.150 Private right of action for data breaches",
            ],
            "FedRAMP": ["NIST SP 800-53 Rev. 5 IR-6 Incident reporting (FedRAMP baseline)"],
        },
        "prompt_outline": """
Write a formal Breach Notification Policy for {legal_name}.
Industry: {industry}. Leadership: {leadership_text}.
Compliance drivers: {compliance_drivers}.
{regulatory_notes}

Apply the notification rules and deadlines of the compliance drivers listed above, each under its
own name. Where no driver sets a deadline, require notification without undue delay and state that
legal counsel confirms the deadline for each jurisdiction and contract. Do not invent statutory
deadlines or thresholds.

Sections:
1. Purpose - Establish how {legal_name} detects, assesses, and reports breaches of personal or otherwise protected data; reference NIST CSF 2.0 RS.CO and RC.CO.
2. Scope - All suspected or confirmed unauthorized access to, or acquisition, use, or disclosure of, data that {legal_name} must protect, in any medium, by workforce members or vendors.
3. Definitions - Security incident vs. breach; the data categories in scope for a {industry} organization under {compliance_drivers}.
4. Roles & Responsibilities - {ciso_or_exec} leads breach assessment; {ceo_or_exec} approves external notifications; Legal advises on obligations; Communications drafts notices.
5. Discovery & Risk Assessment - On discovery, record the date and assess: the nature and amount of data involved; who obtained it; whether it was actually acquired or viewed; whether it was encrypted; and how far the risk has been mitigated.
6. Notification Requirements:
   a. Affected individuals - when and how they are notified under each applicable driver.
   b. Regulators and authorities - which authority is notified under each applicable driver, and by when.
   c. Customers and partners - notice owed under contracts.
   d. Media or public notice - where an applicable driver requires it.
   e. Vendor breaches - vendors must notify {legal_name} in time for {legal_name} to meet these deadlines.
7. Content of Notice - what happened, the types of data involved, steps individuals should take, what {legal_name} is doing, and contact procedures.
8. Documentation - Retain breach assessments, decisions, and notices for the period the applicable drivers require.
9. Enforcement.
10. Review Cadence - Annual; tabletop exercise; updated within 30 days of any reportable breach.
11. Approvals - {ceo_or_exec} and {ciso_or_exec}.

Output clean Markdown only.
""",
    },
    {
        "key": "connected_device_security_policy",
        "title": "Connected Device and Operational Technology Security Policy",
        "summary": "Inventory, segmentation, hardening, and lifecycle controls for IoT, operational technology, and other network-connected equipment, mapped to NIST CSF ID.AM and PR.IR.",
        "csf_baseline": ["ID.AM", "PR.IR", "PR.PS", "DE.CM", "PR.AA", "ID.RA"],
        "citations_by_driver": {
            "SOC 2": [
                "TSC CC6.6 Protection against threats from outside system boundaries",
                "TSC CC7.1 Detection of configuration changes and vulnerabilities",
            ],
            "ISO 27001": [
                "ISO/IEC 27001:2022 Annex A 5.9 Inventory of information and other associated assets",
                "ISO/IEC 27001:2022 Annex A 8.8 Management of technical vulnerabilities",
                "ISO/IEC 27001:2022 Annex A 8.20 Networks security",
                "ISO/IEC 27001:2022 Annex A 8.22 Segregation of networks",
            ],
            "PCI DSS": [
                "PCI DSS v4.0.1 Requirement 1 Install and maintain network security controls",
                "PCI DSS v4.0.1 Requirement 2 Apply secure configurations to all system components",
            ],
            "GDPR": ["GDPR Art. 32 Security of processing"],
            "HIPAA": [
                "45 CFR 164.310(d) Device and media controls",
                "45 CFR 164.312 Technical safeguards",
            ],
            "FedRAMP": ["NIST SP 800-53 Rev. 5 CM and SC control families (FedRAMP baseline)"],
        },
        "prompt_outline": """
Write a formal Connected Device and Operational Technology Security Policy for {legal_name}.
Industry: {industry}. Leadership: {leadership_text}.
Compliance drivers: {compliance_drivers}.
{regulatory_notes}

Connected devices are network-attached equipment that is not a standard managed laptop, server, or
phone: IoT sensors, cameras, badge readers, building systems, point-of-sale terminals, printers,
industrial and operational technology controllers, and any equipment typical of a {industry}
organization. Many cannot be patched or run endpoint agents.

Sections:
1. Purpose - Reduce safety, availability, and data risk from connected devices and operational technology; reference NIST CSF 2.0 ID.AM and PR.IR.
2. Scope - All connected devices and operational technology owned, leased, or operated by {legal_name}, including legacy and unpatchable equipment and vendor-managed devices.
3. Roles & Responsibilities - {ciso_or_exec} owns the program; facilities or operations teams maintain the device inventory; IT operates network controls; vendors support devices under contract.
4. Policy Statements covering:
   a. Asset Inventory (ID.AM) - keep a current inventory of devices, their owners, firmware versions, and data flows; review it at least every 12 months.
   b. Network Segmentation (PR.IR) - place devices on dedicated segments with only the traffic they need allowed.
   c. Access Control & Authentication (PR.AA) - change default credentials before deployment; disable unused ports and services; restrict management interfaces.
   d. Vulnerability & Patch Management - risk-based firmware updates within vendor constraints; compensating controls for devices that cannot be patched.
   e. Monitoring (DE.CM) - monitor device segments for anomalous traffic and new devices.
   f. Procurement - require a software bill of materials, a vulnerability disclosure process, and a security support period from vendors.
   g. Vendor Remote Access - approved, logged, time-limited remote access only.
   h. End-of-Life - secure decommissioning and data sanitization.
5. Enforcement.
6. Review Cadence - Annual; updated within 30 days of a device-related incident or vendor security advisory.
7. Approvals - {ceo_or_exec} and {ciso_or_exec}.

Output clean Markdown only.
""",
    },
]

_CATALOG_BY_KEY: dict[str, dict[str, Any]] = {entry["key"]: entry for entry in CATALOG}

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]")


def _driver_key(name: str) -> str:
    """``PCI-DSS``, ``pci dss``, and ``PCI DSS`` all compare equal."""
    return _NON_ALNUM_RE.sub("", name.lower())


def _public(entry: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``entry`` without the internal per-driver citation table."""
    return copy.deepcopy({k: v for k, v in entry.items() if k != "citations_by_driver"})


def get_catalog() -> list[dict[str, Any]]:
    """Every catalog entry, in display order (copies the caller may change).

    Entries hold ``key``, ``title``, ``summary``, ``csf_baseline``, and
    ``prompt_outline``; citations come from ``citations_for``.
    """
    return [_public(entry) for entry in CATALOG]


def get_entry(key: str) -> dict[str, Any] | None:
    """A copy of the catalog entry for ``key`` (as ``get_catalog``), or None."""
    entry = _CATALOG_BY_KEY.get(key)
    return _public(entry) if entry is not None else None


def citations_for(policy_key: str, compliance_drivers: Iterable[str]) -> list[str]:
    """The policy's citations for the drivers the organization selected, in that order.

    Drivers with no citations (NIST CSF, which the badges already cover, or a
    driver the visitor typed) add nothing. Duplicates are dropped.
    """
    entry = _CATALOG_BY_KEY.get(policy_key) or {}
    by_driver = {
        _driver_key(name): citations
        for name, citations in (entry.get("citations_by_driver") or {}).items()
    }
    result: list[str] = []
    for driver in compliance_drivers:
        for citation in by_driver.get(_driver_key(driver), ()):
            if citation not in result:
                result.append(citation)
    return result


__all__ = ["CATALOG", "citations_for", "get_catalog", "get_entry"]
