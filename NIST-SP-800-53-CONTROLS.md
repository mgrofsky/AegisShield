# NIST SP 800-53 Rev. 5 alignment

This document lists the places where AegisShield's code does something that lines up with a NIST SP 800-53 Rev. 5 control. The same content, in machine-readable form, is in [`nist-sp-800-53-controls-mapping.json`](nist-sp-800-53-controls-mapping.json).

Read it as the maintainers' description of the code, nothing more:

- It is not an assessment. No assessor has reviewed it, and nothing here has been tested against the control assessment procedures in SP 800-53A.
- It is not a statement of compliance with SP 800-53, FedRAMP, FISMA, or any other program. Whether these behaviors meet a control in your environment depends on how you deploy and operate the app, and is your call.
- A control appears here only if code in this repository carries it. Each entry names the files and the functions or classes involved, and the tests that exercise them. A test (`tests/aegisshield/services/test_nist_800_53_service.py`) fails if any of those files or names stops existing, so the evidence cannot silently point at code that is gone.

Each control has a scope:

- **application**: a safeguard in the app itself.
- **capability**: a feature that can help your organization with its own work on the control. The app does not meet the control for you.

## Summary

| Control | Name | Scope | Main code |
|---------|------|-------|-----------|
| IA-5 | Authenticator Management | application | `aegisshield/ui/state.py` |
| SC-4 | Information in Shared System Resources | application | `aegisshield/jobs/runner.py` |
| SI-10 | Information Input Validation | application | `aegisshield/services/pcap_service.py` |
| SI-11 | Error Handling | application | `aegisshield/jobs/runner.py` |
| SI-15 | Information Output Filtering | application | `aegisshield/services/export_service.py` |
| RA-3 | Risk Assessment | capability | `aegisshield/pipeline/run.py` |
| PM-16 | Threat Awareness Program | capability | `aegisshield/pipeline/otx_service.py` |

Seven controls in five families (IA, SC, SI, RA, PM).

## Application safeguards

### IA-5: Authenticator Management

The authenticators here are the API keys the app holds for outside services (OpenAI, NVD, AlienVault OTX). The app does not identify or authenticate its own users; it has no accounts.

- A visitor's keys are typed into masked inputs and kept only in that visitor's Streamlit session state. The input is emptied once the key is stored (`aegisshield/ui/state.py`: `set_api_key`, `key_input_changed`; `aegisshield/ui/pages/settings.py`: `_keys_section`).
- The operator can set NVD and OTX keys in Streamlit secrets. There is no operator fallback for the OpenAI key (`get_api_key`).
- Keys are passed by value into the job that needs them. The job runner drops the job function, which holds the key, as soon as the job ends (`aegisshield/jobs/runner.py`: `JobRunner._run`).
- Failed-job log lines pass through `redact_keys` (`aegisshield/core/text.py`). OpenAI SDK errors are re-raised without their message, and the client's `repr` shows no key (`aegisshield/llm/openai_client.py`: `OpenAIClient._complete`, `OpenAIClient.__repr__`).

### SC-4: Information in Shared System Resources

One Streamlit process serves every visitor, so one visitor's work must not be reachable from another's session.

- Job ids come from `secrets.token_urlsafe(32)`, and the runner offers no way to list jobs. A session sees only the jobs whose ids it holds (`JobRunner.submit`, `JobRunner.snapshot`).
- While a job runs, its id is also in the page URL (`?run=`) so a reload can find it. Anyone with that URL can open the job while it runs and for 30 seconds after it ends. Each page removes the id from the URL when the job finishes, fails, is cancelled, or is no longer held (`aegisshield/ui/state.py`: `adopt_job`, `requested_run_id`, `set_run_param`).
- Finished jobs are dropped after a time to live (15 minutes by default), and a job still running at the job timeout is marked failed and told to stop (`JobRunner._sweep_locked`).
- At most `AEGIS_MAX_CONCURRENT_JOBS` jobs (4 by default) run at once in the process, and at most 1 packet capture analysis, 2 vulnerability lookups, 2 policies, and 3 threat models at once across all visitors. A refused job gets a fixed sentence (`JobRunner.__init__`, `JobRunner.submit`; `aegisshield/config.py`: `Settings`).
- By default the workspace is a `MappingStore` over the visitor's own session state. The on-disk `FileStore` is one file shared by everyone, used only when the operator sets `AEGIS_DATA_DIR`; the app logs a warning when it is set (`aegisshield/storage/stores.py`: `warn_if_shared_workspace`; `aegisshield/ui/state.py`: `workspace_store`).

### SI-10: Information Input Validation

Checks run on the server, whatever the browser sent.

- The Streamlit server accepts at most 25 MB per upload (`maxUploadSize` in `.streamlit/config.toml`).
- A packet capture is checked for size (25 MB), extension (`.pcap` or `.pcapng`), and pcap or pcapng magic bytes before it is written to disk (`aegisshield/services/pcap_service.py`: `validate_upload`, `detect_capture_format`).
- An architecture image (10 MB) and a workspace import (10 MB) are refused by their reported size before they are read (`aegisshield/ui/tool_parts.py`: `upload_too_large`). An image must be a PNG or JPEG by its own first bytes (`aegisshield/pipeline/threat_model_service.py`: `decode_image`).
- A workspace import is refused when its schema version, keys, types, or record ids are wrong (`aegisshield/storage/workspace.py`: `Workspace.from_json`, `Workspace.from_dict`, `Record.from_dict`).
- Text limits: description 20,000 characters, diagram description 10,000, profile values 200 characters and lists 500 items (the threat-model request refuses anything longer: `aegisshield/pipeline/schemas.py`: `AppProfile`, `ThreatModelRequest`), version strings 32 characters, and edited policy text 100,000 characters.
- Visitor text has control and invisible characters, including bidirectional controls, removed (`aegisshield/core/text.py`: `clean_text`, `strip_invisible`, `sanitize_user_markdown`). Model names read from the environment must be in `AVAILABLE_MODELS` (`aegisshield/config.py`: `get_settings`).

### SI-11: Error Handling

- Errors shown to a visitor are fixed sentences from the app's own code that never carry provider text, a library's exception text, or keys. A failed job's message is chosen by exception class, except that a job may show one of its service's own fixed sentences (`pcap_service.JOB_ERRORS`, the safeguards' `JOB_ERRORS`, and the scan service's `JOB_ERRORS`), and the exception's class and message are logged with key-shaped text redacted (`aegisshield/jobs/runner.py`: `plain_error`, `JobRunner._run`; `aegisshield/core/errors.py`).
- OpenAI SDK errors are logged by class and HTTP status and re-raised as a fixed message (`OpenAIClient._complete`).
- `tshark` failures are logged on the server and shown as fixed sentences (`aegisshield/services/pcap_service.py`: `_run_tshark`).
- `.streamlit/config.toml` sets `showErrorDetails = "none"`, so an unexpected exception is not shown in the page.

### SI-15: Information Output Filtering

Model output and visitor text are treated as untrusted when they are written into exports or shown.

- Every string placed into the HTML export is escaped. Markdown is rendered with raw HTML escaped and images reduced to their alt text. The HTML export carries a Content-Security-Policy that allows no scripts and no outside resources (`aegisshield/services/export_service.py`: `escape`, `markdown_html`, `to_html_report`).
- In the HTML export and the PDFs, links stay links only for http, https, mailto, and in-page fragments; any other link becomes plain text (`aegisshield/core/text.py`: `is_safe_link`; `export_service.restrict_links`, `safe_link`; `aegisshield/services/policy_service.py`: `markdown_to_html`). In the page, model text that names a `javascript:`, `vbscript:`, `data:`, or `file:` scheme anywhere has every link shown as plain text (`aegisshield/ui/kit.py`: `model_markdown`); Streamlit's own renderer also refuses `javascript:` and `vbscript:` links.
- Every PDF the app makes (the threat-model report and policies) goes through one renderer whose resource policy refuses every network fetch and every local file read; only images embedded in the document load (`aegisshield/services/pdf_render.py`: `locked_resource_policy`, `html_to_pdf`; `report_service.render_pdf`).
- Packet-derived text is escaped in the PCAP markdown report (`render_markdown_report`).

## Capabilities for your organization

### RA-3: Risk Assessment

The threat-model wizard drafts a STRIDE threat model, an attack tree, a DREAD assessment, mitigations, and test cases for a system you describe (`aegisshield/pipeline/run.py`: `run_threat_model`; `aegisshield/pipeline/workflow_service.py`; `aegisshield/pipeline/dread_service.py`). The output is written by a language model. It is a draft for a person to review and can be an input to a risk assessment; it is not one.

### PM-16: Threat Awareness Program

With an OTX key, a threat-model run fetches recent AlienVault OTX reports for the selected industry sector, and a vulnerability lookup fetches OTX reports for each technology. The vulnerability lookup also marks CVEs that are in the CISA Known Exploited Vulnerabilities catalog (`aegisshield/pipeline/otx_service.py`: `lookup_otx`; `aegisshield/services/kev_service.py`; `aegisshield/services/vuln_lookup.py`: `run_lookup`). These are read-only lookups of public sources.

## Controls the code does not carry

These controls are sometimes claimed for tools like this one. They are not listed above because the code does not carry them:

- **AC-3 Access Enforcement, IA-2 Identification and Authentication**: the app has no users, accounts, or access control. Anyone who can reach a deployment can use it.
- **SC-7 Boundary Protection**: retries and timeouts on outgoing API calls are not boundary protection.
- **SC-12 Cryptographic Key Establishment and Management**: API keys are not cryptographic keys, and the app establishes none.
- **SI-4 System Monitoring, SI-7 Software, Firmware, and Information Integrity**: looking up public CVE data for products a user names does not monitor or verify this system.
- **AU-3, AU-4, AU-6, AU-8 (audit records, storage, review, time stamps)**: the app writes ordinary application logs to a stream. It keeps no audit records, manages no log storage, and its log lines carry no user identity.
- **RA-5 Vulnerability Monitoring and Scanning**: the app never scans or probes another system. The vulnerability lookup reads public databases about product versions a user names. The optional AI workflow scan runs garak only against the app's own workflow steps, through a loopback endpoint.

## Keeping this current

When code named here changes, update the JSON and this page together. The test above catches renamed or deleted files and functions; it cannot tell whether the behavior described is still true, so read the code when you change it.
