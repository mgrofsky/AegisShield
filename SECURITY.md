# Security Policy

## Overview

AegisShield is a Streamlit app that drafts threat models, looks up public vulnerability data for products you name, drafts security policies, and summarizes packet captures. It checks its own model calls with NeMo Guardrails, and an operator can let visitors scan their own AI workflow (a system prompt, and the provider and model they chose in Settings, called through the app's own client) with garak. This page covers how to report a vulnerability in the app, how the app handles keys and data, and what an operator must take care of before exposing it to other people.

## Supported Versions

Security fixes are made on the `main` branch only. There are no maintained release branches.

| Version | Supported |
| ------- | --------- |
| Latest commit on `main` | Yes |
| Anything older | No |

## Reporting a Vulnerability

If you discover a security vulnerability in AegisShield, please report it by:

1. **DO NOT** open a public GitHub issue
2. Email the maintainers directly with details including:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if applicable)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 5 business days
- **Resolution Timeline**: Critical vulnerabilities will be prioritized for immediate patching
- **Credit**: Security researchers will be credited (unless anonymity is requested)

## What the app does with keys

- **Where keys come from.** A visitor types their model provider credential (a Claude, OpenAI, or Gemini API key; for Amazon Bedrock, either a Bedrock API key or an AWS access key ID, secret access key, and optional session token) and their NVD and AlienVault OTX keys on the Settings page, in masked inputs. An operator may also set NVD and OTX keys in `.streamlit/secrets.toml` (`nvd_api_key`, `alienvault_api_key`); a visitor's own key takes precedence. There is no operator setting for any provider credential, so each visitor brings their own. No key is read from an environment variable. (`aegisshield/ui/state.py`)
- **Bedrock uses the visitor's credential and nothing else.** The boto3 session is built from the values the visitor typed and their chosen region (from a fixed list in code; a region is not a secret). Every botocore setting loses its environment and config-file source, no profile or shared file is named, and configured endpoint URLs are ignored. With AWS access keys, the token provider never finds a token and requests are signed with SigV4 set in code. With a Bedrock API key, the token provider returns only the visitor's key, the credential provider finds nothing, and the signature version is set to `bearer` in code, so each request carries `Authorization: Bearer` with the visitor's key and no SigV4 signature. When a visitor holds both, the API key is used, and the Settings page says so. So a server-side `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_BEARER_TOKEN_BEDROCK`, `AWS_ENDPOINT_URL`, `~/.aws` file, or instance role is never used for a visitor's call; tests plant each of these and check the outgoing request for both kinds of credential, and check that two visitors' API keys in one process never cross. One trace remains: botocore 1.44.3 itself checks whether `AWS_BEARER_TOKEN_BEDROCK` is set and, when it is, adds a feature code to the request's user agent string. The token's value is not read into the request. (`visitor_session` in `aegisshield/llm/bedrock_client.py`)
- **The Claude and Gemini clients** are built with the visitor's key passed explicitly, which the SDKs document as overriding their environment credentials; the Gemini client is also told it is not Vertex AI, so `GOOGLE_GENAI_USE_VERTEXAI` and Google Cloud credentials on the server are not used. Endpoint overrides an operator sets in the environment for these SDKs (and OpenAI's) still apply, as for any deployment setting.
- **Where keys are kept.** In the visitor's Streamlit session state only. The input field is emptied once the key is stored. Keys are never written to the workspace, an export, a file, a URL, or a job's progress record. They are gone when the session ends.
- **How keys reach a job.** The page passes the key by value into the job function. The job runner drops that function as soon as the job ends, so the key is not held after the work is done. The runner is also handed the session's credential values with each job, only to remove them from a failure's log line, and drops them when the job starts. (`aegisshield/jobs/runner.py`)
- **Where keys are sent.** Each key goes only to its own service: the chosen model provider (Anthropic, Amazon Bedrock in the chosen region, OpenAI, or Google's Gemini API), the NVD API, or AlienVault OTX. The provider credential is used for the model calls and for asking the provider for its model list.
- **Model lists come from the provider.** No model name is offered from the app's own code except OpenAI's configured default and the Claude model to preselect, and those only when the provider's own list holds them. Each list is bounded (200 models, ids of at most 128 characters), every id must match a strict pattern (letters, digits, dots, underscores, colons, hyphens) before it is shown or sent, and a model not on the provider's latest list is refused in code (`set_model_choice` in `aegisshield/ui/state.py`). A failed listing shows one fixed sentence.
- **Logs.** A failed job's log line carries the exception's class and message, passed through `redact_keys` (`aegisshield/core/text.py`). It removes every credential value the session held when the job started (each provider's secret fields and the OpenAI, NVD, and OTX keys, whatever their shape), and these shapes in any text: `sk-` keys, `Bearer` tokens, AWS access key IDs, Google API keys, the two Bedrock API key shapes AWS documents (long-term keys start `ABSKQmVkcm9ja0FQSUtleS`, short-term keys `bedrock-api-key-`), and a value of 16 or more key characters labeled `api_key`, `apiKey`, `X-OTX-API-KEY`, `otx_api_key`, `nvd_api_key`, `secret_access_key`, `aws_secret_access_key`, `session_token`, or `token` and followed by `=` or `:`. An NVD key (a UUID), an OTX key (64 hex digits), or an AWS secret access key that is not the session's own and carries no label is not recognized, since those shapes are also ordinary ids and hashes. Provider SDK errors (OpenAI, Anthropic, boto3, google-genai) are logged by class and HTTP status only and re-raised with a fixed sentence and no cause chain; lookup failures by exception class only, and `tshark` failures with the end of `tshark`'s error output.

## Error messages

Messages shown in the page are fixed sentences written in the app's own code, chosen by the kind of failure (including the safeguards' own fixed sentences, `JOB_ERRORS` in `aegisshield/safeguards/core.py`). They never include text from a provider's response, a library's exception message, or a key; that detail, where it is kept at all, goes to the server log. `.streamlit/config.toml` sets `showErrorDetails = "none"`, so an unexpected exception is not shown to the visitor either. (`aegisshield/core/errors.py`, `plain_error` in `aegisshield/jobs/runner.py`, and the four clients in `aegisshield/llm/`)

## Output escaping

Model output and visitor text are untrusted wherever they are placed.

- **In the page**: the helpers in `aegisshield/ui/kit.py` that write HTML escape the text they place with `html.escape`, and visitor text has control and invisible characters, including bidirectional controls, removed before it is stored or shown (`aegisshield/core/text.py`). Model text shown in the page goes through `kit.model_markdown`, which shows every link as plain text when the text names a `javascript:`, `vbscript:`, `data:`, or `file:` scheme anywhere (Streamlit's own renderer also refuses `javascript:` and `vbscript:` links).
- **HTML export**: every string is escaped; markdown is rendered with raw HTML escaped, images reduced to their alt text, and links kept only for http, https, mailto, and in-page fragments (`is_safe_link` in `aegisshield/core/text.py`). The file carries a Content-Security-Policy (`default-src 'none'`) that blocks scripts and outside resources. (`aegisshield/services/export_service.py`)
- **PDFs** (the threat-model report and policies): built from escaped HTML with the same link rule, and drawn by one renderer whose resource policy refuses every network fetch and every local file read; only images embedded in the document load. Drawing is bounded too: a table longer than 500 rows is refused before drawing, at most two PDFs are drawn at once in the whole process (a third is refused at once), and a render stops after 8 seconds. A refused PDF fails with a fixed sentence; the page says before the click why that can happen (`aegisshield/services/pdf_render.py`).
- **SARIF and JSON exports**: written with the standard JSON encoder.
- **PCAP report**: packet-derived text is escaped for markdown, and is marked as data in the prompt sent to the model (`aegisshield/services/pcap_service.py`).

## Safeguards on model calls

Every model call goes through NeMo Guardrails 0.24.1 rails that run local pattern checks (`aegisshield/safeguards/`); no model judges anything and nothing leaves the process. [docs/ai-safeguards.md](docs/ai-safeguards.md) says how they decide, what was measured, and their limits. In short:

- **Typed text** (description, profile values) with an instruction addressed to the model is fenced as data between markers that carry a random code, and recorded. Nothing typed is removed or blocked.
- **Other text that reaches a prompt** (diagram description, capture text, NVD and OTX results, imported records, the lookup hand-off) has such an instruction replaced by "[instruction removed from <source>]", and recorded.
- **Every answer** that repeats the step's own instructions or carries out a string demanded by an instruction the visitor typed is withheld with a fixed sentence; key-shaped secrets and markup that loads from or sends data to another host are removed.
- **States are exact.** A check that could not run is "not checked", never "passed". An answer that could not be checked is withheld, in every mode. Input that could not be checked is used as it was and the result says it is not fully checked, unless `AEGIS_SAFEGUARDS_STRICT=1`, which stops the step. Where NeMo is not installed at all (the package cannot be found), the app still works and every result says the safeguards were unavailable; an installed NeMo that fails to import withholds answers instead.
- **Operator switches.** `AEGIS_SAFEGUARDS=0` turns them off for the deployment; a visitor cannot. Settings shows on, off, or unavailable, the NeMo version, and strict mode.
- **No telemetry.** NeMo sends usage statistics to its vendor by default. The app sets `NEMO_GUARDRAILS_NO_USAGE_STATS=1` itself before NeMo is first imported, overriding any value, and a test proves no connection is attempted.
- **What is stored.** Each check's rail set, source or step, status, rail, reason, and at most a 60 character escaped excerpt; never the text of a secret.

**Limits, stated plainly.** The checks are pattern rules: a reworded, encoded, split, or translated instruction can pass, and some everyday phrasings do (the list is in the docs). In a scan with the checks on, an instruction in garak's prompt is fenced as data before the model sees it, so those results partly measure that fence. A quoted instruction in third-party text is left in place, and an answer that obeys it is not withheld. They have been measured only against a simulated stand-in model, never a real one. They do not make the app or its output secure or correct. A pattern match holds Python's interpreter lock for the whole shared process, so every pattern is written to run in time linear in its input, and the tests time each one on long hostile input, including long runs of whitespace after each of its words.

## AI workflow scans

An operator can let visitors run NVIDIA garak 0.17.1 against their own AI workflow (`aegisshield/aiscan/`): a system prompt (at most 6,000 characters), optional sample context (at most 4,000 characters), and the provider and model the visitor chose in Settings, called through the app's own client for that provider with the visitor's credential, with the app's NeMo checks on or off. It is off by default. It is on only when `AEGIS_AI_SCAN=1` and `AEGIS_GARAK_PYTHON` names the Python interpreter of a separate environment where garak is installed and reports a version (asked once per process, 10 second timeout). garak is not in `requirements.txt`, CI, or the Docker image, and the app never imports it.

- **A second subprocess.** Besides `tshark`, the app can start one more program: garak, from a fixed argument list with no shell, in its own process group, with probes taken only from a fixed list in code. Any other probe id is refused before a command line is built. When a scan ends, however it ends, garak's whole process group is killed, so nothing garak started outlives the scan; the version question runs the same way.
- **What it contacts.** garak's configuration is written by the app, and its only address is a loopback endpoint the app starts for that one scan on 127.0.0.1, on a port the system picks, with a random bearer token made for that scan and compared in constant time. That endpoint makes each prompt the user's message of one model call through the app's own client, with the visitor's system prompt, after the sample context under a plain label, to the chosen model. The client for each provider is built the same way as for a threat-model run, with the visitor's credential passed in code: OpenAI's and Anthropic's clients call their SDK's default host (or an endpoint override the operator set in the environment), the Gemini client calls Google's Gemini API (never Vertex AI), and the Bedrock client calls Amazon Bedrock in the visitor's chosen region and ignores configured endpoint URLs. Nothing a visitor gives on the scan page can change the host, and the model is the one chosen in Settings from the provider's own list. The visitor's credential stays inside that client, in the scan's job; it never reaches garak's arguments, environment, configuration, or report, a log line, or the stored record (a test checks each of the four providers). The service checks the system prompt, sample context, and model again whatever the page sent, requires one of the app's providers for a real-model scan, and refuses a control character other than a line break or a tab. The three surfaces that test the app's own steps are developer checks: the page does not offer them and the service refuses them unless a caller passes `developer=True` (`tools/garak_offon.py` and the tests). It serves at most 2 connections at once and closes any connection over that at once, and each request must arrive whole within 15 seconds of the connection or the connection is dropped. When a scan ends it closes every open connection; a workflow call already running ends when its model call returns, which the model client's timeout bounds. garak's environment holds only `PATH`, `HOME` and the XDG directories inside a private temporary directory (removed when the scan ends), the HuggingFace offline switches, a proxy setting that points every outside address at a closed loopback port, and the scan's token. Every offered probe was run with the outside network blocked and downloaded nothing. No visitor input, including the system prompt and sample context, reaches garak's arguments, environment, or configuration.
- **Keys.** Only the app process calls the model. A visitor's key stays in the job and never reaches garak's arguments, environment, files, or the stored record.
- **Limits.** Answers per prompt 1 (at most 3), prompts per probe 5 (at most 20), request limit 60 (at most 300), time per request 120 seconds (at most 300), the whole scan 900 seconds (at most 1,500). A scan that needs no key (the simulated stand-in, in any mode) has lower maximums: 60 requests and 300 seconds for the whole scan. A selection whose planned requests exceed the request limit is refused before it starts; past the limit the endpoint refuses and the scan is marked incomplete. On Linux with `prlimit`, garak runs under a CPU limit of 1,500 seconds. **There is no memory limit for garak**: its need was measured on macOS only (peak resident memory 101 to 131 MB), not on Linux.
- **One at a time.** One scan runs at a time in the whole process (`ai_scan` in `DEFAULT_JOB_KIND_LIMITS`), one per session, and after a scan ends the same session must wait 60 seconds before starting another.
- **What a scan stores.** In the workspace (record kind `ai_scans`, which exports and imports like the others; with `AEGIS_DATA_DIR` set that is the one shared file, and the scan page says so): the run settings, including the visitor's system prompt, sample context, and model (never written to a log), garak's counts per probe and detector, each probe's state and references (garak's OWASP LLM and AVID tags, kept only when they are OWASP LLM01 to LLM10 or an AVID code garak gives an offered probe, and the app's own ATLAS mapping), up to 100 attempts with every text cut to 2,000 characters, the endpoint's counts, and a count-only summary of what the safeguards did. Every stored string passes the key redaction. garak's own files (report, hit log, HTML summary) are kept only in the session that ran the scan, for up to 15 minutes and at most 32 MB per session, for download; this server's paths in them are replaced with placeholders. The endpoint's fixed answers (refused, failed, timed out) carry a random mark made for each scan, which appears in stored attempts and downloads; only an exact match counts as a refusal or failure, so a model answer that copies the wording is read as an ordinary answer.
- **Status.** A scan's status comes from garak's report, never from its exit code (garak exits 0 when attacks succeed). A scan that did not finish is "incomplete" or "failed", never a result. A report line that cannot be read makes the scan not complete, and a probe whose answers were all refusals but where a detector still reported the attack is incomplete.

**What an operator should know before turning scans on.** When scans are on, any visitor can start one with the simulated stand-in model, without a key, and while it runs it holds the single scan slot for the whole process, for up to 300 seconds at a time. The 60 second wait applies per browser session, so a visitor who opens new sessions is not slowed by it. Put a deployment with scans on behind your own access control. A scan with a visitor's credential spends that visitor's model calls with their chosen provider: at most one call per request of the scan's request limit, each asking for at most 1,024 output tokens, and the provider's client sends a call again up to 2 more times when it cannot connect, times out, or gets a rate-limit or server error (which statuses depends on the provider's SDK; the page names them for the chosen provider before the scan starts). A clean scan is not evidence that the workflow resists an attack. A scan tests a system prompt and the visitor's chosen model through this app's own client, not the visitor's deployed system, its tools, retrieval, or network: it never contacts an address a visitor types, it is not a scanner for other systems, and nothing in it protects or assesses any outside endpoint. The app's NeMo checks, when a visitor chooses them for a scan, protect only the calls made through this app. Results from the simulated stand-in are labeled simulated.

## Packet capture uploads and tshark

The PCAP analysis page appears only when `tshark` is installed. For each upload (`aegisshield/services/pcap_service.py`):

- The file must be at most 25 MB, end in `.pcap` or `.pcapng`, and start with pcap or pcapng magic bytes. These are checked on the server before anything is written.
- The file is written under a fixed name into a new private temporary directory (directory mode 0700, file mode 0600), and the directory is removed when the analysis ends.
- `tshark` runs from a fixed argument list with no shell. The only variable argument is the path of that temporary file. Name resolution is off (`-n`) on every call, so `tshark` reads the file and contacts nothing.
- `tshark` gets a minimal environment: `PATH`, and `HOME` and `XDG_CONFIG_HOME` set to the temporary directory, so no user preferences or secrets from the server's environment reach it.
- On Linux, when `prlimit` is on the `PATH`, each `tshark` call runs under `prlimit` with a 3 GiB address-space limit and 90 seconds of CPU time. Elsewhere, or without `prlimit`, `tshark` runs without these limits. The Docker image's base already includes `prlimit`.
- Each `tshark` call has a 60 second timeout, the whole extraction has a 240 second budget, output rows and lines are capped as they are read, and the text sent to the model is capped at 60,000 characters.
- A capture that ends in the middle of a packet is analyzed up to that point, and the page, the prompt, and the report say so. Any other `tshark` failure is shown as a fixed sentence.
- Only the extracted summary is sent to the model provider, never the capture itself.

## Storage

- **By default nothing is shared.** Each visitor's work (threat models, policies, lookups, PCAP analyses, the organization profile) is a workspace held in that visitor's own session state. It is lost when the session ends unless the visitor exports it from the Settings page. (`aegisshield/storage/stores.py`, `MappingStore`)
- **Job results** are held in the server's memory and dropped 15 minutes after the job finishes. Job ids are random 32-byte tokens and there is no way to list jobs, so a session can reach only the jobs whose ids it holds. While a job runs, its id (256 random bits) is in the page URL (`?run=`) so that a reload can find it again. That URL is a bearer link: anyone who has it can open the job while it runs and for 30 seconds after it ends, until a session takes its result. Each page removes the id from the URL when the job finishes, fails, or is cancelled. Do not share the URL of a page with a job in progress.
- **`AEGIS_DATA_DIR`** makes the app keep the workspace in one file, `workspace.json`, in that directory. **That file is shared by everyone who can open the app.** The Settings page says so, and the app logs a warning at start-up. It is meant for a single-user install. Do not set it on a deployment that more than one person can reach. In the Docker image the directory must be writable by uid 10001.

## Deploying for other people

The app has no authentication, no accounts, and no access control. Anyone who can reach the URL can use every page. If you deploy it where others can reach it, you are responsible for:

- **Access.** Put it behind your own authentication (a reverse proxy, a VPN, or your platform's access controls) if it should not be public.
- **Providers.** `AEGIS_PROVIDERS` limits which of the four providers visitors may choose. A visitor's model calls are billed to their own credential.
- **Your keys.** If you set NVD or OTX keys in `.streamlit/secrets.toml`, every visitor's lookups use them and count against your quota with those services.
- **Load.** At most four jobs run at once across the whole process by default (`AEGIS_MAX_CONCURRENT_JOBS`). Across all visitors, at most 1 packet capture analysis, 2 vulnerability lookups, 2 policies, 3 threat models, and 1 AI workflow scan run at once (`DEFAULT_JOB_KIND_LIMITS` in `aegisshield/config.py`; not configurable by environment). Each session runs at most one job of each kind at a time. A refused job gets "Too many tasks are running on this server right now." A job still running after 30 minutes is marked failed and told to stop (`AEGIS_JOB_TIMEOUT_SECONDS`). These caps bound the server, not one visitor: there is no per-address rate limiting, so one visitor with several sessions can keep the slots busy.
- **Uploads.** `.streamlit/config.toml` sets `server.maxUploadSize = 25`, so the server accepts at most 25 MB per upload. Each page also checks its own limit on the server before reading the file: packet captures 25 MB, workspace imports 10 MB, architecture diagrams 10 MB. Keep `maxUploadSize` at or below 25 if you override it.
- **Text.** Limits are enforced on the server: application description 20,000 characters, diagram description 10,000, policy text 100,000, version strings 32, and profile values 200 characters and 500 items.
- **Transport.** Streamlit serves plain HTTP. Terminate TLS in front of it.
- **Streamlit settings.** Keep Streamlit's CORS and XSRF protection on. The development container in `.devcontainer/` turns both off for local use; do not copy those flags to a deployment.
- **Storage.** Leave `AEGIS_DATA_DIR` unset (see above).
- **Logs.** Server logs can hold the redacted messages of failed jobs and `tshark`'s error output. Treat them as you would any application log. NeMo's own logger is set to warnings only, since it logs the text under check at lower levels.
- **Scans.** Leave `AEGIS_AI_SCAN` unset unless you want visitors to be able to run garak scans (see AI workflow scans above).

The Docker image runs as an unprivileged user (uid 10001), has no compiler, installs Python packages from prebuilt wheels only, and leaves the app tree owned by root and read-only to the app user. It copies in only the files the app needs at run time (`Dockerfile`, `.dockerignore`).

## What the app does not protect against

- **Anyone who can reach it.** There is no authentication, and no per-address rate limiting: the job caps bound the server, not one visitor.
- **`tshark` itself.** `tshark` parses untrusted files and is not sandboxed beyond the resource limits above (and has none of those limits off Linux or without `prlimit`).
- **garak itself.** garak is third-party code run as a subprocess with a minimal environment and no outside network for the offered probes, but it is not otherwise sandboxed, and it has no memory limit.
- **Instructions hidden in text.** The safeguards are pattern rules and can be phrased around. They lower the chance that hidden text steers a model call; they do not remove it.
- **Run links.** A `?run=` URL is a bearer link to a running job until 30 seconds after the job ends (see Storage).
- **Data you send to outside services.** Descriptions, selected technologies, uploaded architecture images, policy inputs, and PCAP summaries are sent to the model provider you choose (Anthropic, Amazon Bedrock, OpenAI, or Google's Gemini API) when you run a model step. Product names and versions go to NVD as CPE names; technology names go to endoflife.date and OTX; CVE ids go to FIRST EPSS; and the industry sector you select goes to OTX during a threat model. The CISA KEV catalog and the ExploitDB index are downloaded whole, so nothing about your request is sent for them. What those services keep is governed by their own terms. Do not submit secrets or data your organization has not approved for that use.
- **The server operator.** Whoever runs the server can read its memory and logs, including keys while a session holds them.
- **Model output.** Threat models, policies, compliance mappings, and PCAP analyses are drafts written by a language model. They can be wrong, incomplete, or steered by text in what you submit. Escaping keeps that text from running in your browser; it does not make the content correct. A person must review it before relying on it.
- **Your browser's own requests.** Pages load the Geist and JetBrains Mono fonts from Google Fonts.

The app never scans, probes, or sends traffic to a system you describe or look up. The optional AI workflow scan sends garak's prompts, through a loopback endpoint, only to a model from the app's own list, through the app's own client.

## Development checks

Run from the repository root:

```sh
python -m pytest -q
ruff check .
```

The tests make no network calls and need no keys: `tests/conftest.py` fails any connection or name lookup outside the loopback interface. The tests run no backend against a real provider; each is tested against fakes that use its SDK's real response shapes.

## Contact

For security concerns that don't constitute vulnerabilities, please open a discussion on GitHub or contact the maintainers through appropriate channels.

---

**Last Updated**: 2026-11-16
