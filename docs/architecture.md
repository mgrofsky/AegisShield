# Architecture

AegisShield is one Streamlit app started with `streamlit run main.py`. `main.py` only calls `aegisshield.ui.app.run()`. There is no database, no separate worker process, and no Node build step. Every visitor is served by the same Python process.

The [data-flow diagram](diagrams/README.md) shows the trust boundaries and the numbered data flows on one page.

## Layers

| Package | What it holds |
|---------|---------------|
| `aegisshield/ui` | The app frame (`app.py`), the page table (`routes.py`), one module per page under `pages/`, session state (`state.py`), shared widgets (`kit.py`), and the two live-view components under `components/`. |
| `aegisshield/pipeline` | The threat-model pipeline: the linear workflow (`workflow_service.py`), the agentic path (`agentic_threat_model.py`), each stage's service, the NVD and OTX lookups the run uses, and the live deck builder (`live_deck.py`). `run.py` is its one entry point. |
| `aegisshield/services` | Everything else the pages call: the vulnerability lookup and its sources, NIST CSF and EU AI Act mapping, policy drafting, PCAP analysis, the organization profile, and the PDF, HTML, JSON, and SARIF exports. Every PDF goes through `pdf_render.html_to_pdf`, which loads nothing over the network and reads no local file. |
| `aegisshield/llm` | The `LLMClient` protocol and the fixed sentences every backend raises (`base.py`); four backends, each importing its SDK only when used: Claude (`anthropic_client.py`), Amazon Bedrock (`bedrock_client.py`, with a visitor's Bedrock API key or AWS access keys), OpenAI (`openai_client.py`, with its chat-model list rule in `openai_models.py`), and Gemini (`gemini_client.py`); `providers.py`, which names the providers, holds the visitor's `Credential`, and asks a provider for its live model list; the mock client; `get_llm`, which picks one, and `SusceptibleLLM` (`susceptible.py`), a simulated model that follows injected instructions, used by tests, the safeguards evaluation, and scans without a key. |
| `aegisshield/safeguards` | The checks on every model call: `Safeguards` (`core.py`) decides when checks run and what is recorded, and wraps a model client so every answer is checked; `engine.py` runs the NeMo Guardrails rails (`rails/config.yml`, `rails/rails.co`, and the actions in `rails/actions.py`) through `LLMRails.check_async` with no model; `detect.py` holds the local detectors the actions call; `summary.py` words the record for views and exports. |
| `aegisshield/aiscan` | AI workflow scans: the approved surfaces (`surfaces.py`), the loopback shim garak talks to (`shim.py`), the garak subprocess (`garak_run.py`), the report parser (`report.py`), probes and limits, and `service.run_scan`, which the scan page runs as a job. |
| `aegisshield/jobs` | The in-process job runner. |
| `aegisshield/storage` | The per-visitor workspace and the stores that hold it. |
| `aegisshield/core` | Errors, retry with backoff, text sanitation, and logging setup. |
| `aegisshield/data` | Packaged reference data: MITRE ATLAS, NIST CSF 2.0, regulations, threat cards, and the technology-to-CPE map. The ATT&CK bundles are in `MITRE_ATTACK_DATA/` at the repository root. |

**Only `aegisshield/ui` imports Streamlit.** Everything below it is plain Python, tested without a Streamlit runtime. Services take the model client as an argument (`llm: LLMClient`). No test enforces this rule yet; this should print nothing:

```sh
grep -rlE '^\s*(import|from) streamlit' aegisshield --include='*.py' | grep -v '^aegisshield/ui/'
```

## Where the safeguards sit

The safeguards sit between the pipeline and the model client, not in the UI. Each job builds one `Safeguards` object (`Safeguards.from_settings`), and each service entry point takes it as `safeguards=` (building one from the settings when none is given):

- Where untrusted text enters a prompt, the entry point calls `screen(source, text)`: `run.prepare_description` (the description, the diagram text, an imported record, the lookup hand-off sentence), `run.screen_profile`, `workflow_service.gather_enrichment` (NVD and OTX text), `pcap_service.build_analysis_prompt` (capture text), and `policy_service.screen_org_profile`.
- Every model call goes through `wrap(llm)`, a `GuardedLLM` that runs the output rails on each answer, holds streamed text at least 256 characters behind the model (and at open markup), and tells the live view to drop an answer that is withheld or whose call fails (`retract()` on the stage stream and on the tool pages' streaming progress).
- `report()` is stored with the result under `safeguards`; `output_checks.review_flags` adds `review_flags` to a threat model. `aegisshield/ui/safeguards_view.py` shows both.

The scan service sits beside the job runner: the scan page submits `run_scan` as a job of kind `ai_scan` (one at a time in the process), which starts the shim and the garak subprocess. The shim calls one surface from `aiscan/surfaces.py` with fresh safeguards for each call. The page offers only `visitor_workflow`, which makes each prompt the user's message of one `chat_text` call with the visitor's system prompt and the provider and model chosen in Settings, through the same `get_llm` client a threat-model run uses (each call capped at 1,024 output tokens); the three surfaces that call the app's own entry points as a page would are developer checks the service refuses unless asked for them explicitly. `aiscan/taxonomy.py` maps each offered probe to MITRE ATLAS techniques.

## How a threat-model run flows

1. **Wizard.** `aegisshield/ui/pages/threat_model_new.py` collects the description, the application profile, and the technologies. Generate calls `start_run` in `aegisshield/ui/threat_model_run.py`.
2. **Start.** `start_run` reads the visitor's keys and provider credential once, builds the model client with `get_llm`, and submits a closure to the runner through `state.start_job`. The closure calls `run_threat_model` in `aegisshield/pipeline/run.py`. The job id goes into the session and into the page URL (`?run=`), so a reload, which starts a new Streamlit session, can find the job again.
3. **Run.** The runner (`aegisshield/jobs/runner.py`) runs the closure on its own thread. `run_threat_model` takes the linear path (`run_threat_model_workflow`) or the agentic path (`orchestrate_threat_model`), and as it goes it calls `progress.set(record)` with a whole new progress record.
4. **Poll.** The wizard's live panel is an `st.fragment` that reruns every second while the job runs. Each rerun calls `poll()`, which takes a snapshot of the job and passes its progress record to the live view.
5. **Settle.** When the job ends, `poll()` settles it once: a finished result is saved to the workspace as a threat-model record, and the job is discarded from the runner. The fragment then asks for one full rerun so the results appear below the live view.

The runner hands out deep copies only (`ProgressSink.set`, `JobRunner.snapshot`), so a job thread and a page never share a mutable object.

### ATT&CK and ATLAS mapping

Every run maps each threat to one MITRE ATT&CK technique (`pipeline/mitre_service.py`): a keyword filter keeps at most 25 ATT&CK candidates, the model picks one, and an id the catalog does not hold falls back to the first candidate. For an AI system (`pipeline/ai_system.py`: an AI application type, or any AI pattern chosen or detected; the catalog, the threat cards, the results view, and the EU AI Act view all ask it) the same stage then makes one more model call (`pipeline/atlas_service.py`). For each threat it ranks the ATLAS techniques and sub-techniques by the words they share with the threat's scenario, impact, and keywords, weighted by how rare each word is in ATLAS and helped a little by the application's AI patterns and the threat's STRIDE category, and keeps the best ten. One request carries every threat with its candidate ids and each distinct candidate once (id, name, tactic, first sentence of its description). The model answers one id or NONE per threat. An id counts only if the ATLAS catalog holds it and it was one of that threat's candidates; NONE, or an id that fails the check, is stored as no ATLAS technique, never replaced by a guess. The ATLAS mitigations and case studies for each mapped technique are read from the bundled catalog (`catalog_service.atlas_mitigations_for`, `atlas_case_studies_for`; a sub-technique with none of its own shows its parent's and says so), at most five of each with the total. The result holds them under `atlas_mapping`, with the ATT&CK and ATLAS data versions; a non-AI run has no such key, and its prompts, result, and exports are unchanged. The mitigations step gets each mapped technique's mitigation names as a short reference. Case-study text never enters a prompt, because some case studies quote real injection payloads; a test checks every catalog string that can reach a prompt against the safeguards' detectors. If the ATLAS call fails, the run keeps its ATT&CK mapping and records the ATLAS step as failed.

## The progress record

The record is the only thing the live views read, so its shape is a contract between the pipeline and the components' JavaScript. There are two kinds:

- **Linear path**: `office: true`, `stages` (eleven stages in a fixed order, from `serialize` through `test_cases`, each with an id, label, phase, status, detail, reason, and start and finish times), `step`, `total` (8, or 11 with the add-ons), `current`, and a `deck` holding display data: threats as they are written, then each threat's technique, attack-path steps, fix, DREAD score, and test, plus what the NVD and OTX lookups returned.
- **Agentic path**: `agentic: true`, `step`, `total`, `current`, a `lead` with a status and a note, and `agents`, the roster of specialists with each one's status, activity, and findings.

Everything in a record is model or visitor text capped in length (`aegisshield/pipeline/live_deck.py` lists the caps). No prompt text, key, model id, or exception text goes into it.

`tests/aegisshield/pipeline/record_shape.py` holds the structural checks. They run against records captured from real runs (`tests/fixtures/`) and against every record a full mock run writes (`tests/aegisshield/pipeline/test_pipeline_frames.py`, which also compares the run with `tests/fixtures/pipeline_mock_frames.json.gz`; regenerate it after an intended change with `AEGIS_REGEN_FIXTURES=1`). Change the shape only together with the JavaScript that reads it.

## The provider and model choice

A visitor picks a provider, enters its credential, and picks a model from the list that provider returned for that credential (`aegisshield/ui/state.py`: `selected_provider`, `credential`, `refresh_models`, `set_model_choice`, `model_choice`). `state.get_settings()` applies the choice with `config.with_model_choice`, which sets the provider, sets `architect_model` and `worker_model` both to the chosen model, and records whether the provider says the model reads images (`model_vision`). Every page reads its settings there, so every service that passes `settings.architect_model` or `settings.worker_model` (the linear and agentic threat-model runs, the diagram description, the capture analysis, the policy writer, and the AI workflow scan) uses the chosen model with no change of its own. `get_llm(settings, credential)` builds the client for `settings.provider` and refuses, with one fixed sentence, a provider the server does not offer (`AEGIS_PROVIDERS`), a missing credential field, a missing SDK, or an empty model. Each job stores `providers.answered_by(settings)` under `model` in its result (`{"provider", "name"}`; the scan record keeps it in `settings.model`), and the result views show it; older records show that it was not recorded. The model list is cached in the session for 10 minutes and dropped when the credential changes; `get_settings` reads only that cache and never asks a provider.

## Visitors sharing one process

The process is shared by anonymous visitors, so isolation is built in rather than added at the edge:

- **Job ids.** `secrets.token_urlsafe(32)`. The runner has no way to list jobs; a page can reach only a job whose id its session holds. While a job runs (threat model, lookup, policy, or capture analysis), its id is also in the page URL (`?run=`), so anyone with that URL can open the job while it runs and for 30 seconds after it ends (`ADOPT_AFTER_END_SECONDS`, so a reload that lands as the job ends still saves its result), and only until a session has taken its result. Each page removes the id from the URL when the job ends (`adopt_job` and `set_run_param` in `aegisshield/ui/state.py`).
- **Time to live.** Finished jobs are dropped 15 minutes after they end, or at once when the page discards them. A job still running at the timeout (30 minutes by default) is marked failed and told to stop. Both are checked when a job is submitted or read; there is no sweeper thread.
- **Limits.** At most `AEGIS_MAX_CONCURRENT_JOBS` jobs (default 4) run at once in the process, and per kind at most 1 capture analysis, 2 lookups, 2 policies, 3 threat models, and 1 AI workflow scan (`DEFAULT_JOB_KIND_LIMITS` in `aegisshield/config.py`, passed to `JobRunner` as `kind_limits`). A session runs at most one job of each kind.
- **Keys by value.** A key or provider credential is read from session state when the job starts and captured only in the job's closure. The runner drops the closure when the job ends. The runner is also handed the session's credential values (`state.session_secrets`), holds them only until the job starts, and uses them to remove the keys from a failure's log line. Keys never go into a job record, a progress record, the workspace, or a log line.
- **Workspace.** Each visitor's saved work is a `Workspace` (`aegisshield/storage/workspace.py`) held in their own `st.session_state` by `MappingStore`. `FileStore` (one file under `AEGIS_DATA_DIR`) exists for single-user installs and is shared by everyone who can open the app; `warn_if_shared_workspace` logs a warning once per process when it is in use.
- **Safeguards per job.** Each job gets its own `Safeguards` object and its own rails, so no module-level state holds one job's findings.
- **No module-level visitor state** apart from the job runner, whose jobs are reachable only by id. Process-wide caches hold only public data, such as the KEV catalog, the ExploitDB index, endoflife.date answers (at most 512 products, answers only, never failures), and the ATT&CK catalog.

`aegisshield/ui/state.py` is the only module that names session-state keys; pages go through its functions.

## The two live views

The wizard shows a run in one of two views: the **office** (`aegisshield/ui/components/office/`) for an agentic run, and the **deck** (`aegisshield/ui/components/deck/`) for a linear run.

- Each is a Streamlit custom component registered with `st.components.v2.component`. Its `__init__.py` reads the component's JavaScript and CSS, including a small `shim.js` that connects the view to Streamlit, and bundles them into one ES module string at import time. There is no build step.
- `render_live` in `aegisshield/ui/threat_model_run.py` draws one of them at the page's one live position, each with its own fixed key (`tm_office`, `tm_deck`). A fixed key lets Streamlit keep the same mounted view across reruns, so the animation keeps going while new records arrive. The deck is a module singleton in the browser, so a page shows at most one.
- Each folder's `README.md` describes its files, how the bundle is built, and what the component checks. The component tests check the bundle and the view's contract.

## Mock mode

`AEGIS_MOCK_LLM=1` makes `get_llm` return `MockLLM` (`aegisshield/llm/mock.py`) instead of a provider's client. It answers every kind of request the app makes with canned output about an online retail checkout service, streamed in chunks so the live views animate. No key is needed and no model provider is called. A banner shows while it is on.

Mock mode replaces only the model. The vulnerability lookup and a threat-model run still call their outside sources unless `AEGIS_OFFLINE` or a per-source switch turns them off; both ask `lookup_switches.source_disabled`, and a run shows a switched-off source as skipped (`workflow_service.lookup_off_reason`). `tools/mock_entry.py` starts the app with every outside source stubbed, for the browser checks.
