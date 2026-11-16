# OWASP Top 10 for LLM Applications (2025)

When the application embeds a large language model in any role (chat, agent,
RAG retriever, classifier), enumerate threats against each of the categories
below in addition to the STRIDE categories. Each item lists what the threat
is, where it tends to occur, and the canonical mitigation lever.

- **LLM01 — Prompt Injection.** Untrusted text reaches the model and overrides
  the system prompt. Direct injection comes from the user; indirect injection
  comes from retrieved documents, tool outputs, or images. Mitigations:
  separate trust boundaries on the prompt, output filtering, deny lists for
  tool actions, refusing to follow instructions from retrieved content.

- **LLM02 — Sensitive Information Disclosure.** The model emits secrets it saw
  in training data, system prompts, or prior retrieval results. Mitigations:
  input/output redaction, role-scoped retrieval, no secrets in system prompts,
  red-team for memorisation.

- **LLM03 — Supply Chain.** Compromised base model, fine-tune, dataset, or
  plugin reaches the production pipeline. Mitigations: pinned model versions,
  signed checkpoints, allow-listed plugin registries, SBOM for ML artifacts.

- **LLM04 — Data and Model Poisoning.** Adversaries plant samples in training
  data, fine-tune feedback, or RAG sources to bias outputs. Mitigations:
  curated data sources, anomaly detection on training inputs, segregation of
  feedback channels by user trust level.

- **LLM05 — Improper Output Handling.** Caller treats LLM output as safe HTML,
  SQL, shell, or filesystem input and ends up with XSS, SQLi, RCE, or path
  traversal. Mitigations: encode/escape at the boundary, never feed raw LLM
  output into eval/exec or templating without sanitisation.

- **LLM06 — Excessive Agency.** Tools give the LLM more privilege than the
  user actually has. Mitigations: principle of least privilege per tool,
  human-in-the-loop on destructive actions, scoped credentials per agent run.

- **LLM07 — System Prompt Leakage.** Prompts that contain credentials, tenant
  IDs, or hidden rules are extracted by adversarial inputs. Mitigations:
  treat the system prompt as semi-public, do not put secrets in it, monitor
  for extraction attempts.

- **LLM08 — Vector and Embedding Weaknesses.** Embedding stores, retrieval
  pipelines, and re-rankers can leak data, enable injection, or be poisoned.
  Mitigations: row-level access control on the vector store, validate
  retrieved chunks before they enter the prompt, hash-pin chunk versions.

- **LLM09 — Misinformation.** The model produces confident, false output.
  Mitigations: grounding, citations, refusal-to-answer, calibrated confidence,
  domain-specific fine-tuning, human review on sensitive outputs.

- **LLM10 — Unbounded Consumption.** Token amplification, recursive prompts,
  or expensive tool calls drive cost or denial of service. Mitigations:
  per-tenant token quotas, max-iterations on agent loops, cost meters,
  circuit breakers on tool invocations.
