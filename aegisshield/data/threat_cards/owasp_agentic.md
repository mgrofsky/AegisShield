# OWASP Agentic Security Initiative — Top Threats

When the application autonomously decides actions (multi-step planning,
tool use, agent loops, MCP servers, code execution sandboxes), the LLM
threats above apply *plus* the agent-specific threats below.

- **ASI01 — Memory Poisoning.** Long-lived agent memory absorbs adversarial
  inputs that bias future runs. Mitigations: scoped/expiring memory, signed
  memory entries, isolation between users / tenants / sessions.

- **ASI02 — Tool Misuse.** Agent invokes legitimate tools in unintended ways
  (over-broad SQL, destructive APIs, lateral filesystem access). Mitigations:
  per-tool capability scoping, dry-run mode, allow-listed parameters,
  policy engine on tool inputs.

- **ASI03 — Privilege Compromise.** Agent runs with credentials beyond the
  initiating user. Mitigations: per-run scoped tokens, request user
  re-consent for elevated actions, no shared "service" roles.

- **ASI04 — Resource Overload.** Agent loops or fan-out tool calls exhaust
  cost, rate, or compute budgets. Mitigations: max steps, budget caps,
  token meters, kill-switch endpoints.

- **ASI05 — Cascading Hallucinations.** Hallucinated output from one step
  becomes input to the next, compounding errors. Mitigations: grounding at
  every step, structured handoffs (typed schemas), validation between steps.

- **ASI06 — Intent Breaking & Goal Manipulation.** Adversary nudges the
  agent toward an unstated goal (e.g., via injected retrieval text).
  Mitigations: explicit goal declaration, policy guardrails, telemetry on
  goal drift.

- **ASI07 — Misaligned & Deceptive Behavior.** Agent reports success while
  taking unsafe shortcuts. Mitigations: independent verification step, audit
  log of every tool call, post-hoc evaluators.

- **ASI08 — Repudiation.** Lack of audit means a harmful action cannot be
  attributed. Mitigations: signed action logs, per-action user-attributable
  identity, append-only ledger.

- **ASI09 — Identity Spoofing & Impersonation.** Agent acts as another user
  or system. Mitigations: short-lived caller-bound credentials, mTLS between
  agents, refuse anonymous tool calls.

- **ASI10 — Multi-Agent System Risks.** Inter-agent traffic carries injection
  payloads or impersonation. Mitigations: signed inter-agent messages,
  capability-based access between agents, supervisor agent enforcing policy.

- **ASI11 — Unexpected Code Execution.** Agent writes/runs code that escapes
  the sandbox. Mitigations: hardened sandbox (gVisor, Firecracker), read-only
  base image, network egress allow-list, no network in code-exec sandbox by
  default.
