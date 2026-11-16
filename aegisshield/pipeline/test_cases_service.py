"""Gherkin validation tests for the threats of a threat model."""

from __future__ import annotations

from aegisshield.llm.base import LLMClient, OnText
from aegisshield.pipeline.sector_context import focus_block


def create_test_cases_prompt(threats: str, focus: str | None = None) -> str:
    """The test cases prompt; ``focus`` is the agentic Lead's note for this section."""
    return f"""
Act as a cyber security expert with more than 20 years experience using STRIDE.
Provide Gherkin test cases for the identified threats.

Each threat has an ID (TC-S01, TC-T01, etc.). For each threat, produce one Gherkin feature
titled with the threat ID (e.g. "## TC-S01"). Do NOT copy the full scenario text into the
test-case title; use just the ID.

Threats (for reference):
{threats}

Output format for each threat:

## <ID>

```gherkin
Feature: <short feature name for this threat>
  Scenario: <short scenario name>
    Given ...
    When ...
    Then ...
```

Use concrete details from the threat's scenario in the Given/When/Then steps so the test is
specific. Return only the test cases.
{focus_block(focus)}""".strip()


def generate_test_cases(
    llm: LLMClient,
    model: str,
    threats_markdown: str,
    on_text: OnText | None = None,
    focus: str | None = None,
) -> str:
    """Ask the model for one Gherkin feature per threat id, as markdown."""
    prompt = create_test_cases_prompt(threats_markdown, focus)
    return llm.chat_text(
        system="You provide Gherkin test cases in Markdown format.",
        user=prompt,
        model=model,
        on_text=on_text,
    )
