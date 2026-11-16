"""A deterministic ``LLMClient`` for running the app with no key and no network.

Turned on with ``AEGIS_MOCK_LLM=1``. It answers every kind of request the
services make (threat model JSON, technique selection, ATLAS selection, attack tree,
mitigations, DREAD JSON, test cases, the lead plan, policy text, and packet
capture analysis) with canned output about an online retail checkout service.
The kind of request is read from markers in the prompt text (see ``mock_json``
and ``mock_text``).

With ``on_text`` the answer is streamed in chunks, with an optional delay
between chunks so the live progress view can be exercised.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from typing import Any

from aegisshield.llm.base import (
    DEFAULT_IMAGE_MAX_TOKENS,
    DEFAULT_JSON_MAX_TOKENS,
    DEFAULT_TEXT_MAX_TOKENS,
    OnText,
    SafeText,
    normalize_media_type,
)

logger = logging.getLogger(__name__)

MOCK_NOTE = "Mock answer. Unset AEGIS_MOCK_LLM and add an OpenAI key for a real one."

MOCK_THREAT_MODEL: dict[str, Any] = {
    "threat_model": [
        {
            "Threat Type": "Spoofing",
            "Scenario": (
                "An attacker replays stolen customer session cookies to place orders "
                "as another shopper at checkout."
            ),
            "Assumptions": [{"name": "Sessions use signed cookies with a 30 day lifetime"}],
            "Potential Impact": "Fraudulent orders charged to saved payment methods.",
            "MITRE ATT&CK Keywords": ["valid accounts", "steal web session cookie"],
        },
        {
            "Threat Type": "Tampering",
            "Scenario": (
                "An attacker edits the cart total in the browser before the order is "
                "submitted, and the server trusts the client price."
            ),
            "Assumptions": [{"name": "Prices are recalculated only in the browser"}],
            "Potential Impact": "Goods sold below cost; revenue loss.",
            "MITRE ATT&CK Keywords": ["data manipulation", "exploit public-facing application"],
        },
        {
            "Threat Type": "Repudiation",
            "Scenario": (
                "A customer disputes a completed order and the service cannot show who "
                "placed it because order events are not logged."
            ),
            "Assumptions": [],
            "Potential Impact": "Chargebacks the merchant cannot contest.",
            "MITRE ATT&CK Keywords": ["indicator removal"],
        },
        {
            "Threat Type": "Information Disclosure",
            "Scenario": (
                "The order lookup endpoint returns another customer's shipping address "
                "when the order number is changed in the URL."
            ),
            "Assumptions": [{"name": "Order numbers are sequential"}],
            "Potential Impact": "Exposure of customer names and addresses.",
            "MITRE ATT&CK Keywords": ["data from information repositories"],
        },
        {
            "Threat Type": "Denial of Service",
            "Scenario": (
                "Bots flood the coupon validation endpoint during a sale and exhaust the "
                "checkout database connection pool."
            ),
            "Assumptions": [{"name": "No rate limit on coupon checks"}],
            "Potential Impact": "Checkout unavailable during peak sales.",
            "MITRE ATT&CK Keywords": ["endpoint denial of service"],
        },
        {
            "Threat Type": "Elevation of Privilege",
            "Scenario": (
                "A support agent account can call the refund API without a second "
                "approval and issue refunds to any card."
            ),
            "Assumptions": [{"name": "Refund API checks only that the caller is staff"}],
            "Potential Impact": "Unauthorized refunds and payment fraud.",
            "MITRE ATT&CK Keywords": ["abuse elevation control mechanism"],
        },
    ],
    "improvement_suggestions": [
        "Describe how the checkout service talks to the payment provider.",
        "List which roles can issue refunds and how they sign in.",
        "Say where order and payment events are logged and for how long.",
    ],
}

_DEFAULT_IDS = ("TC-S01", "TC-T01", "TC-R01", "TC-I01", "TC-D01", "TC-E01")
# A threat id in the first cell of a markdown table row ("| TC-S01 | ...").
_TABLE_ID_RE = re.compile(r"^\|\s*(TC-[A-Z]\d{2,4})\s*\|", re.MULTILINE)
_LEAD_PLAN_RE = re.compile(r'"plan"\s*:\s*\[\s*\{\s*"section"')
_DREAD_RE = re.compile(r'"Risk Assessment"\s*:\s*\[')
# The agentic Teammate and Rebuttal system prompts show their answer shapes.
_TEAMMATE_RE = re.compile(r'\{"flags"\s*:\s*\[')
_REBUTTAL_RE = re.compile(r'\{"rebuttals"\s*:\s*\[')
MOCK_TEAMMATE_REVIEW: dict[str, Any] = {
    "flags": [
        {
            "threat": "TC-R01",
            "reason": "Order disputes are a payment provider process; keep it, but score it lower.",
        }
    ],
    "notes": "The draft fits a public checkout service.",
}

MOCK_REBUTTAL_REVIEW: dict[str, Any] = {
    "rebuttals": [
        {
            "threat": "TC-I01",
            "counterexample": "Order ids are random UUIDs, so changing the URL rarely finds another order.",
            "adjusted": "6",
            "reason": "Guessing is unlikely, but the ownership check is still missing.",
        }
    ]
}
_CANDIDATES_HEADER = "Candidate Techniques"
# The ATLAS step's system prompt shows its answer shape; its user prompt ends
# with each threat's candidate ids as JSON after this header.
_ATLAS_RE = re.compile(r'\{"atlas"\s*:\s*\[')
_ATLAS_CANDIDATES_HEADER = "ATLAS candidates per threat"

MOCK_ATTACK_TREE = """graph TD
    A["Compromise checkout"] --> B["TC-S01 Replay a stolen session"]
    A --> C["TC-T01 Change the cart total"]
    A --> D["TC-I01 Read another order"]
    B --> B1["Steal cookie through a malicious browser extension"]
    B --> B2["Reuse cookie before it expires"]
    C --> C1["Edit the price field in the request"]
    D --> D1["Change the order number in the URL"]
"""

MOCK_MITIGATIONS = """| Threat ID | Threat Type | Mitigation |
|-----------|-------------|------------|
| TC-S01 | Spoofing | Bind sessions to the device, shorten their lifetime, and ask for the card security code at checkout. |
| TC-T01 | Tampering | Recalculate every price and total on the server and ignore client totals. |
| TC-R01 | Repudiation | Log each order event with the account, time, and source address to append-only storage. |
| TC-I01 | Information Disclosure | Check that the signed-in customer owns the order before returning it; use random order ids. |
| TC-D01 | Denial of Service | Rate limit coupon checks per client and cache valid coupon codes. |
| TC-E01 | Elevation of Privilege | Require a second approver for refunds above a set amount. |
"""

MOCK_TEST_CASES = """## TC-S01 Session replay

```gherkin
Feature: Session binding at checkout
  Scenario: A replayed session cookie cannot place an order
    Given a customer session cookie copied to a new device
    When the copied session submits an order
    Then the order is refused and the customer is asked to sign in again
```

## TC-T01 Cart total tampering

```gherkin
Feature: Server side pricing
  Scenario: A changed cart total is ignored
    Given a cart with one item priced at 40.00
    When the client submits the order with a total of 1.00
    Then the order is charged 40.00
```
"""

MOCK_POLICY = """## Purpose

This policy sets the rules for protecting customer and payment data in the
online store. (Mock text: unset AEGIS_MOCK_LLM to generate a real policy.)

## Scope

All staff, contractors, and systems that handle orders or payments.

## Policy Statements

1. Payment card data is handled only by the payment provider and never stored.
2. Access to order data is granted by role and reviewed every quarter.
3. Every refund above the set limit needs a second approver.
4. Security events are logged and kept for at least one year.

## Review

This policy is reviewed every year and after any significant incident.
"""

MOCK_PCAP_ANALYSIS = """## Summary

The capture shows ordinary web checkout traffic with one anomaly.

## Findings

- **MEDIUM**: One client sent 1,200 requests to `/api/coupons/validate` in two
  minutes, which looks like automated coupon guessing. Rate limit the endpoint
  and review the source address.
- **INFORMATIONAL**: All payment traffic used TLS 1.3 to the payment provider.

## Next steps

1. Add a per-client rate limit on coupon validation.
2. Keep watching for the same pattern during the next sale.
"""

MOCK_IMAGE_DESCRIPTION = (
    "The diagram shows a browser talking to a web storefront, which calls a checkout "
    "API, an order database, and an external payment provider. The trust boundary "
    "sits between the storefront and the internet."
)

MOCK_LEAD_PLAN: dict[str, Any] = {
    "plan": [
        {"section": "STRIDE", "focus": "Checkout sessions, pricing, and refunds.", "skip": False},
        {"section": "MITRE", "focus": "Map each threat to web attack techniques.", "skip": False},
        {"section": "DREAD", "focus": "Rank threats by fraud loss.", "skip": False},
        {"section": "MITIGATIONS", "focus": "Server side controls first.", "skip": False},
        {"section": "TEST_CASES", "focus": "Tests for pricing and session reuse.", "skip": False},
    ],
    "rationale": "A public checkout handles money, so every section adds value.",
}

# Scores per STRIDE letter, so the DREAD answer is the same on every run.
_DREAD_SCORES = {
    "S": (8, 6, 6, 7, 5),
    "T": (7, 7, 6, 8, 6),
    "R": (5, 6, 5, 4, 4),
    "I": (8, 8, 7, 7, 7),
    "D": (6, 7, 7, 9, 6),
    "E": (9, 5, 4, 6, 4),
}
_DREAD_KEYS = (
    "Damage Potential",
    "Reproducibility",
    "Exploitability",
    "Affected Users",
    "Discoverability",
)


def _technique_choice(prompt: str) -> str:
    """The first candidate's ``technique_id`` from the prompt's candidate list.

    The prompt carries the candidates as a JSON list after a "Candidate
    Techniques" header, after the visitor's description, so the last header
    is the real one.
    """
    start = prompt.rfind(_CANDIDATES_HEADER)
    bracket = prompt.find("[", start) if start != -1 else -1
    choice = "NONE"
    if bracket != -1:
        try:
            candidates, _end = json.JSONDecoder().raw_decode(prompt, bracket)
        except json.JSONDecodeError:
            candidates = []
        first = candidates[0] if isinstance(candidates, list) and candidates else None
        if isinstance(first, dict) and isinstance(first.get("technique_id"), str):
            choice = first["technique_id"]
    return json.dumps({"technique_id": choice})


def _atlas_choice(prompt: str) -> dict[str, Any]:
    """Each threat's first ATLAS candidate, read from the JSON after the last
    candidates header (the threats and their scenarios come before it)."""
    start = prompt.rfind(_ATLAS_CANDIDATES_HEADER)
    brace = prompt.find("{", start) if start != -1 else -1
    picks: list[dict[str, str]] = []
    if brace != -1:
        try:
            per_threat, _end = json.JSONDecoder().raw_decode(prompt, brace)
        except json.JSONDecodeError:
            per_threat = {}
        for threat_id, ids in per_threat.items() if isinstance(per_threat, dict) else ():
            if isinstance(ids, list) and ids and isinstance(ids[0], str):
                picks.append({"threat_id": str(threat_id), "technique_id": ids[0]})
    return {"atlas": picks}


def _dread(prompt: str) -> dict[str, Any]:
    """One row per threat id in the prompt's threats table (not its examples)."""
    ids = list(dict.fromkeys(_TABLE_ID_RE.findall(prompt))) or list(_DEFAULT_IDS)
    rows = []
    for threat_id in ids:
        scores = _DREAD_SCORES.get(threat_id[3], (5, 5, 5, 5, 5))
        rows.append({"ID": threat_id, **dict(zip(_DREAD_KEYS, scores, strict=True))})
    return {"Risk Assessment": rows}


def mock_json(system: str, user: str) -> dict[str, Any]:
    """The canned JSON answer for a request.

    Chosen from markers the prompts always carry, not from words a
    visitor's description might contain: the lead plan's system prompt shows
    a ``"plan"`` with ``"section"`` entries, and the DREAD prompt shows the
    ``"Risk Assessment": [`` structure; the agentic Teammate and Rebuttal
    system prompts show ``{"flags": [`` and ``{"rebuttals": [``, and the ATLAS
    step's shows ``{"atlas": [`` (answered with each threat's first
    candidate). Everything else gets the threat model.
    """
    if _LEAD_PLAN_RE.search(system):
        return json.loads(json.dumps(MOCK_LEAD_PLAN))
    if _TEAMMATE_RE.search(system):
        return json.loads(json.dumps(MOCK_TEAMMATE_REVIEW))
    if _REBUTTAL_RE.search(system):
        return json.loads(json.dumps(MOCK_REBUTTAL_REVIEW))
    if _ATLAS_RE.search(system):
        return _atlas_choice(user)
    if _DREAD_RE.search(user):
        return _dread(user)
    return json.loads(json.dumps(MOCK_THREAT_MODEL))


def mock_text(system: str, user: str) -> str:
    """The canned text answer for a request, chosen from its system prompt.

    Every text service has its own system prompt, so the
    visitor's text in the user prompt never changes the route.
    """
    sys_lower = system.lower()
    if "attack techniques" in sys_lower:
        return _technique_choice(user)
    if "policy" in sys_lower:
        return MOCK_POLICY
    if "packet capture" in sys_lower:
        return MOCK_PCAP_ANALYSIS
    if "mermaid" in sys_lower or "attack tree" in sys_lower:
        return MOCK_ATTACK_TREE
    if "gherkin" in sys_lower or "test case" in sys_lower:
        return MOCK_TEST_CASES
    if "mitigation" in sys_lower:
        return MOCK_MITIGATIONS
    return MOCK_NOTE


class MockLLM:
    """An ``LLMClient`` with canned answers. Never touches the network."""

    def __init__(
        self,
        *,
        chunk_size: int = 40,
        chunk_delay_seconds: float = 0.0,
        call_delay_seconds: float = 0.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be at least 1")
        self._chunk_size = chunk_size
        self._delay = max(chunk_delay_seconds, 0.0)
        # A pause for a call answered without streaming (no ``on_text``), so
        # a mock run of a path that does not stream (the agentic one) takes
        # long enough for its live view to play.
        self._call_delay = max(call_delay_seconds, 0.0)
        self._sleep = sleep

    def _pause_unstreamed(self, on_text: OnText | None) -> None:
        if on_text is None and self._call_delay:
            self._sleep(self._call_delay)

    def _stream(self, text: str, on_text: OnText | None) -> None:
        if on_text is None:
            return
        safe = SafeText(on_text)
        for start in range(0, len(text), self._chunk_size):
            if self._delay and start:
                self._sleep(self._delay)
            safe(text[start : start + self._chunk_size])

    def chat_text(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_TEXT_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> str:
        """Return canned text for the request (see ``LLMClient.chat_text``)."""
        logger.info("mock chat_text model=%s", model)
        text = mock_text(system, user)
        self._pause_unstreamed(on_text)
        self._stream(text, on_text)
        return text

    def chat_json(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_JSON_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> dict[str, Any]:
        """Return a canned JSON object (see ``LLMClient.chat_json``)."""
        logger.info("mock chat_json model=%s", model)
        value = mock_json(system, user)
        self._pause_unstreamed(on_text)
        self._stream(json.dumps(value, indent=2), on_text)
        return value

    def describe_image(
        self,
        *,
        image_bytes: bytes,
        media_type: str,
        prompt: str,
        model: str,
        max_tokens: int = DEFAULT_IMAGE_MAX_TOKENS,
    ) -> str:
        """Return a canned diagram description (see ``LLMClient.describe_image``)."""
        normalize_media_type(media_type)
        logger.info("mock describe_image model=%s", model)
        return MOCK_IMAGE_DESCRIPTION
