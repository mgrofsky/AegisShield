"""A visitor's saved work, held in memory and exportable as JSON.

A visitor saves threat models, policies, the organization profile, lookups,
packet capture analyses, and AI workflow scans. A public Streamlit deployment is one process
shared by anonymous visitors, so a shared store such as a database would leak
one visitor's work to another. Here each visitor has a ``Workspace`` kept in
their own session (see ``stores.py``), and can download it with ``to_json``
and load it again with ``from_json``.

Every record has the same shape: ``id``, ``created_at`` (UTC ISO 8601),
``title``, and a JSON ``payload``. The payload keys the pages store per kind
are listed in ``PAYLOAD_KEYS`` (a test holds the list to what they store).
"""

from __future__ import annotations

import builtins
import json
import math
import secrets
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from aegisshield.core.errors import WorkspaceError
from aegisshield.core.text import single_line

SCHEMA_VERSION = 1
MAX_TITLE_CHARS = 200
_MAX_ID_CHARS = 64

# Limits on what a workspace may hold, checked on every save and import. An
# import is untrusted: the pages render what it holds, and Python holds the
# interpreter lock for the whole of one ``json.loads`` or one pattern match,
# so an oversized value would stall every visitor's session. Measured on
# this app's own records (a full mock threat model is about 34 KB, its
# longest string 10,393 characters; the longest string in a recorded real
# run is 13,407; the deepest nesting in any fixture is 11 levels and the
# longest list 1,518 items), each limit leaves wide headroom:
#
# - MAX_WORKSPACE_BYTES: 10 MB holds about a hundred real threat models or
#   thirty worst-case packet analyses. ``json.loads`` of 10 MB of the
#   smallest values blocks other threads for about 0.1 s; at 25 MB it was
#   0.25 s.
# - MAX_CONTAINERS: JSON arrays and objects, counted on the raw bytes before
#   parsing (a bracket inside a string counts too). 10 MB of nested empty
#   arrays took 0.19 s to parse; a mock threat model has 133.
# - MAX_STRING_CHARS: twice the longest text a page saves (a packet analysis
#   is clipped to 100,000 characters; a model answer is bounded by its
#   16,000-token limit) and the most any renderer shows.
# - MAX_DEPTH, MAX_LIST_ITEMS, MAX_RECORDS: nesting, one list or object, and
#   one collection.
#
# An AI workflow scan record is held to its own caps before it is saved
# (aiscan.service: at most 100 attempts, three answers each, 2,000
# characters per text). The largest possible one, every character four
# bytes, is about 3.3 MB in this file's indented JSON, with fewer than 1,000
# containers and no string over 2,000 characters; a scan with the page's
# defaults is about a tenth of that. The limits above hold it unchanged.
MAX_WORKSPACE_BYTES = 10 * 1024 * 1024
MAX_CONTAINERS = 100_000
MAX_STRING_CHARS = 200_000
MAX_DEPTH = 32
MAX_LIST_ITEMS = 10_000
MAX_RECORDS = 500
_MAX_MB = MAX_WORKSPACE_BYTES // (1024 * 1024)


class RecordKind(StrEnum):
    """The collections a workspace holds (the organization profile is separate)."""

    THREAT_MODELS = "threat_models"
    POLICIES = "policies"
    LOOKUPS = "lookups"
    PCAP_ANALYSES = "pcap_analyses"
    AI_SCANS = "ai_scans"


ORG_PROFILE_KEY = "org_profile"

# What each payload is expected to hold. Documentation for the services that
# write records; the workspace itself only checks that a payload is a JSON object.
PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    # The wizard stores the job result (aegisshield.pipeline.run.assemble_result)
    # plus the request's profile and description. The add-on keys appear only
    # when those stages ran; the agentic keys only on the agentic path.
    RecordKind.THREAT_MODELS: (
        "profile",
        "description",
        # every run
        "threat_model",
        "improvement_suggestions",
        "improvement_suggestions_markdown",
        "threat_model_markdown",
        "mitre_attack_markdown",
        "nvd_vulnerabilities_markdown",
        "otx_data_markdown",
        "attack_tree_code",
        "mitre_data",
        "detected_patterns",
        "pattern_source",
        # an AI system's ATLAS mapping (pipeline.atlas_service.ATLAS_RESULT_KEY);
        # absent for any other system and in records saved before it existed
        "atlas_mapping",
        # the add-ons (linear) or the specialists (agentic)
        "mitigations_markdown",
        "dread_assessment",
        "dread_assessment_markdown",
        "test_cases_markdown",
        # agentic only
        "agentic",
        "lead_plan",
        "decider",
        "section_deciders",
        "teammate_review",
        "rebuttal_review",
        # the safeguards record (aegisshield.safeguards.REPORT_KEY) and the
        # application checks' flags (output_checks.REVIEW_FLAGS_KEY)
        "safeguards",
        "review_flags",
        # the ids of AI workflow scans attached to this threat model (scan page)
        "ai_scans",
        # which provider and model answered (aegisshield.llm.providers.answered_by);
        # absent from records saved before there were providers
        "model",
    ),
    # The policies page: what ``policy_service.generate_policy`` returns, plus
    # the catalog key, status, version, and ``edited`` once the visitor edits it.
    RecordKind.POLICIES: (
        "policy_key", "status", "version", "title", "body_markdown", "csf_mappings",
        "regulatory_citations", "edited", "safeguards", "model",
    ),
    # The lookup page: the request it sent and the lookup service's result.
    RecordKind.LOOKUPS: ("request", "result"),
    # The PCAP page: the uploaded file's name and size and the trimmed analysis.
    RecordKind.PCAP_ANALYSES: ("filename", "filesize_bytes", "result", "model"),
    # The AI workflow scan page: the scan record ``aiscan.service.build_record``
    # returns, stored as the payload itself.
    RecordKind.AI_SCANS: (
        "version", "status", "reasons", "settings", "probes", "attempts", "caps", "shim", "report",
        "safeguards",
    ),
    # ``OrgProfile.to_dict()``.
    ORG_PROFILE_KEY: (
        "legal_name",
        "dba_name",
        "industry",
        "employee_count",
        "leadership",
        "compliance_drivers",
        "regulatory_notes",
    ),
}

_TOP_LEVEL_KEYS = frozenset({"schema_version", ORG_PROFILE_KEY, *RecordKind})
_RECORD_KEYS = frozenset({"id", "created_at", "title", "payload"})


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _check_value(value: object) -> None:
    """Raise ``WorkspaceError`` unless ``value`` is plain JSON within the limits.

    One iterative walk, so neither a deep value nor a large one can exhaust
    the stack or hold the interpreter lock for long.
    """
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, str):
            if len(item) > MAX_STRING_CHARS:
                raise WorkspaceError(f"A text value is longer than {MAX_STRING_CHARS:,} characters.")
        elif item is None or isinstance(item, bool | int):
            continue
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise WorkspaceError("A record's payload must hold only JSON values (no NaN or infinity).")
        elif isinstance(item, dict | list):
            if depth > MAX_DEPTH:
                raise WorkspaceError(f"The data is nested more than {MAX_DEPTH} levels deep.")
            if len(item) > MAX_LIST_ITEMS:
                raise WorkspaceError(f"A list or object holds more than {MAX_LIST_ITEMS:,} items.")
            if isinstance(item, dict):
                for key in item:
                    if not isinstance(key, str):
                        raise WorkspaceError("A record's payload must hold only JSON values.")
                    if len(key) > MAX_STRING_CHARS:
                        raise WorkspaceError(f"A text value is longer than {MAX_STRING_CHARS:,} characters.")
                stack.extend((child, depth + 1) for child in item.values())
            else:
                stack.extend((child, depth + 1) for child in item)
        else:
            raise WorkspaceError("A record's payload must hold only JSON values.")


def _check_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise WorkspaceError("A record's payload must be a JSON object.")
    _check_value(payload)
    return payload


@dataclass(frozen=True)
class Record:
    """One saved item. ``payload`` is a JSON object; treat it as read-only."""

    id: str
    created_at: str
    title: str
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def new(cls, title: str, payload: dict[str, Any]) -> Record:
        """A record with a fresh random id and the current UTC time."""
        return cls(
            id=secrets.token_urlsafe(16),
            created_at=_now_iso(),
            title=single_line(title, MAX_TITLE_CHARS),
            payload=_check_payload(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        """The record as plain JSON values."""
        return {
            "id": self.id,
            "created_at": self.created_at,
            "title": self.title,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: object) -> Record:
        """Validate and build a record from JSON values. Raises ``WorkspaceError``."""
        if not isinstance(data, dict):
            raise WorkspaceError("Each record must be a JSON object.")
        if set(data) != _RECORD_KEYS:
            raise WorkspaceError("A record has missing or unknown fields.")
        record_id, created_at, title = data["id"], data["created_at"], data["title"]
        if not isinstance(record_id, str) or not 0 < len(record_id) <= _MAX_ID_CHARS:
            raise WorkspaceError("A record id is missing or too long.")
        if not isinstance(created_at, str):
            raise WorkspaceError("A record's created_at must be a string.")
        try:
            datetime.fromisoformat(created_at)
        except ValueError:
            raise WorkspaceError("A record's created_at is not a date and time.") from None
        if not isinstance(title, str):
            raise WorkspaceError("A record's title must be a string.")
        return cls(
            id=record_id,
            created_at=created_at,
            title=single_line(title, MAX_TITLE_CHARS),
            payload=_check_payload(data["payload"]),
        )


def _sort_key(record: Record) -> datetime:
    stamp = datetime.fromisoformat(record.created_at)
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)


class Workspace:
    """A visitor's organization profile and saved records."""

    def __init__(self) -> None:
        self.org_profile: Record | None = None
        self._items: dict[RecordKind, dict[str, Record]] = {kind: {} for kind in RecordKind}

    # Organization profile --------------------------------------------------

    def set_org_profile(self, title: str, payload: dict[str, Any]) -> Record:
        """Replace the organization profile and return the new record."""
        self.org_profile = Record.new(title, payload)
        return self.org_profile

    def clear_org_profile(self) -> None:
        """Remove the organization profile."""
        self.org_profile = None

    # Collections -----------------------------------------------------------

    def add(self, kind: RecordKind | str, title: str, payload: dict[str, Any]) -> Record:
        """Save a new record of ``kind`` and return it."""
        record = Record.new(title, payload)
        self._items[RecordKind(kind)][record.id] = record
        return record

    def get(self, kind: RecordKind | str, record_id: str) -> Record | None:
        """The record with ``record_id``, or None."""
        return self._items[RecordKind(kind)].get(record_id)

    def list(self, kind: RecordKind | str) -> builtins.list[Record]:
        """Records of ``kind``, newest first (later additions first on a tie)."""
        items = builtins.list(reversed(self._items[RecordKind(kind)].values()))
        return sorted(items, key=_sort_key, reverse=True)

    def rename(self, kind: RecordKind | str, record_id: str, title: str) -> Record | None:
        """Give a record a new title, keeping its id, time, and payload.

        Returns the updated record, or None if there is no such record.
        """
        items = self._items[RecordKind(kind)]
        record = items.get(record_id)
        if record is None:
            return None
        items[record_id] = replace(record, title=single_line(title, MAX_TITLE_CHARS))
        return items[record_id]

    def update_payload(self, kind: RecordKind | str, record_id: str, payload: dict[str, Any]) -> Record | None:
        """Replace a record's payload, keeping its id, time, and title.

        Returns the updated record, or None if there is no such record.
        Raises ``WorkspaceError`` for a payload ``Record.new`` would refuse.
        """
        items = self._items[RecordKind(kind)]
        record = items.get(record_id)
        if record is None:
            return None
        items[record_id] = replace(record, payload=_check_payload(payload))
        return items[record_id]

    def delete(self, kind: RecordKind | str, record_id: str) -> bool:
        """Remove a record. True if it existed."""
        return self._items[RecordKind(kind)].pop(record_id, None) is not None

    # Export and import -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """The workspace as plain JSON values."""
        data: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            ORG_PROFILE_KEY: self.org_profile.to_dict() if self.org_profile else None,
        }
        for kind in RecordKind:
            data[kind.value] = [r.to_dict() for r in self._items[kind].values()]
        return data

    def to_json(self) -> bytes:
        """UTF-8 JSON for download or a file store.

        Raises ``WorkspaceError`` when ``from_json`` would refuse the result
        (over the size, container, or record limits), so a saved file always
        loads again.
        """
        if any(len(items) > MAX_RECORDS for items in self._items.values()):
            raise WorkspaceError(f"A collection holds more than {MAX_RECORDS} records, so the workspace "
                                 "cannot be saved. Delete some first.")
        data = json.dumps(self.to_dict(), ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8")
        if len(data) > MAX_WORKSPACE_BYTES:
            raise WorkspaceError(f"The workspace is larger than {_MAX_MB} MB and cannot be saved.")
        if data.count(b"[") + data.count(b"{") > MAX_CONTAINERS:
            raise WorkspaceError("The workspace holds more lists, objects, and brackets than a file can, "
                                 "so it cannot be saved. Delete some items first.")
        return data

    @classmethod
    def from_json(cls, data: bytes) -> Workspace:
        """Load a workspace exported by ``to_json``. Raises ``WorkspaceError``.

        Rejects, before parsing, files over ``MAX_WORKSPACE_BYTES`` or with
        more than ``MAX_CONTAINERS`` brackets and braces; then text that is
        not UTF-8 JSON, a different ``schema_version``, unknown top-level
        keys, wrong types, duplicate record ids, and anything over the
        string, depth, list, and record limits.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise WorkspaceError("A workspace file must be bytes.")
        if len(data) > MAX_WORKSPACE_BYTES:
            raise WorkspaceError(f"The workspace file is larger than {_MAX_MB} MB.")
        if data.count(b"[") + data.count(b"{") > MAX_CONTAINERS:
            raise WorkspaceError("The workspace file holds more lists and objects than this app ever saves.")
        try:
            raw = json.loads(bytes(data).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise WorkspaceError("The workspace file is not valid JSON.") from None
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: object) -> Workspace:
        """Validate and build a workspace from JSON values. Raises ``WorkspaceError``."""
        if not isinstance(raw, dict):
            raise WorkspaceError("The workspace file must hold a JSON object.")
        if set(raw) - _TOP_LEVEL_KEYS:
            raise WorkspaceError("The workspace file has fields this version does not know.")
        version = raw.get("schema_version")
        if isinstance(version, bool) or version != SCHEMA_VERSION:
            raise WorkspaceError("The workspace file is from an unsupported version.")
        workspace = cls()
        profile = raw.get(ORG_PROFILE_KEY)
        if profile is not None:
            workspace.org_profile = Record.from_dict(profile)
        for kind in RecordKind:
            entries = raw.get(kind.value, [])
            if not isinstance(entries, builtins.list):
                raise WorkspaceError("Each record collection must be a list.")
            if len(entries) > MAX_RECORDS:
                raise WorkspaceError(f"A collection holds more than {MAX_RECORDS} records.")
            bucket = workspace._items[kind]
            for entry in entries:
                record = Record.from_dict(entry)
                if record.id in bucket:
                    raise WorkspaceError("The workspace file has a repeated record id.")
                bucket[record.id] = record
        return workspace
