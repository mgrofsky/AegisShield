"""New threat model: a four-step wizard with the live deck while it runs.

Steps: Description, Technology, Threat model, Export. Every input is kept in
the session's wizard draft (``state.wizard_draft()``), so it survives a step
change, a rerun, and a page switch. The page also opens with:

- ``?id=<lookup record>``: technologies from a vulnerability lookup
  (``prefill_from_lookup``), applied once per record;
- ``?id=<threat model record>``: "Run again with these inputs", applied once;
- ``?run=<job>``: a run that was going when the browser reloaded.
"""

from __future__ import annotations

import base64
import binascii
import html
from collections.abc import Callable
from typing import Any

import streamlit as st

from aegisshield.core.errors import AegisError, ValidationError
from aegisshield.core.text import clip_words
from aegisshield.llm import get_llm
from aegisshield.llm.base import LLMImageError
from aegisshield.llm.providers import IMAGE_UNSUPPORTED
from aegisshield.pipeline.threat_model_service import analyze_architecture_image
from aegisshield.safeguards import SafeguardsStopped
from aegisshield.services.vuln_lookup import prefill_from_lookup
from aegisshield.storage import RecordKind
from aegisshield.ui import kit, options, state, tm_style, tool_parts
from aegisshield.ui import threat_model_run as runs
from aegisshield.ui.theme import Area, Tone
from aegisshield.ui.threat_model_view import render_exports, render_results

STEPS = ("Description", "Technology", "Threat model", "Export")
_HINTS = ("What the application does", "Context and stack", "Generate and watch", "Reports and files")
_W = "tmw_"  # widget-key prefix for this page

DESCRIPTION_SHORT = (f"Application description must be at least {options.MIN_DESCRIPTION_CHARS} "
                     "characters.")
DESCRIPTION_LONG = (f"Application description must be at most {options.MAX_DESCRIPTION_CHARS:,} "
                    "characters; it has {count:,}.")
DIAGRAM_LONG = (f"The diagram description must be at most {options.MAX_DIAGRAM_TEXT_CHARS:,} "
                "characters; it has {count:,}.")
PROFILE_MISSING = "Complete every required field: {fields}."
IMAGE_TYPE = "Only PNG and JPEG images are supported."
IMAGE_SIZE = "The image must be 10 MB or smaller."
MAX_IMAGE_MB = options.MAX_IMAGE_BYTES // (1024 * 1024)
LOOKUP_FAILED_NOTICE = "That lookup's technologies could not be loaded."

_REQUIRED = (
    ("app_type", "Application type", options.APP_TYPE_OPTIONS),
    ("industry_sector", "Industry sector", options.INDUSTRY_OPTIONS),
    ("sensitive_data", "Data sensitivity", options.DATA_SENSITIVITY_OPTIONS),
    ("internet_facing", "Internet-facing", options.INTERNET_FACING_OPTIONS),
    ("num_employees", "Number of employees", options.NUM_EMPLOYEES_OPTIONS),
    ("technical_ability", "Technical ability", options.TECHNICAL_ABILITY_OPTIONS),
)
_ADDONS = (
    ("mitigations", "Mitigations", "Recommended controls for each threat."),
    ("dread", "DREAD risk assessment", "Scores each threat so the worst come first."),
    ("test_cases", "Test cases", "Gherkin scenarios that check the key controls."),
)


# ------------------------------------------------------------ draft helpers


def _draft() -> dict[str, Any]:
    draft = state.wizard_draft()
    draft.setdefault("step", 0)
    draft.setdefault("reached", 0)
    draft.setdefault("technical_ability", "Medium")
    draft.setdefault("technologies", {})
    draft.setdefault("addons", {name: True for name, _, _ in _ADDONS})
    return draft


def _bound(field: str, default: Any, widget: Callable[..., Any], **kwargs: Any) -> Any:
    """Draw ``widget`` bound to ``draft[field]``: seeded from the draft and
    written back on every run, so the value outlives the widget."""
    draft = _draft()
    key = _W + field
    state.seed_widget(key, draft.get(field, default))
    value = widget(key=key, **kwargs)
    draft[field] = value
    return value


def _go(step: int) -> None:
    draft = _draft()
    draft["step"] = step
    draft["reached"] = max(int(draft.get("reached", 0)), step)


# --------------------------------------------------------------- validation


def description_error(draft: dict[str, Any]) -> str | None:
    """The step 1 message, or None when the description (and the diagram
    description, when it is used) is within its limits. The browser's
    ``max_chars`` is not relied on: these checks run on the server."""
    text = str(draft.get("description") or "").strip()
    if len(text) < options.MIN_DESCRIPTION_CHARS:
        return DESCRIPTION_SHORT
    if len(text) > options.MAX_DESCRIPTION_CHARS:
        return DESCRIPTION_LONG.format(count=len(text))
    diagram = str(draft.get("diagram_text") or "").strip()
    if draft.get("diagram_use", True) and len(diagram) > options.MAX_DIAGRAM_TEXT_CHARS:
        return DIAGRAM_LONG.format(count=len(diagram))
    return None


def profile_errors(draft: dict[str, Any]) -> list[str]:
    """Every step 2 message: missing required fields, then bad versions."""
    errors: list[str] = []
    missing = [label for field, label, choices in _REQUIRED if draft.get(field) not in choices]
    if missing:
        errors.append(PROFILE_MISSING.format(fields=", ".join(missing)))
    names = {choice.key: choice.name for choice in options.technology_choices()}
    for key, version in (draft.get("technologies") or {}).items():
        message = options.validate_version(version or "")
        if message and key in names:
            errors.append(f"{names[key]}: {message}")
    return errors


# ------------------------------------------------------------- hand-offs


def _apply_handoffs() -> None:
    """Fill the draft from a lookup or an earlier threat model, once per id."""
    record_id = state.requested_record_id()
    if not record_id:
        return
    draft = _draft()
    if draft.get("applied") == record_id:
        return
    workspace = state.get_workspace()
    lookup = workspace.get(RecordKind.LOOKUPS, record_id)
    model = workspace.get(RecordKind.THREAT_MODELS, record_id)
    if lookup is not None:
        _apply_lookup(draft, lookup.payload)
    elif model is not None:
        _apply_rerun(model.payload)
        draft = _draft()
    else:
        return
    draft["applied"] = record_id


def _apply_lookup(draft: dict[str, Any], payload: dict[str, Any]) -> None:
    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    prefill = prefill_from_lookup(result, options.form_catalog())
    selected = prefill.get("selected_technologies") or {}
    versions = prefill.get("selected_versions") or {}
    if not selected and not prefill.get("description"):
        draft["notice"] = (LOOKUP_FAILED_NOTICE, Tone.WARN.value)
        return
    techs = dict(draft.get("technologies") or {})
    for choice in options.technology_choices():
        if choice.parent is None and choice.name in selected and selected[choice.name] == choice.cpe:
            techs[choice.key] = versions.get(choice.name, "")
    draft["technologies"] = techs
    sentence = str(prefill.get("description") or "").strip()
    current = str(draft.get("description") or "").strip()
    if sentence and sentence not in current:
        draft["description"] = f"{current}\n\n{sentence}".strip()
    draft["notice"] = (str(prefill.get("notice") or ""), Tone.INFO.value)
    draft.setdefault("prefilled_from", "lookup")
    _forget_widgets()


def _apply_rerun(payload: dict[str, Any]) -> None:
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    description = str(payload.get("description") or "")
    diagram = ""
    if runs.DIAGRAM_HEADING in description:
        description, _, diagram = description.partition(runs.DIAGRAM_HEADING)
    techs: dict[str, str] = {}
    chosen = profile.get("selected_technologies") or {}
    versions = profile.get("selected_versions") or {}
    for choice in options.technology_choices():
        if chosen.get(choice.name) == choice.cpe and choice.key not in techs:
            version = str(versions.get(choice.name) or "")
            techs[choice.key] = "" if version == "*" else version
    draft: dict[str, Any] = {
        "description": description.strip(),
        "diagram_text": diagram.strip(),
        "diagram_use": bool(diagram.strip()),
        "technologies": techs,
        "notice": ("Filled in from an earlier threat model. Review before generating.",
                   Tone.INFO.value),
        "reached": 1,
        "prefilled_from": "record",
    }
    for field in ("app_type", "industry_sector", "sensitive_data", "internet_facing",
                  "num_employees", "technical_ability"):
        if profile.get(field):
            draft[field] = profile[field]
    for field in ("compliance_requirements", "authentication", "app_pattern"):
        draft[field] = [str(v) for v in profile.get(field) or []]
    state.replace_wizard_draft(draft)
    if not runs.is_running():
        state.set_threat_model_run(None)
    _forget_widgets()


def _forget_widgets() -> None:
    for field in ("description", "diagram_text", "diagram_use", "app_type", "industry_sector",
                  "sensitive_data", "internet_facing", "num_employees", "technical_ability",
                  "compliance_requirements", "authentication", "tech_pick"):
        state.drop_widget(_W + field)
    for choice in options.technology_choices():
        state.drop_widget(f"{_W}ver_{choice.key}")
    for pattern in options.PATTERN_OPTIONS:
        state.drop_widget(f"{_W}pat_{pattern.value}")


# ------------------------------------------------------------------ steps


def _stepper(draft: dict[str, Any]) -> None:
    saved = bool(_saved_record_id())
    reached = int(draft.get("reached", 0))
    current = int(draft.get("step", 0))
    with st.container(key="tm_stepper"):
        cols = st.columns(len(STEPS))
        for index, (col, name) in enumerate(zip(cols, STEPS, strict=True)):
            # Export opens once a result is saved; the others once reached.
            locked = not saved if index == 3 else index > reached
            col.button(f"{index + 1}  {name}", key=f"tm_step_{index}",
                       type="primary" if index == current else "secondary",
                       disabled=locked and index != current, on_click=_go, args=(index,),
                       help=_HINTS[index], width="stretch")


def _step_description(draft: dict[str, Any]) -> None:
    left, right = st.columns([2, 1], gap="large")
    with left:
        text = _bound("description", "", st.text_area, label="Application description",
                      height=240, max_chars=options.MAX_DESCRIPTION_CHARS,
                      placeholder="Describe what the application does, who uses it, how they "
                                  "sign in, where data is stored, and what it talks to.")
        count = len(text or "")
        short = len((text or "").strip()) < options.MIN_DESCRIPTION_CHARS
        st.html(f'<p class="tm-counter{" tm-short" if short else ""}">Characters: {count}'
                f" (at least {options.MIN_DESCRIPTION_CHARS})</p>")
        st.button("Insert the example description", key="tm_example",
                  on_click=_insert_example, disabled=bool((text or "").strip()),
                  help="Available while the description is empty.")
        _image_block(draft)
    with right:
        with kit.card("why_detail"):
            kit.section("Why detail matters")
            st.markdown(
                "- Defines scope and trust boundaries.\n"
                "- Makes the STRIDE threats more relevant and the mitigations sharper.\n"
                "- Gives the DREAD scores and test cases more to work with.")
            st.caption("AegisShield checks the National Vulnerability Database and AlienVault "
                       "OTX when you add keys, then maps the threats to MITRE ATT&CK techniques.")
        with st.expander("Example description"):
            st.write(options.EXAMPLE_DESCRIPTION)
    _nav(draft, back=None, next_step=1, check=lambda: description_error(draft))


def _insert_example() -> None:
    _draft()["description"] = options.EXAMPLE_DESCRIPTION
    state.set_widget(_W + "description", options.EXAMPLE_DESCRIPTION)


def _image_block(draft: dict[str, Any]) -> None:
    kit.section("Architecture diagram", "Optional. PNG or JPEG, up to 10 MB. The model describes "
                "it and you review the description before it is used.")
    nonce = int(draft.get("image_nonce", 0))
    upload = st.file_uploader("Upload an architecture diagram", type=["png", "jpg", "jpeg"],
                              key=f"tm_image_{nonce}", label_visibility="collapsed",
                              max_upload_size=MAX_IMAGE_MB)
    if upload is not None and tool_parts.upload_too_large(upload, options.MAX_IMAGE_BYTES):
        kit.notice(IMAGE_SIZE, tone=Tone.CRIT)
    elif upload is not None:
        data = upload.getvalue()
        problem = image_error(data)
        if problem:
            kit.notice(problem, tone=Tone.CRIT)
        elif draft.get("image_name") != upload.name or draft.get("image_size") != len(data):
            draft.update(image_b64=base64.b64encode(data).decode("ascii"), image_name=upload.name,
                         image_size=len(data), diagram_text="", diagram_use=True)
            state.drop_widget(_W + "diagram_text")
    if not draft.get("image_b64"):
        return
    cols = st.columns([1, 2], gap="medium")
    with cols[0]:
        try:
            st.image(base64.b64decode(draft["image_b64"]), caption=str(draft.get("image_name") or ""))
        except (binascii.Error, ValueError):
            kit.notice("The image could not be shown.", tone=Tone.WARN)
        st.button("Remove the image", key="tm_image_remove", on_click=_remove_image)
    with cols[1]:
        if not draft.get("diagram_text"):
            disabled = not state.have_llm()
            if st.button("Describe the diagram", key="tm_describe", type="primary",
                         disabled=disabled):
                _describe_image(draft)
            if disabled:
                st.caption(f"{state.llm_blocker() or ''} The diagram is described by the model "
                           "you choose in Settings.".strip())
        if draft.get("diagram_text"):
            _bound("diagram_text", "", st.text_area,
                   label="Diagram description (edit it before it is used)", height=200,
                   max_chars=options.MAX_DIAGRAM_TEXT_CHARS)
            _bound("diagram_use", True, st.checkbox,
                   label="Add this description to the threat model")


def image_error(data: bytes) -> str | None:
    """Why an uploaded diagram cannot be used, or None. The type is read from
    the file's first bytes, not its name."""
    if len(data) > options.MAX_IMAGE_BYTES:
        return IMAGE_SIZE
    if not (data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff")):
        return IMAGE_TYPE
    return None


def _describe_image(draft: dict[str, Any]) -> None:
    settings = state.get_settings()
    if settings.model_vision is False and not settings.mock_llm:
        # The provider's own list says this model takes no images.
        kit.notice(IMAGE_UNSUPPORTED, tone=Tone.WARN)
        return
    try:
        llm = get_llm(settings, state.credential(settings.provider))
        with st.spinner("Reading the diagram"):
            # Not screened here: the run screens the reviewed text that
            # reaches the prompt (as the diagram description) and records it.
            text = analyze_architecture_image(llm, settings.architect_model, draft["image_b64"],
                                              settings=settings, screen=False)
    except (ValidationError, SafeguardsStopped, LLMImageError) as exc:
        kit.notice(str(exc), tone=Tone.CRIT)
        return
    except AegisError:
        kit.notice("The diagram could not be described. Try again.", tone=Tone.CRIT)
        return
    text = clip_words(text, options.MAX_DIAGRAM_TEXT_CHARS)
    draft["diagram_text"] = text
    state.set_widget(_W + "diagram_text", text)
    st.rerun()


def _remove_image() -> None:
    draft = _draft()
    for field in ("image_b64", "image_name", "image_size", "diagram_text"):
        draft.pop(field, None)
    draft["image_nonce"] = int(draft.get("image_nonce", 0)) + 1
    state.drop_widget(_W + "diagram_text")


def _step_technology(draft: dict[str, Any]) -> None:
    with kit.card("context"):
        kit.section("Context", "Required. These six answers are all STRIDE needs.")
        cols = st.columns(3)
        for index, (field, label, choices) in enumerate(_REQUIRED):
            with cols[index % 3]:
                _bound(field, None, st.selectbox, label=label, options=list(choices),
                       index=None, placeholder="Choose one")
    with st.expander("Technology stack (optional): for version-aware CVE lookups",
                     expanded=bool(draft.get("technologies"))):
        _tech_stack(draft)
    with st.expander("Compliance, authentication, and patterns (optional)",
                     expanded=bool(draft.get("compliance_requirements") or draft.get("app_pattern"))):
        cols = st.columns(2)
        with cols[0]:
            _bound("compliance_requirements", [], st.multiselect, label="Compliance requirements",
                   options=list(options.COMPLIANCE_OPTIONS), placeholder="Add a framework")
        with cols[1]:
            _bound("authentication", [], st.multiselect, label="Authentication methods",
                   options=list(options.AUTHENTICATION_OPTIONS), placeholder="Add a method")
        kit.section("Application patterns", "Tick any that apply. Any of them makes this an AI "
                    "system: the threat model then also uses the OWASP reference lists and MITRE "
                    "ATLAS, and each threat gets an ATLAS technique (one more model call) with the "
                    "ATLAS mitigations and case studies for it. Leave them blank to detect them "
                    "from the description.")
        chosen = set(draft.get("app_pattern") or [])
        pcols = st.columns(3)
        picked: list[str] = []
        for index, pattern in enumerate(options.PATTERN_OPTIONS):
            key = f"{_W}pat_{pattern.value}"
            state.seed_widget(key, pattern.value in chosen)
            with pcols[index % 3]:
                if st.checkbox(pattern.label, key=key, help=pattern.description):
                    picked.append(pattern.value)
        draft["app_pattern"] = picked
    _nav(draft, back=0, next_step=2, check=lambda: "\n".join(profile_errors(draft)) or None)


def _tech_label(key: str) -> str:
    choice = _CHOICES[key]
    where = f"{choice.parent} library" if choice.parent else choice.category
    return f"{choice.name} ({where})"


_CHOICES = {choice.key: choice for choice in options.technology_choices()}


def _tech_stack(draft: dict[str, Any]) -> None:
    techs: dict[str, str] = dict(draft.get("technologies") or {})
    key = _W + "tech_pick"
    state.seed_widget(key, list(techs))
    picked = st.multiselect("Technologies", options=list(_CHOICES), format_func=_tech_label,
                            key=key, placeholder="Type to search, for example postgres or react")
    techs = {k: techs.get(k, "") for k in picked}
    if not picked:
        st.caption("No technologies selected yet.")
    cols = st.columns(3)
    for index, tech_key in enumerate(picked):
        with cols[index % 3]:
            widget = f"{_W}ver_{tech_key}"
            state.seed_widget(widget, techs[tech_key])
            version = st.text_input(f"Version for {_CHOICES[tech_key].name}", key=widget,
                                    placeholder="4.0.0 or 4.0.*")
            techs[tech_key] = version
            message = options.validate_version(version)
            if message:
                st.html(f'<p class="tm-counter tm-short">{_esc(message)}</p>')
    draft["technologies"] = techs


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def _nav(draft: dict[str, Any], *, back: int | None, next_step: int | None,
         check: Callable[[], str | None] | None = None) -> None:
    with st.container(horizontal=True, key=f"tm_nav_{back}_{next_step}"):
        if back is not None:
            st.button("Back", key=f"tm_back_{back}", on_click=_go, args=(back,),
                      icon=":material/arrow_back:")
        clicked = next_step is not None and st.button(
            "Next", key=f"tm_next_{next_step}", type="primary", icon=":material/arrow_forward:")
    if clicked:
        message = check() if check else None
        if message:
            draft["error"] = message
        else:
            draft.pop("error", None)
            _go(next_step)
        st.rerun()
    if next_step is not None and draft.get("error") and int(draft.get("step", 0)) == next_step - 1:
        for line in str(draft["error"]).splitlines():
            kit.notice(line, tone=Tone.CRIT)


AGENTIC_SUMMARY = (
    "The agent team always writes the STRIDE threats, the MITRE ATT&CK mapping, and the "
    "attack tree. The lead decides which of DREAD scoring, mitigations, test cases, a "
    "teammate review for false positives, and a rebuttal of the highest risks this "
    "application needs, so the add-on switches do not apply. Turn the agentic path off in "
    "Settings to choose the add-ons yourself."
)


def _step_threat_model(draft: dict[str, Any]) -> None:
    body, running, agentic = _run_bar(draft)
    _live_panel(body, running=running, agentic=agentic)
    _results(draft)


def _addon_toggles(draft: dict[str, Any], *, disabled: bool) -> None:
    addons = dict(draft.get("addons") or {})
    cols = st.columns(len(_ADDONS))
    for col, (name, label, hint) in zip(cols, _ADDONS, strict=True):
        key = f"{_W}addon_{name}"
        state.seed_widget(key, addons.get(name, True))
        with col:
            addons[name] = st.toggle(label, key=key, help=hint, disabled=disabled)
    draft["addons"] = addons


def _addon_words(draft: dict[str, Any]) -> str:
    addons = draft.get("addons") or {}
    chosen = [label for name, label, _hint in _ADDONS if addons.get(name, True)]
    return ", ".join(chosen) if chosen else "none"


def _run_bar(draft: dict[str, Any]) -> tuple[dict[str, Any] | None, bool, bool]:
    """The add-ons, Generate and Cancel, and the run's message.

    Before the first run this is the add-on card with the buttons below it.
    Once a run starts it is one compact line, so the live view sits near the
    top of the page. Everything is inside one keyed container, so the live
    view below keeps its place in the page whatever this shows (a moved
    element would remount it).
    """
    body = runs.poll()
    running = runs.is_running()
    status = (body or {}).get("status")
    run = state.threat_model_run()
    # The live view keeps the run's own mode (a finished run stays in the view
    # it ran in); the bar describes what Generate starts next, which follows
    # the setting unless a run is going.
    agentic = bool(run["agentic"]) if run else state.agentic_enabled()
    bar_agentic = agentic if running else state.agentic_enabled()
    label = "Run it again" if status in ("failed", "cancelled") else "Generate"
    with st.container(key="tm_runbar"):
        if run is None:
            with kit.card("addons"):
                if bar_agentic:
                    kit.section("Agent team", AGENTIC_SUMMARY)
                else:
                    kit.section("Additional analyses", "On by default. Each adds a stage to the run.")
                    _addon_toggles(draft, disabled=False)
            with st.container(horizontal=True, key="tm_controls"):
                _run_buttons(draft, label, running)
        else:
            with st.container(horizontal=True, key="tm_runline", vertical_alignment="center"):
                if bar_agentic:
                    st.html('<p class="tm-runline"><strong>Agent team.</strong> STRIDE, MITRE '
                            "ATT&amp;CK, and the attack tree; the lead picks the rest.</p>")
                else:
                    st.html(f'<p class="tm-runline"><strong>Additional analyses:</strong> '
                            f"{_esc(_addon_words(draft))}</p>")
                    with st.popover("Analyses", icon=":material/tune:", disabled=running):
                        _addon_toggles(draft, disabled=running)
                _run_buttons(draft, label, running)
        message = draft.get("run_error")
        if message:
            kit.notice(str(message), tone=Tone.CRIT)
        elif status == "failed" and body and body.get("error"):
            kit.notice(str(body["error"]), tone=Tone.CRIT)
        elif status == "cancelled":
            kit.notice("The run was cancelled.", tone=Tone.WARN)
    return body, running, agentic


def _run_buttons(draft: dict[str, Any], label: str, running: bool) -> None:
    st.button(label, key="tm_generate", type="primary", disabled=running,
              icon=":material/play_arrow:", on_click=_generate, args=(draft,))
    st.button("Cancel", key="tm_cancel", disabled=not running, on_click=runs.cancel_run,
              icon=":material/stop:")


def _live_panel(body: dict[str, Any] | None, *, running: bool, agentic: bool) -> None:
    """The live view: the only part of the page that polls.

    Generate and Cancel sit outside the fragment (in the run bar), so a
    click is an ordinary app rerun. The fragment asks for one app rerun when
    the run settles, so the results appear below it.
    """

    @st.fragment(run_every=1 if running else None)
    def panel() -> None:
        latest = runs.poll() if running else body
        runs.render_live(latest, agentic=agentic)
        if running and not runs.is_running():
            st.rerun(scope="app")

    panel()


def _generate(draft: dict[str, Any]) -> None:
    """``on_click`` for Generate: check the inputs, then start the run."""
    errors = [m for m in (description_error(draft), *profile_errors(draft)) if m]
    if errors:
        draft["run_error"] = "Complete steps 1 and 2 first. " + errors[0]
        return
    try:
        runs.start_run(draft)
    except AegisError as exc:
        draft["run_error"] = runs.describe_error(exc)
    else:
        draft.pop("run_error", None)


def _saved_record_id() -> str | None:
    run = state.threat_model_run()
    return run.get("record_id") if run else None


def _results(draft: dict[str, Any]) -> None:
    record_id = _saved_record_id()
    if not record_id or runs.is_running():
        return
    record = state.get_workspace().get(RecordKind.THREAT_MODELS, record_id)
    if record is None:
        return
    draft["reached"] = max(int(draft.get("reached", 0)), 3)
    run = state.threat_model_run() or {}
    kit.notice(f"Saved to your workspace as: {record.title}", tone=Tone.OK)
    kit.record_link("threat_model_detail", record.id, "Open the saved threat model")
    render_results(record, duration=run.get("duration"), key_prefix="tmw")


def _step_export(draft: dict[str, Any]) -> None:
    record_id = _saved_record_id()
    record = state.get_workspace().get(RecordKind.THREAT_MODELS, record_id) if record_id else None
    if record is None:
        kit.empty_state("Nothing to export yet", "Generate a threat model first. Its report and "
                        "files appear here.")
    else:
        render_exports(record, key_prefix="tmw")
    _nav(draft, back=2, next_step=None)


# ------------------------------------------------------------------- page


def render() -> None:
    """The wizard."""
    kit.wide_canvas()
    tm_style.apply()
    kit.page_header("New threat model", "Describe the application, add context, then watch the "
                    "agents build the threat model.", area=Area.DEFENSE)
    if runs.reattach_from_url():
        _go(2)
    _apply_handoffs()
    # Settle a finished run before anything is drawn, so the stepper and
    # the results agree on this run.
    runs.poll()
    draft = _draft()
    notice = draft.get("notice")
    if isinstance(notice, (tuple, list)) and len(notice) == 2 and notice[0]:
        kit.notice(str(notice[0]), tone=Tone(notice[1]))
    _stepper(draft)
    step = int(draft.get("step", 0))
    if step == 0:
        _step_description(draft)
    elif step == 1:
        _step_technology(draft)
    elif step == 2:
        _step_threat_model(draft)
        _nav(draft, back=1, next_step=None)
    else:
        _step_export(draft)
