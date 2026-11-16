# The office component

The office is the live view of an agentic threat-model run: the Threat Model Lead sits at the center of a top-down room, and each specialist from `AGENT_ROLES` in `aegisshield/pipeline/agentic_threat_model.py` has a desk on a ring around it. Each desk shows its agent's status, current activity, and finding count, and the links between desks light up while work passes between them.

It is part of AegisShield and is covered by the repository's license (GNU AGPL v3, see `LICENSE`).

## Files

| File | What it does |
|---|---|
| `roster.js` | The model. Pure functions, no DOM: desk layout, status and finding counts per desk, the mesh of links, and the tween that makes every desk show "working" for a moment before it lands on "done". `tests/aegisshield/ui/office_roster.test.mjs` tests it under `node --test`. |
| `office_vector.js` | The view. Draws the room, desks, links, and moving packets with `createElement`, `createElementNS`, and `textContent` only, and runs its own animation-frame loop. |
| `office.css` | The room's styles. Every selector starts with `.aegis-office-root` and every keyframes name with `aegis-office-`, so no rule reaches outside the component; a test checks both. |
| `host.css` | The design tokens `office.css` reads, set on the wrapper; the panel header; the room's height; two-line activity bubbles; a text cue after each label so status is not told by color alone; and `prefers-reduced-motion` handling. |
| `shim.js` | The Streamlit side. Builds the panel once per mount, starts the renderer, and turns each progress record into a desk model. |
| `probe.js` | Mount, update, and frame counters on `window.__aegisOffice`, read by the tests and the browser check. |
| `__init__.py` | The bundler and `render_office`. |

## How it is loaded

`st.components.v2.component(js=...)` takes one inline ES module, so `__init__.py` builds one when it is imported, with no Node build step:

1. `probe.js` first.
2. `roster.js` inside its own function scope, with the column-0 `export` keywords removed; the scope returns the exported names.
3. `office_vector.js` the same way, with its one import from `./roster.js` removed and those names bound from step 2. Its `requestAnimationFrame` and `cancelAnimationFrame` are bound to the probe's counting versions.
4. `shim.js`, with its two import lines replaced by the names from steps 2 and 3. Its `export default function` is the component entry point.

The bundler raises `RuntimeError` if an import line or an export form is not exactly what it expects, so a change that would load a broken module fails at import instead.

The component uses `isolate_styles=False` because `office_vector.js` finds its mount and its panel with `document.getElementById`, which cannot see into a shadow root. The `.aegis-office-root` prefix keeps every rule inside the office's wrapper.

## Seven specialists on one ring

`RING_IDS` in `roster.js` lists the seven specialists in the pipeline's order, and a test checks it against `AGENT_ROLES`. `ringPos(index, count)` spaces any number of seats evenly, starting at the top, and `officeFracPos` normalizes positions against the desks' bounding box, so adding a specialist needs only its entry in `RING_IDS`, `RING_META`, and `QUEUED_ACTIVITY`.

## How the room settles

- A specialist the Lead left out of its plan is missing from the progress record. The shim shows it as skipped, so the run still resolves and the animation loop stops.
- A failed or cancelled job can leave agents queued or working. The shim shows them as error or skipped.
- The idle and queued previews are a still frame: the desks are built, then the loop the sync asked for is cancelled.
