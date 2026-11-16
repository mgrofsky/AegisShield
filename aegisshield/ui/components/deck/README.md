# The deck component

The deck is the live "agents at work" view of a linear threat-model run. Each pipeline stage is an agent in a list on the left; threats, mitigations, and attack-tree links fly from the working agent to cards on a board as the model writes them, and a log, tally, and legend run along the bottom. A visitor can open any card or lookup agent to read what it holds.

It is part of AegisShield and is covered by the repository's license (GNU AGPL v3, see `LICENSE`).

## Files

| File | What it does |
|---|---|
| `deck.js` | The model. Pure: no page globals, timers, or clock of its own. It takes each progress record with the time it arrived, paces what the record delivers, and returns a view model on each animation tick. |
| `deck_view.js` | The view. Draws the view model with `createElement`, `createElementNS`, `textContent`, and one canvas, and runs its own animation-frame loop. |
| `deck.css` | The deck's styles. Every class starts with `dk-`. Sizes follow the deck's own box (container units), not the viewport. |
| `host.css` | The design tokens `deck.css` reads (`--mono`, `--bg-base`, `--topbar-height`, and the rest), set on the deck's wrapper instead of `:root`. |
| `hooks.js` | Records the `document` listeners and `ResizeObserver` that `deckInit` adds outside its host, so the shim can release them when a mount leaves the page. |
| `shim.js` | The Streamlit side. Mounts the view, seeds it before a run starts, and feeds it each progress record. |
| `probe.js` | Mount, update, and frame counters on `window.__aegisDeck`, read by the tests and the browser check. |
| `__init__.py` | The bundler and `render_deck`. |

Every string in a progress record is untrusted (model output or visitor text). It reaches the page only through `textContent` or a text node.

## How it is loaded

`st.components.v2.component(js=...)` takes one inline ES module, so `__init__.py` builds one when it is imported, with no Node build step:

1. `probe.js` first.
2. `deck.js` inside its own function scope, with the column-0 `export` keywords removed; the scope returns the exported names.
3. `deck_view.js` inside its own function scope, with its one import line (`import { createDeckFeed, fmtClock, MAX_PIPS, nvdLink } from "./deck.js";`) removed and the same names taken from step 2. `requestAnimationFrame` and `cancelAnimationFrame` are bound in that scope to the probe's counting versions, and `document` and `ResizeObserver` to the recording versions from `hooks.js`.
4. `shim.js`, with its two import lines replaced by the names from steps 2 and 3. Its `export default function` is the component entry point.

The bundler raises `RuntimeError` if an import line or an export form is not exactly what it expects, so a change that would load a broken module fails at import instead.

## Listeners released at unmount

`deckInit` adds three `document` listeners and one `ResizeObserver` for each new host and does not remove them itself. The shim wraps `deckInit` in `hooks.js`'s `collect` and calls `release` when the mount's host has left the page, so remounting the deck does not stack listeners. `deck_view.js` only reads members of `document` and never passes `document` itself to another API, which is what makes the recording stand-in safe; `tests/aegisshield/ui/test_deck_component.py` checks that.
