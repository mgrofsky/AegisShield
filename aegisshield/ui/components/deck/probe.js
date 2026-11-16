// Instrumentation for the deck component, read by tests and the demo.
//
// The bundle (see __init__.py) puts this first and hands deck_view.js the
// two animation-frame functions below in place of the window ones, so the
// view's own code stays as written while every frame it draws is counted.
//
// window.__aegisDeck:
//   calls           times Streamlit called the default export
//   mounts          times the shim built a deck host (one per mount)
//   inits           deckInit calls (one per run, plus the idle preview)
//   updates         data updates the shim applied
//   chainStarts     animation loops started from outside a frame
//   cancels         loops cancelled (stop() in deck_view.js)
//   frames          frames drawn by the deck
//   maxGapMs        longest gap between two frames of one loop
//   updatesInLoop   updates that arrived while a loop was already running
//   log             the last 400 events, for a test to read

const __aegisProbe = (() => {
  const probe = window.__aegisDeck || {
    calls: 0,
    mounts: 0,
    inits: 0,
    updates: 0,
    chainStarts: 0,
    cancels: 0,
    frames: 0,
    maxGapMs: 0,
    updatesInLoop: 0,
    log: [],
  };
  window.__aegisDeck = probe;
  let inFrame = false;
  let requested = false;
  let looping = false;
  let lastAt = 0;

  function note(kind, extra) {
    probe.log.push({ kind, at: Math.round(performance.now()), ...extra });
    if (probe.log.length > 400) probe.log.shift();
  }

  function requestFrame(cb) {
    if (!inFrame && !looping) {
      probe.chainStarts += 1;
      note("loop-start");
    }
    looping = true;
    requested = true;
    return window.requestAnimationFrame((ts) => {
      const now = performance.now();
      if (lastAt) {
        const gap = Math.round(now - lastAt);
        probe.maxGapMs = Math.max(probe.maxGapMs, gap);
        if (gap > 40) note("long-gap", { gap });
      }
      lastAt = now;
      probe.frames += 1;
      inFrame = true;
      requested = false;
      try {
        cb(ts);
      } finally {
        inFrame = false;
        if (!requested) {
          looping = false;
          lastAt = 0;
          note("loop-end", { frames: probe.frames });
        }
      }
    });
  }

  function cancelFrame(id) {
    probe.cancels += 1;
    looping = false;
    requested = false;
    lastAt = 0;
    note("loop-cancel");
    window.cancelAnimationFrame(id);
  }

  return {
    probe,
    note,
    requestFrame,
    cancelFrame,
    looping: () => looping,
  };
})();
