// Instrumentation for the office component, read by tests and the demo.
//
// The bundle (see __init__.py) puts this first and hands office_vector.js
// the two animation-frame functions below in place of the window ones, so
// the view's own code stays as written while every frame it draws is counted.
//
// window.__aegisOffice:
//   calls           times Streamlit called the default export
//   mounts          times the shim built an office host (one per mount)
//   inits           officeRenderInit calls that built a shell
//   updates         data updates the shim applied
//   chainStarts     animation loops started from outside a frame
//   cancels         loops cancelled while a frame was pending
//   ends            loops that ended by not asking for another frame,
//                   including office_vector.js's stop from inside step()
//   frames          frames drawn by the office
//   maxGapMs        longest gap between two frames of one loop
//   updatesInLoop   updates that arrived while a loop was already running
//   log             the last 400 events, for a test to read

const __aegisProbe = (() => {
  const probe = window.__aegisOffice || {
    calls: 0,
    mounts: 0,
    inits: 0,
    updates: 0,
    chainStarts: 0,
    cancels: 0,
    ends: 0,
    frames: 0,
    maxGapMs: 0,
    updatesInLoop: 0,
    log: [],
  };
  window.__aegisOffice = probe;
  let inFrame = false;
  let requested = false;
  let looping = false;
  let lastAt = 0;

  function note(kind, extra) {
    probe.log.push({ kind, at: Math.round(performance.now()), ...extra });
    if (probe.log.length > 400) probe.log.shift();
  }

  function end() {
    looping = false;
    lastAt = 0;
    probe.ends += 1;
    note("loop-end", { frames: probe.frames });
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
        if (!requested && looping) end();
      }
    });
  }

  // office_vector.js stopLoop() cancels its last frame id even from inside
  // that frame, where nothing is pending. Only a cancel with a frame still
  // pending stops a running loop; the other kind is the loop ending.
  function cancelFrame(id) {
    if (requested) {
      probe.cancels += 1;
      looping = false;
      requested = false;
      lastAt = 0;
      note("loop-cancel");
    }
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
