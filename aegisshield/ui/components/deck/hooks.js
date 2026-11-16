// What deck_view.js registers outside its own host, so the shim can release
// it when a mount leaves the page.
//
// deck_view.js adds three document listeners and one
// ResizeObserver in each deckInit for a new host and never removes them, so
// every remount would stack another set. The bundle (see __init__.py) hands
// deck_view.js the two names below in its own scope, in place of the
// globals: a document whose addEventListener also records the listener, and
// a ResizeObserver that records itself. Every other document member is the
// real one. deck_view.js only reads members of document (it never passes
// document itself to another API), so the stand-in is safe; a test pins that.
//
// The shim calls collect(list, fn) around deckInit, then release(list) when
// the mount's host has left the page.

const __aegisHooks = (() => {
  let sink = null;
  const realDocument = globalThis.document;
  const bound = new Map(); // document methods, bound once
  const document = new Proxy(realDocument, {
    get(target, prop) {
      if (prop === "addEventListener") {
        return (type, fn, options) => {
          if (sink) sink.push({ type, fn, options });
          target.addEventListener(type, fn, options);
        };
      }
      const value = Reflect.get(target, prop);
      if (typeof value !== "function") return value;
      if (!bound.has(prop)) bound.set(prop, value.bind(target));
      return bound.get(prop);
    },
  });
  const Real = globalThis.ResizeObserver;
  const ResizeObserver = Real
    ? class extends Real {
        constructor(callback) {
          super(callback);
          if (sink) sink.push({ observer: this });
        }
      }
    : undefined;

  function collect(list, fn) {
    const previous = sink;
    sink = list;
    try {
      return fn();
    } finally {
      sink = previous;
    }
  }

  function release(list) {
    for (const item of list.splice(0)) {
      if (item.observer) item.observer.disconnect();
      else realDocument.removeEventListener(item.type, item.fn, item.options);
    }
  }

  return { document, ResizeObserver, collect, release };
})();
