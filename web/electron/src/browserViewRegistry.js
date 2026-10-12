/**
 * Per-conversation WebContentsView registry.
 *
 * Keyed by `conversationId` for Omnigent's session model. Each entry owns its
 * own bounds controller so per-conversation state never cross-contaminates.
 *
 * Pure factory — no Electron imports at module scope. All deps are injected
 * so a unit test can drive create/swap/close/closeAll/cap behavior with a
 * stub `WebContentsViewCtor` without booting Electron.
 *
 * Lifecycle invariants:
 *  - `setActive` NEVER lazy-creates — it only attaches an existing entry (so a
 *    background agent's view isn't blanked by panel mounts). Creation goes only
 *    through `getOrCreate` / `openOrNavigate`, both cap-enforcing and non-throwing.
 *  - The old active entry is detached before the new one attaches. Inactive
 *    entries stay alive (JS + agent IPCs still run), just not painting; they're
 *    detached on hide and destroyed only on explicit close.
 */

const dns = require("node:dns");

const { isAgentNavigationAllowed, resolveAgentNavigation } = require("./browserUrlPolicy");
const { createAgentConnectProxy } = require("./browserConnectProxy");

const DEFAULT_CAP = 10;

function defaultLookup(hostname) {
  return dns.promises.lookup(hostname, { all: true, verbatim: true });
}

// Electron partition strings are path-like. Keep the conversation id readable
// but drop anything that isn't a token character.
function browserPartition(conversationId) {
  const safe = String(conversationId).replace(/[^A-Za-z0-9_-]/g, "_");
  return `persist:omnigent-browser-${safe}`;
}

function createBrowserViewRegistry({
  WebContentsViewCtor, // (opts) => new WebContentsView(opts) — injectable for tests
  createBoundsController, // bounds-controller factory (createBrowserViewBoundsController)
  attachToHost, // (view) => mainWindow.contentView.addChildView(view)
  detachFromHost, // (view) => mainWindow.contentView.removeChildView(view)
  sendToRenderer, // (channel, payload) => mainWindow.webContents.send(...)
  getHostZoomFactor = () => 1,
  getHostDisplayScaleFactor = () => null,
  cap = DEFAULT_CAP,
  // Hostname → addresses. Tests inject this; production uses the OS resolver.
  lookup = defaultLookup,
  // Builds the local pinning proxy. Tests inject a fake connect path.
  createConnectProxy = createAgentConnectProxy,
  // When set, skips the real session proxy (unit tests have no Electron session).
  pinAgentConnection = null,
  clearAgentConnection = null,
} = {}) {
  const entries = new Map(); // conversationId -> BrowserViewEntry
  let activeConversationId = null;
  // One pinning proxy per registry (per window). Started on the first agent
  // navigation and stopped when the last view closes. `unref`'d so a forgotten
  // close does not keep the process alive.
  let connectProxy = null;
  let connectProxyStart = null;
  // When true, the active view is hidden in place (setVisible(false)) so DOM
  // overlays (dialogs, menus, tooltips, toasts) aren't covered by the native
  // layer, which always paints above the renderer regardless of z-index. Sticky
  // across attaches: a view that becomes active while suppressed stays hidden.
  let overlaySuppressed = false;

  // Apply the current suppress flag to the active view (no-op with none active).
  function applyActiveVisibility() {
    if (activeConversationId === null) return;
    const entry = entries.get(activeConversationId);
    if (!entry) return;
    try {
      entry.view.setVisible(!overlaySuppressed);
    } catch {
      /* view destroyed */
    }
  }

  function setSuppressed(suppressed) {
    overlaySuppressed = !!suppressed;
    applyActiveVisibility();
    return { ok: true };
  }

  function makeEntry(conversationId, view) {
    const entry = {
      conversationId,
      view,
      boundsController: createBoundsController({
        getZoomFactor: getHostZoomFactor,
        getDisplayScaleFactor: getHostDisplayScaleFactor,
        setBounds: (bounds) => {
          // Only paint the active entry; inactive views are detached (no-op).
          if (activeConversationId === conversationId) {
            try {
              view.setBounds(bounds);
            } catch {
              /* destroyed */
            }
          }
        },
      }),
      // Last URL we EXPLICITLY requested (not getURL(), which drifts as the page
      // navigates) — lets openOrNavigate skip reissuing loadURL on a re-mount.
      lastRequestedUrl: "",
      // Whether the CURRENT navigation was agent-initiated. Set on every
      // openOrNavigate from opts.agent; read by the will-navigate/will-redirect
      // guard so the allowlist is enforced on the agent's whole nav chain
      // (initial load + every redirect / meta-refresh / location.href) but NOT
      // on user-typed URL-bar browsing, which stays permissive. SECURITY: without
      // this, the allowlist only guards the first hop and a redirect to an
      // internal host slips through (SSRF via screenshot).
      agentNavLocked: false,
      // True only after the view's session is pointed at the pinning proxy.
      // The nav guard treats a locked-but-unpinned view as deny-all.
      agentProxyEngaged: false,
      proxyLoginListener: null,
      // Design-mode listeners + webContents, set by browserIpc's enable handler
      // and cleared on disable/close (console-message forwarder + native-gesture
      // tracker). Null until design mode is enabled for this entry.
      designModeListener: null,
      designModeInputListener: null,
      designModeWebContents: null,
    };
    return entry;
  }

  function get(conversationId) {
    return entries.get(conversationId) || null;
  }

  function getOrCreate(conversationId) {
    const existing = entries.get(conversationId);
    if (existing) return { ok: true, entry: existing, created: false };
    if (entries.size >= cap) {
      return { ok: false, error: "browser view cap reached — close one", cap };
    }
    const view = WebContentsViewCtor({
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        // Own session so the pinning proxy never becomes the shell window's proxy.
        partition: browserPartition(conversationId),
      },
    });
    const entry = makeEntry(conversationId, view);
    entries.set(conversationId, entry);
    denyChildWindowOpen(entry);
    attachAgentNavGuard(conversationId, entry);
    return { ok: true, entry, created: true };
  }

  // SECURITY: a visited page must not spawn windows from the desktop shell.
  // Deny every window.open / target=_blank on the child view (the safe default;
  // unlike the main shell window we do NOT route to shell.openExternal, since an
  // agent-visited page popping the user's real browser to an arbitrary URL is
  // itself an abuse vector).
  function denyChildWindowOpen(entry) {
    const wc = entry.view && entry.view.webContents;
    if (!wc || typeof wc.setWindowOpenHandler !== "function") return;
    wc.setWindowOpenHandler(() => ({ action: "deny" }));
  }

  // SECURITY (SSRF): enforce the agent-navigation allowlist on the child view's
  // OWN navigation events, not just the first loadURL. A server 302 / meta-
  // refresh / location.href during an agent-initiated navigation would otherwise
  // redirect the view to an internal host (metadata / loopback / RFC-1918) with
  // no re-check, and browser_screenshot could read it back. `will-navigate` and
  // `will-redirect` (plus subframes via `will-frame-navigate`) are the blocking
  // hooks — did-navigate is report-only and fires too late. Enforced ONLY while
  // `entry.agentNavLocked` (set per-navigation from opts.agent), so user-typed
  // URL-bar browsing — including legitimate auth-redirect chains to internal
  // hosts — stays permissive.
  function blockAgentNav(event, conversationId, targetUrl, error) {
    try {
      event.preventDefault();
    } catch {
      /* event shape without preventDefault — nothing to cancel */
    }
    sendToRenderer("browser-nav-blocked", { conversationId, url: targetUrl, error });
  }

  function attachAgentNavGuard(conversationId, entry) {
    const wc = entry.view && entry.view.webContents;
    if (!wc || typeof wc.on !== "function") return;
    const guard = (event, targetUrl) => {
      if (!entry.agentNavLocked) return; // user-driven nav: permissive
      // Fail closed until the pinning proxy is installed. A redirect that
      // lands in that window must not dial with Chromium's own resolver.
      if (!entry.agentProxyEngaged) {
        blockAgentNav(
          event,
          conversationId,
          targetUrl,
          "navigation blocked: agent browser connection is not pinned",
        );
        return;
      }
      // Literals and schemes are rejected here. Hostnames pass the string
      // check and are resolved once by the pinning proxy on the way out.
      const verdict = isAgentNavigationAllowed(targetUrl);
      if (!verdict.ok) {
        blockAgentNav(event, conversationId, targetUrl, verdict.error);
      }
    };
    wc.on("will-navigate", guard);
    wc.on("will-redirect", guard);
    // Subframe navigations (iframes) can also reach an internal host; guard them
    // too. Older Electron may not emit this event — harmless if it never fires.
    wc.on("will-frame-navigate", (event) => {
      // will-frame-navigate passes a single event whose `.url` is the target.
      guard(event, event && event.url);
    });
  }

  function restoreAgentLock(entry, prevLocked, prevEngaged) {
    if (!entry) return;
    entry.agentNavLocked = prevLocked;
    entry.agentProxyEngaged = prevEngaged;
  }

  async function sharedProxy() {
    if (connectProxy) return connectProxy;
    if (!connectProxyStart) {
      connectProxyStart = (async () => {
        const proxy = createConnectProxy({ lookup });
        await proxy.listen();
        connectProxy = proxy;
        return proxy;
      })().catch((err) => {
        connectProxyStart = null;
        throw err;
      });
    }
    return connectProxyStart;
  }

  function stopSharedProxy() {
    if (entries.size !== 0) return;
    const proxy = connectProxy;
    connectProxy = null;
    connectProxyStart = null;
    if (proxy) proxy.close();
  }

  function attachProxyLogin(entry, proxy) {
    if (entry.proxyLoginListener) return;
    const wc = entry.view && entry.view.webContents;
    if (!wc || typeof wc.on !== "function") return;
    const onLogin = (event, _details, authInfo, callback) => {
      if (!authInfo || !authInfo.isProxy || typeof callback !== "function") return;
      try {
        event.preventDefault();
      } catch {
        /* no preventDefault */
      }
      callback(proxy.username, proxy.password);
    };
    wc.on("login", onLogin);
    entry.proxyLoginListener = onLogin;
  }

  function detachProxyLogin(entry) {
    const wc = entry && entry.view && entry.view.webContents;
    if (!entry || !entry.proxyLoginListener || !wc || typeof wc.removeListener !== "function") {
      if (entry) entry.proxyLoginListener = null;
      return;
    }
    try {
      wc.removeListener("login", entry.proxyLoginListener);
    } catch {
      /* destroyed */
    }
    entry.proxyLoginListener = null;
  }

  // Point the view's own session at the pinning proxy. Chromium then sends
  // every request (navigation, redirect, subframe) here, and the proxy dials
  // only the address it just resolved. Missing session fails closed.
  async function defaultPinAgentConnection(entry) {
    const wc = entry.view && entry.view.webContents;
    const session = wc && wc.session;
    if (!wc || !session || typeof session.setProxy !== "function" || typeof wc.on !== "function") {
      return {
        ok: false,
        error: "navigation blocked: agent browser cannot pin the resolved address",
      };
    }
    let proxy;
    try {
      proxy = await sharedProxy();
    } catch {
      return {
        ok: false,
        error: "navigation blocked: agent browser connect proxy failed to start",
      };
    }
    attachProxyLogin(entry, proxy);
    try {
      await session.setProxy({
        mode: "fixed_servers",
        proxyRules: `http://127.0.0.1:${proxy.port()}`,
        proxyBypassRules: "",
      });
    } catch {
      return { ok: false, error: "navigation blocked: failed to pin agent browser connections" };
    }
    return { ok: true };
  }

  async function defaultClearAgentConnection(entry) {
    const session = entry.view && entry.view.webContents && entry.view.webContents.session;
    if (!session || typeof session.setProxy !== "function") return;
    await session.setProxy({ mode: "direct" });
  }

  async function openOrNavigate(conversationId, url, bounds, opts) {
    const force = !!(opts && opts.force);
    const agent = !!(opts && opts.agent);
    // Agent-driven nav is gated by the literal allowlist AND a DNS pin, so the
    // model can't point the view at file:// / metadata / private / rebinding
    // hosts and exfiltrate via screenshot. URL-bar nav stays permissive.
    // Checked before getOrCreate so a rejected nav creates no blank view.
    // An existing view is fail-closed for the duration of the lookup so a
    // redirect cannot race the check.
    const existing = agent && url ? entries.get(conversationId) : null;
    const prevLocked = existing ? existing.agentNavLocked : false;
    const prevEngaged = existing ? existing.agentProxyEngaged : false;
    if (existing) {
      existing.agentNavLocked = true;
      existing.agentProxyEngaged = false;
    }
    if (agent && url) {
      let verdict;
      try {
        verdict = await resolveAgentNavigation(url, lookup);
      } catch {
        restoreAgentLock(existing, prevLocked, prevEngaged);
        return { ok: false, error: "navigation blocked: destination check failed" };
      }
      if (!verdict.ok) {
        restoreAgentLock(existing, prevLocked, prevEngaged);
        return { ok: false, error: verdict.error };
      }
    }
    const result = getOrCreate(conversationId);
    if (!result.ok) {
      restoreAgentLock(existing, prevLocked, prevEngaged);
      return result;
    }
    const { entry, created } = result;
    // Latch who drives THIS navigation so the will-navigate/will-redirect guard
    // enforces the allowlist on an agent nav's whole redirect chain, and leaves
    // user-typed URL-bar nav permissive. The proxy must be engaged before
    // loadURL; until then the guard rejects every hop.
    if (url && agent) {
      entry.agentNavLocked = true;
      entry.agentProxyEngaged = false;
      const pin = await (pinAgentConnection || defaultPinAgentConnection)(entry);
      if (!pin.ok) {
        detachProxyLogin(entry);
        if (created) close(conversationId, "agent-pin-failed");
        else restoreAgentLock(entry, prevLocked, prevEngaged);
        return {
          ok: false,
          error: pin.error || "navigation blocked: failed to pin agent browser connections",
        };
      }
      entry.agentProxyEngaged = true;
    } else if (url) {
      try {
        await (clearAgentConnection || defaultClearAgentConnection)(entry);
      } catch {
        // Stay agent-locked if the session is still pointed at the pinning proxy.
        return {
          ok: false,
          error: "navigation failed: could not disable the agent connection pin",
        };
      }
      detachProxyLogin(entry);
      entry.agentNavLocked = false;
      entry.agentProxyEngaged = false;
    }
    if (bounds) entry.boundsController.setRendererBounds(bounds);
    // Only attach immediately when this is the active conversation; otherwise
    // create-detached and let `setActive(conversationId)` attach on user switch.
    if (created && activeConversationId === conversationId) {
      try {
        attachToHost(entry.view);
      } catch {
        /* host gone */
      }
      // Honor a live overlay suppression on a just-created active view.
      applyActiveVisibility();
    }
    // Signal the renderer a view now exists. On a fresh conversation the view is
    // created detached (no host-active-changed fires), so without this the pane
    // never mounts its placeholder or calls setActive to attach it.
    if (created) {
      sendToRenderer("browser-view-created", { conversationId });
    }
    if (url) {
      // Reissue loadURL on a fresh entry, a different requested URL, or `force`
      // (agent "bring me back"). Comparing lastRequestedUrl — not getURL(), which
      // drifts with in-page nav — stops a re-mount from refreshing to the initial URL.
      if (created || force || entry.lastRequestedUrl !== url) {
        entry.lastRequestedUrl = url;
        try {
          entry.view.webContents.loadURL(url);
        } catch (e) {
          return { ok: false, error: `loadURL failed: ${e && e.message ? e.message : e}` };
        }
      }
    }
    return { ok: true, entry, created };
  }

  function setActive(conversationId) {
    // null = "detach everything" sentinel (no pane mounted): stop painting over
    // the React layout, but keep the view so its agent can still drive it.
    if (conversationId === null || conversationId === undefined) {
      if (activeConversationId !== null) {
        const prev = entries.get(activeConversationId);
        if (prev) {
          try {
            detachFromHost(prev.view);
          } catch {
            /* view already detached */
          }
        }
        activeConversationId = null;
        sendToRenderer("browser-host-active-changed", { conversationId: null });
      }
      return { ok: true };
    }
    const next = entries.get(conversationId);
    if (!next) {
      // No view for this conversation: still detach whatever was visible, else
      // switching A (has browser) → B (none) leaves A painted over B's page.
      if (activeConversationId !== null) {
        const prev = entries.get(activeConversationId);
        if (prev) {
          try {
            detachFromHost(prev.view);
          } catch {
            /* view already detached */
          }
        }
        activeConversationId = null;
        sendToRenderer("browser-host-active-changed", { conversationId: null });
      }
      return { ok: false, error: "No browser view" };
    }
    if (activeConversationId === conversationId) {
      // Already active — repositioning bounds is a re-apply, not a swap.
      next.boundsController.resync();
      return { ok: true };
    }
    if (activeConversationId !== null) {
      const prev = entries.get(activeConversationId);
      if (prev) {
        try {
          detachFromHost(prev.view);
        } catch {
          /* detached / destroyed */
        }
      }
    }
    activeConversationId = conversationId;
    try {
      attachToHost(next.view);
    } catch {
      /* host gone */
    }
    // A view attaching while an overlay is open must stay hidden (sticky flag).
    applyActiveVisibility();
    next.boundsController.resync();
    sendToRenderer("browser-host-active-changed", { conversationId });
    return { ok: true };
  }

  function close(conversationId, reason) {
    const entry = entries.get(conversationId);
    if (!entry) return { ok: true, removed: false };
    if (activeConversationId === conversationId) {
      try {
        detachFromHost(entry.view);
      } catch {
        /* view already detached */
      }
      activeConversationId = null;
    }
    // Detach any design-mode listeners before closing the webContents, so a
    // closed view leaves nothing dangling. No-op if design mode was never on.
    if (entry.designModeWebContents) {
      if (entry.designModeListener) {
        try {
          entry.designModeWebContents.removeListener("console-message", entry.designModeListener);
        } catch {
          /* destroyed */
        }
      }
      if (entry.designModeInputListener) {
        try {
          entry.designModeWebContents.removeListener("input-event", entry.designModeInputListener);
        } catch {
          /* destroyed */
        }
      }
      entry.designModeListener = null;
      entry.designModeInputListener = null;
      entry.designModeWebContents = null;
    }
    detachProxyLogin(entry);
    entry.boundsController.clear();
    try {
      entry.view.webContents.close();
    } catch {
      /* already destroyed */
    }
    entries.delete(conversationId);
    stopSharedProxy();
    sendToRenderer("browser-view-closed", { conversationId, reason: reason || null });
    return { ok: true, removed: true };
  }

  function closeAll(reason) {
    for (const conversationId of [...entries.keys()]) {
      close(conversationId, reason);
    }
  }

  return {
    // Lifecycle
    get,
    getOrCreate,
    openOrNavigate,
    setActive,
    setSuppressed,
    close,
    closeAll,
    // Introspection
    activeConversationId: () => activeConversationId,
    isSuppressed: () => overlaySuppressed,
    size: () => entries.size,
    has: (conversationId) => entries.has(conversationId),
    forEach: (fn) => entries.forEach(fn),
    // Constants exposed for tests / main.js wiring
    cap,
  };
}

module.exports = {
  createBrowserViewRegistry,
  DEFAULT_CAP,
};
