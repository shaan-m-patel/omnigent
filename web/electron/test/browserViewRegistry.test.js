// Tests for the per-conversation browser-view registry (src/browserViewRegistry.js),
// run with `node --test` (no extra deps). The registry is a pure factory — all
// Electron deps are injected — so we drive it with stub views + spies.
//
// The load-bearing case is the FIRST-navigate activation signal: on a fresh
// conversation, openOrNavigate creates the view DETACHED (activeConversationId
// is null), so no `browser-host-active-changed` fires. Without the
// `browser-view-created` emit the React pane would never learn a view exists,
// never mount its placeholder, and never call setActive — the pane would stay
// invisible (the bug this test guards against).

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const { createBrowserViewRegistry } = require("../src/browserViewRegistry");
const { createAgentConnectProxy } = require("../src/browserConnectProxy");
const { createBrowserViewBoundsController } = require("../src/browserViewBounds");

// Public answers for the hosts these tests navigate to. Anything else resolves
// to metadata so a forgotten stub fails closed instead of hitting the network.
function agentNavigationDeps(overrides = {}) {
  return {
    lookup: async (hostname) => {
      const host = String(hostname).replace(/\.$/, "").toLowerCase();
      if (
        host === "example.com" ||
        host === "example.org" ||
        host === "example.net" ||
        host.endsWith(".example.com") ||
        host.endsWith(".example.org") ||
        host.endsWith(".example.net")
      ) {
        return [{ address: "93.184.216.34", family: 4 }];
      }
      return [{ address: "169.254.169.254", family: 4 }];
    },
    pinAgentConnection: async () => ({ ok: true }),
    ...overrides,
  };
}

/** Build a registry with spy-backed injected deps. Returns the registry plus
 *  the recorded renderer sends / attach / detach calls for assertions. */
function makeRegistry() {
  const sent = []; // { channel, payload }
  const attached = [];
  const detached = [];
  const visibility = []; // booleans passed to any view's setVisible, in order
  const makeStubView = () => ({
    setBounds() {},
    setVisible(v) {
      visibility.push(v);
    },
    webContents: {
      loadURL() {},
      close() {},
      removeListener() {},
      on() {},
      setWindowOpenHandler() {},
    },
  });
  const registry = createBrowserViewRegistry({
    WebContentsViewCtor: () => makeStubView(),
    createBoundsController: createBrowserViewBoundsController,
    attachToHost: (view) => attached.push(view),
    detachFromHost: (view) => detached.push(view),
    sendToRenderer: (channel, payload) => sent.push({ channel, payload }),
    getHostZoomFactor: () => 1,
  });
  return { registry, sent, attached, detached, visibility };
}

describe("browserViewRegistry — first-navigate activation signal", () => {
  let ctx;
  beforeEach(() => {
    ctx = makeRegistry();
  });

  it("emits browser-view-created on first openOrNavigate for a fresh conversation", async () => {
    const r = await ctx.registry.openOrNavigate("conv_1", "https://example.com");
    assert.equal(r.ok, true);
    assert.equal(r.created, true);
    const created = ctx.sent.filter((s) => s.channel === "browser-view-created");
    assert.equal(created.length, 1, "exactly one create event");
    assert.deepEqual(created[0].payload, { conversationId: "conv_1" });
  });

  it("creates the view DETACHED when the conversation isn't active (no attach, no host-active event)", async () => {
    await ctx.registry.openOrNavigate("conv_1", "https://example.com");
    // Fresh conversation → activeConversationId stayed null → never attached.
    assert.equal(ctx.attached.length, 0, "view is created detached");
    assert.equal(ctx.registry.activeConversationId(), null);
    const active = ctx.sent.filter((s) => s.channel === "browser-host-active-changed");
    assert.equal(active.length, 0, "no host-active event on detached create");
  });

  it("does NOT re-emit browser-view-created on a subsequent navigate of the same conversation", async () => {
    await ctx.registry.openOrNavigate("conv_1", "https://example.com");
    await ctx.registry.openOrNavigate("conv_1", "https://example.org");
    const created = ctx.sent.filter((s) => s.channel === "browser-view-created");
    assert.equal(created.length, 1, "create fires once, on first create only");
  });

  it("setActive after create attaches the view and fires host-active-changed", async () => {
    await ctx.registry.openOrNavigate("conv_1", "https://example.com");
    const r = ctx.registry.setActive("conv_1");
    assert.equal(r.ok, true);
    assert.equal(ctx.attached.length, 1, "setActive attaches the view");
    assert.equal(ctx.registry.activeConversationId(), "conv_1");
    const active = ctx.sent.filter(
      (s) => s.channel === "browser-host-active-changed" && s.payload.conversationId === "conv_1",
    );
    assert.equal(active.length, 1);
  });

  it("has() reports view existence for the re-mount probe", async () => {
    assert.equal(ctx.registry.has("conv_1"), false);
    await ctx.registry.openOrNavigate("conv_1", "https://example.com");
    assert.equal(ctx.registry.has("conv_1"), true);
  });

  it("full first-navigate path: create signal → setActive → attached + bounds synced", async () => {
    // Mirrors what BrowserPane does: it learns of the view from the create
    // event, mounts the placeholder, then setActive attaches + syncs bounds.
    // (the pane's onBrowserViewCreated listener)
    ctx.sent.length = 0;
    await ctx.registry.openOrNavigate("conv_1", "https://example.com");
    const sawCreate = ctx.sent.find((s) => s.channel === "browser-view-created");
    assert.ok(sawCreate, "pane would receive the create event");

    // Pane reacts: setActive(conversationId) then a resize (bounds).
    ctx.registry.setActive("conv_1");
    const entry = ctx.registry.get("conv_1");
    assert.ok(entry, "entry resolvable for resize");
    entry.boundsController.setRendererBounds({
      x: 10,
      y: 20,
      width: 300,
      height: 400,
      devicePixelRatio: 1,
    });
    assert.equal(ctx.attached.length, 1, "view attached to host");
  });

  it("close() detaches any design-mode console listener stored on the entry", async () => {
    await ctx.registry.openOrNavigate("conv_1", "https://example.com");
    const entry = ctx.registry.get("conv_1");
    // Simulate what browserIpc's enable-design-mode handler does: stash a
    // listener + its webContents on the entry. close() must detach it so a
    // destroyed view leaves no dangling console-message listener.
    let removed = null;
    const handler = () => {};
    entry.designModeListener = handler;
    entry.designModeWebContents = {
      removeListener: (evt, fn) => {
        removed = { evt, fn };
      },
    };
    const r = ctx.registry.close("conv_1");
    assert.equal(r.removed, true);
    assert.deepEqual(removed, { evt: "console-message", fn: handler });
    assert.equal(entry.designModeListener, null);
    assert.equal(entry.designModeWebContents, null);
  });
});

// Build a registry whose stub views record every loadURL call, so we can
// assert the agent-navigation allowlist blocks BEFORE loadURL is reached.
function makeLoadTrackingRegistry(overrides = {}) {
  const loaded = []; // urls passed to loadURL
  const registry = createBrowserViewRegistry({
    WebContentsViewCtor: () => ({
      setBounds() {},
      webContents: {
        loadURL(u) {
          loaded.push(u);
        },
        close() {},
        removeListener() {},
        on() {},
        setWindowOpenHandler() {},
      },
    }),
    createBoundsController: createBrowserViewBoundsController,
    attachToHost() {},
    detachFromHost() {},
    sendToRenderer() {},
    getHostZoomFactor: () => 1,
    ...agentNavigationDeps(overrides),
  });
  return { registry, loaded };
}

describe("browserViewRegistry — agent-navigation allowlist", () => {
  it("rejects agent navigation to file:// and never calls loadURL", async () => {
    const { registry, loaded } = makeLoadTrackingRegistry();
    const r = await registry.openOrNavigate("conv_1", "file:///home/user/.ssh/id_rsa", undefined, {
      agent: true,
    });
    assert.equal(r.ok, false);
    assert.match(r.error, /navigation blocked/);
    assert.equal(loaded.length, 0, "loadURL must not run on a rejected agent nav");
  });

  it("rejects agent navigation to the cloud-metadata IP (169.254.169.254)", async () => {
    const { registry, loaded } = makeLoadTrackingRegistry();
    const r = await registry.openOrNavigate(
      "conv_1",
      "http://169.254.169.254/latest/meta-data/",
      undefined,
      {
        agent: true,
      },
    );
    assert.equal(r.ok, false);
    assert.equal(loaded.length, 0);
  });

  it("rejects agent navigation to localhost", async () => {
    const { registry, loaded } = makeLoadTrackingRegistry();
    const r = await registry.openOrNavigate("conv_1", "http://localhost:6767/health", undefined, {
      agent: true,
    });
    assert.equal(r.ok, false);
    assert.equal(loaded.length, 0);
  });

  it("allows agent navigation to a normal public https URL (loadURL runs)", async () => {
    const { registry, loaded } = makeLoadTrackingRegistry();
    const r = await registry.openOrNavigate("conv_1", "https://example.com/", undefined, {
      agent: true,
    });
    assert.equal(r.ok, true);
    assert.deepEqual(loaded, ["https://example.com/"]);
  });

  it("does NOT gate the user-typed URL-bar path (agent flag absent) — file:// still loads", async () => {
    // The URL bar is user-initiated; the strict allowlist is scoped to the
    // agent path only. A user who types a local address keeps that ability.
    const { registry, loaded } = makeLoadTrackingRegistry();
    const r = await registry.openOrNavigate("conv_1", "file:///tmp/report.html", undefined, {
      force: true,
    });
    assert.equal(r.ok, true);
    assert.deepEqual(loaded, ["file:///tmp/report.html"]);
  });

  it("rejects an agent navigation whose name resolves to a metadata address", async () => {
    const { registry, loaded } = makeLoadTrackingRegistry({
      lookup: async () => [{ address: "169.254.169.254", family: 4 }],
    });
    const r = await registry.openOrNavigate(
      "conv_1",
      "http://rebind.test/latest/meta-data/",
      undefined,
      {
        agent: true,
      },
    );
    assert.equal(r.ok, false);
    assert.match(r.error, /navigation blocked/);
    assert.equal(loaded.length, 0);
    assert.equal(registry.has("conv_1"), false, "a rejected nav must not leave a view behind");
  });

  it("does not loadURL when the pinning proxy cannot be installed", async () => {
    const { registry, loaded } = makeLoadTrackingRegistry({
      pinAgentConnection: async () => ({
        ok: false,
        error: "navigation blocked: agent browser cannot pin the resolved address",
      }),
    });
    const r = await registry.openOrNavigate("conv_1", "https://example.com/", undefined, {
      agent: true,
    });
    assert.equal(r.ok, false);
    assert.match(r.error, /not pin/);
    assert.equal(loaded.length, 0);
    assert.equal(registry.has("conv_1"), false);
  });

  it("pins the connection before loadURL and keeps the hostname in the URL", async () => {
    let pinned = false;
    const { registry, loaded } = makeLoadTrackingRegistry({
      pinAgentConnection: async () => {
        assert.equal(loaded.length, 0, "loadURL must wait until the pin succeeds");
        pinned = true;
        return { ok: true };
      },
    });
    const r = await registry.openOrNavigate("conv_1", "https://example.com/docs", undefined, {
      agent: true,
    });
    assert.equal(r.ok, true);
    assert.equal(pinned, true);
    assert.deepEqual(loaded, ["https://example.com/docs"]);
    assert.equal(registry.get("conv_1").agentProxyEngaged, true);
    assert.equal(registry.get("conv_1").agentNavLocked, true);
  });
});

// A stub view that captures the webContents event handlers (will-navigate /
// will-redirect / will-frame-navigate) and the window-open handler, so tests
// can fire a redirect and assert whether it was cancelled (preventDefault).
function makeEventCapturingRegistry() {
  const sent = []; // { channel, payload }
  let handlers; // { [event]: fn } for the single created view
  let windowOpenHandler;
  const registry = createBrowserViewRegistry({
    WebContentsViewCtor: () => {
      handlers = {};
      return {
        setBounds() {},
        webContents: {
          loadURL() {},
          close() {},
          removeListener() {},
          on(event, fn) {
            handlers[event] = fn;
          },
          setWindowOpenHandler(fn) {
            windowOpenHandler = fn;
          },
        },
      };
    },
    createBoundsController: createBrowserViewBoundsController,
    attachToHost() {},
    detachFromHost() {},
    sendToRenderer: (channel, payload) => sent.push({ channel, payload }),
    getHostZoomFactor: () => 1,
    ...agentNavigationDeps(),
  });
  return {
    registry,
    sent,
    fire: (event, targetUrl) => {
      const ev = {
        url: targetUrl,
        prevented: false,
        preventDefault() {
          this.prevented = true;
        },
      };
      handlers[event](ev, targetUrl);
      return ev;
    },
    windowOpen: (url) => windowOpenHandler({ url }),
  };
}

describe("browserViewRegistry — redirect/nav guard (SSRF: allowlist on every hop)", () => {
  it("blocks an agent-locked will-redirect to the cloud-metadata IP", async () => {
    const { registry, sent, fire } = makeEventCapturingRegistry();
    // Agent navigates to an allowed host (locks the view to agent policy).
    await registry.openOrNavigate("conv_1", "https://example.com/", undefined, { agent: true });
    // The server 302s to the metadata endpoint — the guard must cancel it.
    const ev = fire("will-redirect", "http://169.254.169.254/latest/meta-data/");
    assert.equal(ev.prevented, true, "will-redirect to metadata must be preventDefault'd");
    const blocked = sent.filter((s) => s.channel === "browser-nav-blocked");
    assert.equal(blocked.length, 1, "a browser-nav-blocked signal is emitted");
    assert.match(blocked[0].payload.error, /navigation blocked/);
  });

  it("blocks an agent-locked will-navigate to a loopback host", async () => {
    const { registry, fire } = makeEventCapturingRegistry();
    await registry.openOrNavigate("conv_1", "https://example.com/", undefined, { agent: true });
    const ev = fire("will-navigate", "http://127.0.0.1:8080/");
    assert.equal(ev.prevented, true);
  });

  it("blocks an agent-locked will-navigate to an RFC-1918 private host", async () => {
    const { registry, fire } = makeEventCapturingRegistry();
    await registry.openOrNavigate("conv_1", "https://example.com/", undefined, { agent: true });
    const ev = fire("will-navigate", "http://10.1.2.3/admin");
    assert.equal(ev.prevented, true);
  });

  it("allows an agent-locked redirect between normal public https hosts", async () => {
    const { registry, sent, fire } = makeEventCapturingRegistry();
    await registry.openOrNavigate("conv_1", "https://example.com/", undefined, { agent: true });
    const ev = fire("will-redirect", "https://cdn.example.net/asset");
    assert.equal(ev.prevented, false, "a normal https→https redirect must not be blocked");
    assert.equal(sent.filter((s) => s.channel === "browser-nav-blocked").length, 0);
  });

  it("does NOT block redirects on a user-typed (non-agent) navigation", async () => {
    const { registry, fire } = makeEventCapturingRegistry();
    // User types a URL (no agent flag) → the view is NOT agent-locked, so its
    // redirects — even to an internal host (auth-redirect chains) — are allowed.
    await registry.openOrNavigate("conv_1", "https://intranet.example.com/", undefined, {
      force: true,
    });
    const ev = fire("will-redirect", "http://10.0.0.5/sso/callback");
    assert.equal(ev.prevented, false, "user-driven nav stays permissive");
  });

  it("blocks an agent-locked redirect to CGNAT, Azure WireServer, and IPv6 ULA", async () => {
    const { registry, fire } = makeEventCapturingRegistry();
    await registry.openOrNavigate("conv_1", "https://example.com/", undefined, { agent: true });
    for (const url of [
      "http://100.100.100.200/latest/meta-data/",
      "http://100.64.1.1/",
      "http://168.63.129.16/",
      "http://[fd00::1]/",
      "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
      "http://[::ffff:7f00:1]/",
    ]) {
      const ev = fire("will-redirect", url);
      assert.equal(ev.prevented, true, `expected block: ${url}`);
    }
  });

  it("blocks an agent-locked subframe navigation to a non-public literal", async () => {
    const { registry, fire } = makeEventCapturingRegistry();
    await registry.openOrNavigate("conv_1", "https://example.com/", undefined, { agent: true });
    const ev = fire("will-frame-navigate", "http://[fc00::1]/admin");
    assert.equal(ev.prevented, true);
  });

  it("blocks every hop while the agent lock is on but the proxy is not engaged", async () => {
    const { registry, fire } = makeEventCapturingRegistry();
    await registry.openOrNavigate("conv_1", "https://example.com/", undefined, { agent: true });
    registry.get("conv_1").agentProxyEngaged = false;
    const ev = fire("will-navigate", "https://cdn.example.net/asset");
    assert.equal(ev.prevented, true);
  });

  it("re-locks correctly: a user nav after an agent nav flips enforcement off", async () => {
    const { registry, fire } = makeEventCapturingRegistry();
    await registry.openOrNavigate("conv_1", "https://example.com/", undefined, { agent: true });
    // Then the user types a new address on the same view.
    await registry.openOrNavigate("conv_1", "https://intranet.example.com/", undefined, {
      force: true,
    });
    const ev = fire("will-redirect", "http://192.168.1.10/");
    assert.equal(ev.prevented, false, "the later user nav unlocked the view");
  });
});

describe("browserViewRegistry — child window.open is denied (S3)", () => {
  it("installs a window-open handler that denies every popup", async () => {
    const { registry, windowOpen } = makeEventCapturingRegistry();
    await registry.openOrNavigate("conv_1", "https://example.com/", undefined, { agent: true });
    assert.deepEqual(windowOpen("https://evil.example.com/popup"), { action: "deny" });
    assert.deepEqual(windowOpen("https://example.com/ok"), { action: "deny" });
  });
});

describe("browserViewRegistry — overlay suppression (#3980)", () => {
  let ctx;
  beforeEach(() => {
    ctx = makeRegistry();
  });

  it("toggles setVisible on the active view when suppressed/unsuppressed", async () => {
    await ctx.registry.openOrNavigate("conv_1", "https://example.com");
    ctx.registry.setActive("conv_1");
    ctx.visibility.length = 0; // ignore any visibility calls during attach
    ctx.registry.setSuppressed(true);
    assert.deepEqual(ctx.visibility, [false], "suppress hides the active view");
    ctx.registry.setSuppressed(false);
    assert.deepEqual(ctx.visibility, [false, true], "unsuppress shows it again");
    assert.equal(ctx.registry.isSuppressed(), false);
  });

  it("keeps a view hidden when it becomes active while suppression is on (sticky)", async () => {
    // Suppress with nothing active, then attach a view — it must attach hidden.
    await ctx.registry.openOrNavigate("conv_1", "https://example.com");
    ctx.registry.setSuppressed(true);
    ctx.visibility.length = 0;
    ctx.registry.setActive("conv_1");
    assert.ok(
      ctx.visibility.includes(false) && !ctx.visibility.includes(true),
      "a view attaching under active suppression stays hidden",
    );
  });

  it("is a no-op (no throw) when no view is active", async () => {
    assert.deepEqual(ctx.registry.setSuppressed(true), { ok: true });
    assert.equal(ctx.registry.isSuppressed(), true);
    assert.equal(ctx.visibility.length, 0, "nothing to toggle with no active view");
  });
});

describe("browserViewRegistry — pinning proxy is installed before loadURL", () => {
  it("sends agent traffic through the proxy and refuses a rebinding CONNECT", async () => {
    const events = [];
    const handlers = {};
    let proxyConfig = null;
    let partition = null;
    const connects = [];
    const registry = createBrowserViewRegistry({
      WebContentsViewCtor: (opts) => {
        partition = opts.webPreferences.partition;
        return {
          setBounds() {},
          webContents: {
            loadURL() {
              events.push("load");
            },
            close() {},
            removeListener(event, fn) {
              if (handlers[event] === fn) delete handlers[event];
            },
            on(event, fn) {
              handlers[event] = fn;
            },
            setWindowOpenHandler() {},
            session: {
              async setProxy(cfg) {
                events.push(`setProxy:${cfg.mode}`);
                proxyConfig = cfg;
              },
            },
          },
        };
      },
      createBoundsController: createBrowserViewBoundsController,
      attachToHost() {},
      detachFromHost() {},
      sendToRenderer() {},
      getHostZoomFactor: () => 1,
      lookup: async (host) => {
        if (host === "example.com") return [{ address: "93.184.216.34", family: 4 }];
        if (host === "rebind.test") return [{ address: "10.1.2.3", family: 4 }];
        throw new Error(`unexpected lookup ${host}`);
      },
      createConnectProxy: (opts) =>
        createAgentConnectProxy({
          ...opts,
          connectTcp(spec) {
            connects.push(spec);
            const sock = new (require("node:events").EventEmitter)();
            sock.destroy = () => {};
            sock.write = () => {};
            sock.pipe = () => sock;
            process.nextTick(() => sock.emit("error", new Error("stopped")));
            return sock;
          },
        }),
    });

    const opened = await registry.openOrNavigate("conv_1", "https://example.com/start", undefined, {
      agent: true,
    });
    assert.equal(opened.ok, true);
    assert.deepEqual(events, ["setProxy:fixed_servers", "load"]);
    assert.equal(proxyConfig.proxyBypassRules, "");
    assert.match(proxyConfig.proxyRules, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.equal(partition, "persist:omnigent-browser-conv_1");
    assert.equal(registry.get("conv_1").agentProxyEngaged, true);

    let creds = null;
    handlers.login({ preventDefault() {} }, {}, { isProxy: true }, (user, pass) => {
      creds = { user, pass };
    });
    assert.ok(creds, "the view answers the proxy's auth challenge");
    const port = Number(proxyConfig.proxyRules.slice(proxyConfig.proxyRules.lastIndexOf(":") + 1));
    const status = await new Promise((resolve, reject) => {
      const req = http.request({
        host: "127.0.0.1",
        port,
        method: "CONNECT",
        path: "rebind.test:80",
        headers: {
          "Proxy-Authorization":
            "Basic " + Buffer.from(`${creds.user}:${creds.pass}`).toString("base64"),
        },
      });
      req.on("connect", (res, socket) => {
        socket.destroy();
        resolve(res.statusCode);
      });
      req.on("error", reject);
      req.end();
    });
    assert.equal(status, 403);
    assert.equal(connects.length, 0, "a private DNS answer must not be dialed");

    // A later user navigation drops the proxy so the URL bar can reach internal hosts.
    const cleared = [];
    registry.get("conv_1").view.webContents.session.setProxy = async (cfg) => {
      cleared.push(cfg.mode);
    };
    const userNav = await registry.openOrNavigate("conv_1", "http://10.0.0.5/", undefined, {
      force: true,
    });
    assert.equal(userNav.ok, true);
    assert.deepEqual(cleared, ["direct"]);
    assert.equal(registry.get("conv_1").agentNavLocked, false);
    assert.equal(registry.get("conv_1").agentProxyEngaged, false);

    registry.close("conv_1");
  });
});
