// Local HTTP proxy for agent-locked browser views.
//
// Chromium dials this proxy instead of resolving the page's hostname itself.
// Each CONNECT or forward resolves the destination once and opens TCP only to
// that pinned address, so a second DNS answer cannot retarget the socket onto
// metadata, loopback, or another non-global host.

"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const net = require("node:net");

const { resolveAgentNavigation } = require("./browserUrlPolicy");

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/**
 * @param {string} host
 * @param {number} [defaultPort]
 * @returns {{ host: string, port: number } | null}
 */
function parseHostPort(authority, defaultPort) {
  if (typeof authority !== "string" || authority.length === 0 || authority.length > 2048) {
    return null;
  }
  let host;
  let portStr;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end <= 1) return null;
    host = authority.slice(1, end);
    const rest = authority.slice(end + 1);
    if (rest === "") portStr = "";
    else if (rest.startsWith(":")) portStr = rest.slice(1);
    else return null;
  } else {
    const colon = authority.lastIndexOf(":");
    if (colon === -1) {
      host = authority;
      portStr = "";
    } else {
      host = authority.slice(0, colon);
      portStr = authority.slice(colon + 1);
    }
  }
  if (!host || host.includes("/") || host.includes(" ") || host.includes("@")) return null;
  const port = portStr === "" ? defaultPort : Number(portStr);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

/**
 * @param {string} host
 */
function probeUrl(host) {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  return bare.includes(":") ? `http://[${bare}]/` : `http://${bare}/`;
}

/**
 * @param {string} address
 * @returns {4 | 6}
 */
function addressFamily(address) {
  return address.includes(":") ? 6 : 4;
}

/**
 * Force Node's resolver to the address we already accepted. `http.request`
 * would otherwise look the host up again.
 *
 * @param {string} address
 */
function pinnedLookup(address) {
  const family = addressFamily(address);
  return (hostname, options, callback) => {
    let cb = callback;
    let opts = options;
    if (typeof options === "function") {
      cb = options;
      opts = {};
    }
    if (opts && opts.all) cb(null, [{ address, family }]);
    else cb(null, address, family);
  };
}

/**
 * @param {{ lookup?: Function, connectTcp?: Function, httpRequest?: Function }} [opts]
 */
function createAgentConnectProxy({
  lookup,
  connectTcp = net.connect,
  httpRequest = http.request,
} = {}) {
  const password = crypto.randomBytes(24).toString("hex");
  const username = "omnigent";
  const expectedUserPass = Buffer.from(`${username}:${password}`);
  const server = http.createServer();

  /**
   * @param {string | undefined} header
   */
  function authorized(header) {
    if (typeof header !== "string") return false;
    const space = header.indexOf(" ");
    if (space <= 0 || header.slice(0, space).toLowerCase() !== "basic") return false;
    let decoded;
    try {
      decoded = Buffer.from(header.slice(space + 1).trim(), "base64");
    } catch {
      return false;
    }
    if (decoded.length !== expectedUserPass.length) return false;
    return crypto.timingSafeEqual(decoded, expectedUserPass);
  }

  /**
   * @param {string} host
   */
  async function pinHost(host) {
    if (typeof lookup !== "function") {
      return { ok: false, error: "navigation blocked: DNS resolver unavailable" };
    }
    return resolveAgentNavigation(probeUrl(host), lookup);
  }

  /**
   * @param {import("node:http").IncomingMessage} req
   * @param {import("node:http").ServerResponse} res
   */
  async function forwardHttp(req, res) {
    if (!authorized(req.headers["proxy-authorization"])) {
      res.writeHead(407, {
        "Proxy-Authenticate": 'Basic realm="omnigent-browser"',
        "Content-Type": "text/plain",
        Connection: "close",
      });
      res.end("proxy authentication required");
      return;
    }
    let target;
    try {
      target = new URL(req.url || "");
    } catch {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("bad proxy request");
      return;
    }
    if (target.protocol !== "http:" || !target.hostname) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("navigation blocked: only http forward and https CONNECT are proxied");
      return;
    }
    if (req.headers["transfer-encoding"] && req.headers["content-length"]) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("bad proxy request");
      return;
    }
    const pinned = await pinHost(target.hostname);
    if (!pinned.ok) {
      res.writeHead(403, { "Content-Type": "text/plain", Connection: "close" });
      res.end(pinned.error);
      return;
    }
    const port = Number(target.port || 80);
    const headers = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (HOP_BY_HOP.has(name.toLowerCase())) continue;
      headers[name] = value;
    }
    // Origin sees the name the agent asked for; the socket goes to the pin.
    headers.host = target.host;
    const upstream = httpRequest(
      {
        host: pinned.pinnedAddress,
        port,
        family: addressFamily(pinned.pinnedAddress),
        method: req.method,
        path: `${target.pathname || "/"}${target.search}`,
        headers,
        lookup: pinnedLookup(pinned.pinnedAddress),
      },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
        upstreamRes.pipe(res);
      },
    );
    upstream.on("error", () => {
      if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" });
      res.end("upstream connection failed");
    });
    req.pipe(upstream);
  }

  /**
   * @param {import("node:http").IncomingMessage} req
   * @param {import("node:net").Socket} clientSocket
   * @param {Buffer} head
   */
  async function tunnel(req, clientSocket, head) {
    const deny = (status, body) => {
      if (clientSocket.destroyed) return;
      const reason =
        status === 407
          ? "Proxy Authentication Required"
          : status === 400
            ? "Bad Request"
            : status === 502
              ? "Bad Gateway"
              : "Forbidden";
      const extra = status === 407 ? 'Proxy-Authenticate: Basic realm="omnigent-browser"\r\n' : "";
      clientSocket.end(
        `HTTP/1.1 ${status} ${reason}\r\n${extra}Content-Type: text/plain\r\nConnection: close\r\n\r\n${body}`,
      );
    };
    if (!authorized(req.headers["proxy-authorization"])) {
      deny(407, "proxy authentication required");
      return;
    }
    const target = parseHostPort(req.url || "", 443);
    if (!target) {
      deny(400, "bad proxy request");
      return;
    }
    const pinned = await pinHost(target.host);
    if (!pinned.ok) {
      deny(403, pinned.error);
      return;
    }
    const upstream = connectTcp({
      host: pinned.pinnedAddress,
      port: target.port,
      family: addressFamily(pinned.pinnedAddress),
    });
    let established = false;
    upstream.on("error", () => {
      if (!established) deny(502, "upstream connection failed");
      else clientSocket.destroy();
    });
    upstream.on("connect", () => {
      established = true;
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
  }

  server.on("request", (req, res) => {
    forwardHttp(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" });
      res.end("proxy failure");
    });
  });
  server.on("connect", (req, clientSocket, head) => {
    clientSocket.on("error", () => {});
    tunnel(req, clientSocket, head).catch(() => {
      if (!clientSocket.destroyed) clientSocket.destroy();
    });
  });
  server.on("clientError", (_err, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    else socket.destroy();
  });

  return {
    username,
    password,
    listen() {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        // 127.0.0.1 only — the proxy is a local pin, not a network service.
        server.listen(0, "127.0.0.1", () => {
          server.unref();
          const address = server.address();
          resolve(typeof address === "object" && address ? address.port : 0);
        });
      });
    },
    port() {
      const address = server.address();
      return typeof address === "object" && address ? address.port : 0;
    },
    close() {
      return new Promise((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}

module.exports = {
  createAgentConnectProxy,
  parseHostPort,
};
