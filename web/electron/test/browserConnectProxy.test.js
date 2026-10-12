// The agent browser's pinning proxy: one DNS lookup per destination, then a
// TCP connection only to that address. Run with `node --test`.

const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { PassThrough } = require("node:stream");

const { createAgentConnectProxy } = require("../src/browserConnectProxy");

function basic(user, pass) {
  return "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
}

function connectRequest(port, authority, headers) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      method: "CONNECT",
      path: authority,
      headers,
    });
    req.on("connect", (res, socket) => {
      socket.destroy();
      resolve(res.statusCode);
    });
    req.on("error", reject);
    req.end();
  });
}

function httpProxyGet(port, url, headers) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: url, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    req.on("error", reject);
  });
}

/**
 * @param {object} [overrides]
 */
async function startProxy(overrides = {}) {
  const connects = [];
  const httpOptions = [];
  const proxy = createAgentConnectProxy({
    lookup: async () => [{ address: "1.1.1.1", family: 4 }],
    connectTcp(spec) {
      connects.push(spec);
      const sock = new PassThrough();
      process.nextTick(() => sock.emit("connect"));
      return sock;
    },
    httpRequest(options, callback) {
      httpOptions.push(options);
      const res = new PassThrough();
      res.statusCode = 204;
      res.headers = { "content-length": "0" };
      const req = new PassThrough();
      process.nextTick(() => {
        callback(res);
        res.end();
      });
      return req;
    },
    ...overrides,
  });
  const port = await proxy.listen();
  return { proxy, port, connects, httpOptions };
}

describe("browserConnectProxy — pin and refuse", () => {
  /** @type {Array<{ proxy: { close: () => Promise<void> } }>} */
  const open = [];
  after(async () => {
    for (const item of open) await item.proxy.close();
  });

  it("refuses CONNECT without proxy credentials and does not dial", async () => {
    const started = await startProxy();
    open.push(started);
    const status = await connectRequest(started.port, "example.com:443");
    assert.equal(status, 407);
    assert.equal(started.connects.length, 0);
  });

  it("CONNECT dials only the pinned address, not the hostname", async () => {
    const started = await startProxy({
      lookup: async (host) => {
        assert.equal(host, "example.com");
        return [
          { address: "1.0.0.1", family: 4 },
          { address: "1.1.1.1", family: 4 },
        ];
      },
    });
    open.push(started);
    const status = await connectRequest(started.port, "example.com:443", {
      "Proxy-Authorization": basic(started.proxy.username, started.proxy.password),
    });
    assert.equal(status, 200);
    assert.equal(started.connects.length, 1);
    assert.equal(started.connects[0].host, "1.0.0.1");
    assert.equal(started.connects[0].port, 443);
    assert.equal(started.connects[0].family, 4);
  });

  it("refuses a DNS answer that is not globally routable and does not dial", async () => {
    const started = await startProxy({
      lookup: async () => [
        { address: "8.8.8.8", family: 4 },
        { address: "169.254.169.254", family: 4 },
      ],
    });
    open.push(started);
    const status = await connectRequest(started.port, "rebind.test:80", {
      "Proxy-Authorization": basic(started.proxy.username, started.proxy.password),
    });
    assert.equal(status, 403);
    assert.equal(started.connects.length, 0);
  });

  it("refuses literal metadata, CGNAT, Azure, and IPv6 unique-local targets", async () => {
    const started = await startProxy({
      lookup: async () => {
        throw new Error("literal targets must not be resolved");
      },
    });
    open.push(started);
    const auth = { "Proxy-Authorization": basic(started.proxy.username, started.proxy.password) };
    for (const authority of [
      "169.254.169.254:80",
      "100.100.100.200:80",
      "168.63.129.16:80",
      "[fd00::1]:80",
      "[::ffff:a9fe:a9fe]:80",
      "[::ffff:7f00:1]:80",
    ]) {
      const status = await connectRequest(started.port, authority, auth);
      assert.equal(status, 403, authority);
    }
    assert.equal(started.connects.length, 0);
  });

  it("forwards HTTP to the pinned address and keeps the original Host", async () => {
    const started = await startProxy();
    open.push(started);
    const result = await httpProxyGet(started.port, "http://example.com/latest", {
      "Proxy-Authorization": basic(started.proxy.username, started.proxy.password),
      Host: "example.com",
    });
    assert.equal(result.status, 204);
    assert.equal(started.httpOptions.length, 1);
    const options = started.httpOptions[0];
    assert.equal(options.host, "1.1.1.1");
    assert.equal(options.headers.host, "example.com");
    assert.equal(options.headers["proxy-authorization"], undefined);
    await new Promise((resolve, reject) => {
      options.lookup("example.com", {}, (err, address, family) => {
        if (err) reject(err);
        else {
          assert.equal(address, "1.1.1.1");
          assert.equal(family, 4);
          resolve();
        }
      });
    });
  });

  it("refuses an HTTP forward to a metadata literal", async () => {
    const started = await startProxy();
    open.push(started);
    const result = await httpProxyGet(started.port, "http://100.100.100.200/latest/meta-data/", {
      "Proxy-Authorization": basic(started.proxy.username, started.proxy.password),
    });
    assert.equal(result.status, 403);
    assert.match(result.body, /navigation blocked/);
    assert.equal(started.httpOptions.length, 0);
  });
});
