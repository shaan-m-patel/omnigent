// Tests for the agent-navigation URL allowlist (src/browserUrlPolicy.js),
// run with `node --test`. Pure function — no Electron needed.
//
// The security property under test: a model-issued `browser_navigate` must not
// be able to reach file://, cloud-metadata / loopback / private-range hosts,
// or any non-http(s) scheme (else it screenshots the bytes back out = SSRF +
// local-file read + exfil). Normal public https must still be allowed.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const { execFileSync } = require("node:child_process");

const {
  isAgentNavigationAllowed,
  resolveAgentNavigation,
  assessIp,
  parseIpv6,
} = require("../src/browserUrlPolicy");

describe("browserUrlPolicy — agent navigation allowlist", () => {
  it("allows ordinary public http(s) URLs", () => {
    for (const url of [
      "https://example.com/",
      "http://example.com/path?q=1",
      "https://sub.domain.example.org/a/b",
      "https://example.com:8443/x", // non-loopback host with a port is fine
    ]) {
      assert.equal(isAgentNavigationAllowed(url).ok, true, `expected allow: ${url}`);
    }
  });

  it("rejects non-http(s) schemes (file/chrome/devtools/data/blob/javascript/about)", () => {
    for (const url of [
      "file:///home/user/.ssh/id_rsa",
      "file:///etc/passwd",
      "chrome://settings",
      "devtools://devtools/bundled/inspector.html",
      "data:text/html,<script>alert(1)</script>",
      "blob:https://example.com/uuid",
      "javascript:alert(document.cookie)",
      "about:blank",
    ]) {
      const v = isAgentNavigationAllowed(url);
      assert.equal(v.ok, false, `expected reject: ${url}`);
      assert.match(v.error, /navigation blocked/);
    }
  });

  it("blocks cloud metadata + link-local (169.254.0.0/16)", () => {
    for (const url of [
      "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/",
      "http://169.254.0.1/",
      "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ]) {
      assert.equal(isAgentNavigationAllowed(url).ok, false, `expected reject: ${url}`);
    }
  });

  it("blocks loopback: localhost, *.localhost, 127.0.0.0/8, ::1", () => {
    for (const url of [
      "http://localhost/",
      "http://localhost:6767/health",
      "http://app.localhost/",
      "http://127.0.0.1/",
      "http://127.0.0.1:8080/admin",
      "http://127.5.6.7/",
      "http://[::1]/",
    ]) {
      assert.equal(isAgentNavigationAllowed(url).ok, false, `expected reject: ${url}`);
    }
  });

  it("blocks RFC-1918 private ranges (10/8, 172.16/12, 192.168/16)", () => {
    for (const url of [
      "http://10.0.0.1/",
      "http://10.255.255.255/",
      "http://172.16.0.1/",
      "http://172.20.10.5/",
      "http://172.31.255.255/",
      "http://192.168.0.1/",
      "http://192.168.1.100/internal",
    ]) {
      assert.equal(isAgentNavigationAllowed(url).ok, false, `expected reject: ${url}`);
    }
  });

  it("allows the 172.x hosts that are NOT in the private /12 (172.15, 172.32)", () => {
    assert.equal(isAgentNavigationAllowed("http://172.15.0.1/").ok, true);
    assert.equal(isAgentNavigationAllowed("http://172.32.0.1/").ok, true);
  });

  it("canonicalizes obfuscated IPv4 forms before checking (integer/hex/octal)", () => {
    // WHATWG URL normalizes these to 127.0.0.1 — the allowlist must still block.
    for (const url of [
      "http://2130706433/", // 127.0.0.1 as a 32-bit int
      "http://0x7f000001/", // 127.0.0.1 as hex
      "http://0177.0.0.1/", // 127.0.0.1 with an octal first octet
    ]) {
      assert.equal(isAgentNavigationAllowed(url).ok, false, `expected reject: ${url}`);
    }
  });

  it("rejects empty / malformed / non-string input without throwing", () => {
    for (const bad of ["", "   ", "not a url", "://missing-scheme", null, undefined, 42]) {
      const v = isAgentNavigationAllowed(bad);
      assert.equal(v.ok, false);
    }
  });

  it("blocks CGNAT, Alibaba IMDS, Azure WireServer, multicast, and documentation ranges", () => {
    for (const url of [
      "http://100.100.100.200/latest/meta-data/",
      "http://100.64.0.1/",
      "http://100.127.255.255/",
      "http://168.63.129.16/",
      "http://224.0.0.1/",
      "http://239.255.255.255/",
      "http://240.0.0.1/",
      "http://255.255.255.255/",
      "http://192.0.2.1/",
      "http://198.51.100.1/",
      "http://203.0.113.1/",
      "http://198.18.0.1/",
      "http://192.0.0.8/",
      "http://0.0.0.0/",
    ]) {
      assert.equal(isAgentNavigationAllowed(url).ok, false, `expected reject: ${url}`);
    }
  });

  it("blocks IPv6 unique-local, link-local, multicast, and compressed IPv4-mapped forms", () => {
    for (const url of [
      "http://[fd00::1]/",
      "http://[fc00::1]/",
      "http://[fe80::1]/",
      "http://[febf::1]/",
      "http://[fec0::1]/",
      "http://[ff02::1]/",
      "http://[::]/",
      "http://[::1]/",
      "http://[::ffff:7f00:1]/", // 127.0.0.1
      "http://[::ffff:a9fe:a9fe]/latest/meta-data/", // 169.254.169.254
      "http://[::ffff:6464:64c8]/", // 100.100.100.200
      "http://[::ffff:a83f:8110]/", // 168.63.129.16
      "http://[::ffff:a00:1]/", // 10.0.0.1
      "http://[64:ff9b::a9fe:a9fe]/", // NAT64 embedding of metadata
      "http://[::7f00:1]/", // deprecated IPv4-compatible loopback
      "http://[2001:db8::1]/",
      "http://localhost./",
      "http://app.localhost./",
    ]) {
      assert.equal(isAgentNavigationAllowed(url).ok, false, `expected reject: ${url}`);
    }
  });

  it("allows globally routable literals, including public IPv4-mapped and the 192.0.0.9 exception", () => {
    for (const url of [
      "http://8.8.8.8/",
      "http://1.1.1.1/",
      "http://100.63.255.255/",
      "http://100.128.0.1/",
      "http://192.0.0.9/",
      "http://192.0.0.10/",
      "https://[2001:4860:4860::8888]/",
      "http://[::ffff:808:808]/", // 8.8.8.8
      "http://[2606:4700:4700::1111]/",
    ]) {
      assert.equal(isAgentNavigationAllowed(url).ok, true, `expected allow: ${url}`);
    }
  });

  it("parses IPv6 literals the same way Python does", () => {
    const samples = [
      "::",
      "::1",
      "fe80::1",
      "febf::1",
      "fd00::1",
      "fc00::1",
      "::ffff:7f00:1",
      "::ffff:127.0.0.1",
      "::ffff:a9fe:a9fe",
      "::ffff:169.254.169.254",
      "::ffff:6464:64c8",
      "::ffff:100.100.100.200",
      "::ffff:a83f:8110",
      "64:ff9b::a9fe:a9fe",
      "2001:4860:4860::8888",
      "ff02::1",
      "::7f00:1",
      "2001:db8::1",
      "fec0::1",
      "2001:1::1",
    ];
    const raw = execFileSync(
      "python3",
      [
        "-c",
        "import ipaddress, json, sys\n" +
          "samples = json.loads(sys.argv[1])\n" +
          "print(json.dumps({s: str(int(ipaddress.ip_address(s))) for s in samples}))\n",
        JSON.stringify(samples),
      ],
      { encoding: "utf8" },
    );
    const parsed = JSON.parse(raw);
    for (const sample of samples) {
      assert.equal(parseIpv6(sample).toString(), parsed[sample], sample);
    }
  });

  it("matches Python is_global/multicast plus the Azure cloud trap for IPv4", () => {
    const samples = [
      "0.0.0.0",
      "10.1.2.3",
      "100.63.255.255",
      "100.64.0.0",
      "100.100.100.200",
      "100.127.255.255",
      "100.128.0.1",
      "127.0.0.1",
      "169.254.169.254",
      "172.15.255.255",
      "172.16.0.0",
      "172.31.255.255",
      "172.32.0.0",
      "192.0.0.8",
      "192.0.0.9",
      "192.0.0.10",
      "192.0.0.11",
      "192.0.2.1",
      "192.168.1.1",
      "198.18.0.1",
      "198.51.100.1",
      "203.0.113.1",
      "224.0.0.1",
      "233.252.0.0",
      "240.0.0.1",
      "255.255.255.255",
      "8.8.8.8",
      "1.1.1.1",
      "168.63.129.16",
      "11.0.0.1",
    ];
    const raw = execFileSync(
      "python3",
      [
        "-c",
        "import ipaddress, json, sys\n" +
          "trap = ipaddress.ip_address('168.63.129.16')\n" +
          "samples = json.loads(sys.argv[1])\n" +
          "out = {}\n" +
          "for s in samples:\n" +
          "    a = ipaddress.ip_address(s)\n" +
          "    out[s] = (not a.is_global) or a.is_multicast or a == trap\n" +
          "print(json.dumps(out))\n",
        JSON.stringify(samples),
      ],
      { encoding: "utf8" },
    );
    const expected = JSON.parse(raw);
    for (const sample of samples) {
      assert.equal(!assessIp(sample).ok, expected[sample], sample);
    }
  });
});

describe("browserUrlPolicy — DNS pin", () => {
  it("does not resolve an IP literal that already passed the string check", async () => {
    let called = false;
    const verdict = await resolveAgentNavigation("http://8.8.8.8/dns", async () => {
      called = true;
      return [{ address: "127.0.0.1", family: 4 }];
    });
    assert.equal(called, false);
    assert.deepEqual(verdict, { ok: true, pinnedAddress: "8.8.8.8" });
  });

  it("pins the first address when every answer is globally routable", async () => {
    const verdict = await resolveAgentNavigation("https://example.com/a", async () => [
      { address: "1.1.1.1", family: 4 },
      { address: "8.8.8.8", family: 4 },
    ]);
    assert.deepEqual(verdict, { ok: true, pinnedAddress: "1.1.1.1" });
  });

  it("fails closed when any answer is non-public, metadata, or a cloud trap", async () => {
    for (const answers of [
      ["1.1.1.1", "169.254.169.254"],
      ["10.0.0.5"],
      ["100.100.100.200"],
      ["168.63.129.16"],
      ["fd00::1"],
      ["::ffff:7f00:1"],
      ["::ffff:6464:64c8"],
      ["64:ff9b::a9fe:a9fe"],
    ]) {
      const verdict = await resolveAgentNavigation("http://rebind.test/", async () =>
        answers.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })),
      );
      assert.equal(verdict.ok, false, `expected reject for ${answers.join(",")}`);
      assert.match(verdict.error, /navigation blocked/);
    }
  });

  it("fails closed when DNS fails or returns nothing", async () => {
    const failed = await resolveAgentNavigation("http://rebind.test/", async () => {
      throw new Error("ENOTFOUND");
    });
    assert.equal(failed.ok, false);
    assert.match(failed.error, /DNS resolution failed/);
    const empty = await resolveAgentNavigation("http://rebind.test/", async () => []);
    assert.equal(empty.ok, false);
    assert.match(empty.error, /no address/);
  });

  it("fails closed when no resolver is available for a hostname", async () => {
    const verdict = await resolveAgentNavigation("https://example.com/", undefined);
    assert.equal(verdict.ok, false);
    assert.match(verdict.error, /resolver unavailable/);
  });
});
