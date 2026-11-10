"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const html = fs.readFileSync(path.join(__dirname, "..", "ioc-extractor.html"), "utf8");
const START = "// ===== IOC-LOGIC-START";
const END = "// ===== IOC-LOGIC-END =====";
const from = html.indexOf(START);
const to = html.indexOf(END);
assert.ok(from !== -1 && to > from, "logic markers not found in ioc-extractor.html");
const code = html.slice(html.indexOf("\n", from) + 1, to);
const { refang, defangValue, extract, defangText } = new Function(
  code + "\nreturn { refang, defangValue, extract, defangText };"
)();

const SAMPLE = [
  "Visit http://evil.example.com/a/b.php?x=1 or https://other.test/path.",
  "Mail admin@phish.example.org. IPs 8.8.8.8, 2001:db8::1 and 192.168.0.1.",
  "MD5 44d88612fea8a8f36de82e1278abb02f",
  "SHA1 3395856ce81f2b7382dee72602f798b642f14140",
  "SHA256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "CVE-2021-44228 and cve-2023-23397."
].join("\n");

test("extracts all IOC types", () => {
  const r = extract(SAMPLE);
  assert.deepEqual(r.urls, ["http://evil.example.com/a/b.php?x=1", "https://other.test/path"]);
  assert.ok(r.domains.includes("evil.example.com"));
  assert.ok(r.domains.includes("other.test"));
  assert.ok(r.domains.includes("phish.example.org"));
  assert.deepEqual(r.ipv4, ["8.8.8.8", "192.168.0.1"]);
  assert.deepEqual(r.ipv6, ["2001:db8::1"]);
  assert.deepEqual(r.emails, ["admin@phish.example.org"]);
  assert.deepEqual(r.md5, ["44d88612fea8a8f36de82e1278abb02f"]);
  assert.deepEqual(r.sha1, ["3395856ce81f2b7382dee72602f798b642f14140"]);
  assert.deepEqual(r.sha256, ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]);
  assert.deepEqual(r.cve, ["CVE-2021-44228", "CVE-2023-23397"]);
});

test("understands defanged input", () => {
  const r = extract("hxxps://bad[.]example[.]com/x, evil(.)net, user[@]mail[dot]ru, a{dot}b{.}org, 1[.]2[.]3[.]4, fxp://ftp[.]site[.]io/f, hxxp[://]foo[.]bar, x(at)y.com");
  assert.ok(r.urls.includes("https://bad.example.com/x"));
  assert.ok(r.urls.includes("ftp://ftp.site.io/f"));
  assert.ok(r.urls.includes("http://foo.bar"));
  assert.ok(r.domains.includes("evil.net"));
  assert.ok(r.domains.includes("a.b.org"));
  assert.ok(r.emails.includes("user@mail.ru"));
  assert.ok(r.emails.includes("x@y.com"));
  assert.deepEqual(r.ipv4, ["1.2.3.4"]);
});

test("refang handles hxxp, brackets and case", () => {
  assert.equal(refang("hxxp[:]//a[.]b"), "http://a.b");
  assert.equal(refang("HXXPS://A[.]B"), "HTTPS://A.B");
  assert.equal(refang("u[at]h[dot]com (at) {dot}"), "u@h.com @ .");
});

test("private IPs are filtered only on request", () => {
  const priv = ["10.1.2.3", "127.0.0.1", "0.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.1.1", "169.254.1.1"];
  const pub = ["172.15.0.1", "172.32.0.1", "8.8.4.4", "11.0.0.1", "192.169.0.1"];
  const text = priv.concat(pub).join(" ");
  assert.deepEqual(extract(text, { hidePrivate: true }).ipv4, pub);
  assert.equal(extract(text).ipv4.length, priv.length + pub.length);
});

test("file extensions, IPs and numeric TLDs are not domains", () => {
  const r = extract("run setup.exe lib.dll app.js index.php doc.pdf a.zip pic.png 1.2.3.4 10.0.0.256 v1.2.3 real-site.com");
  assert.deepEqual(r.domains, ["real-site.com"]);
});

test("defang/refang are reversible", () => {
  const inputs = [
    SAMPLE,
    "Contact HTTP://Example.COM/Path, ftp://files.example.net/a.bin and Bob@Mail.Example.org now.",
    "Sub http://a.example.com/x and a.example.com plus example.com and user@example.com."
  ];
  for (const x of inputs) {
    const d = defangText(x);
    assert.notEqual(d, refang(x), "defang should change the text");
    assert.equal(refang(d), refang(x));
  }
  assert.equal(defangValue("http://a.com/b", "urls"), "hxxp[://]a[.]com/b");
  assert.equal(defangValue("a@b.com", "emails"), "a[@]b[.]com");
  assert.equal(defangValue("1.2.3.4", "ipv4"), "1[.]2[.]3[.]4");
  assert.equal(defangValue("2001:db8::1", "ipv6"), "2001[:]db8[:][:]1");
});

test("defangText does not touch hashes or CVEs", () => {
  const h = "44d88612fea8a8f36de82e1278abb02f CVE-2021-44228";
  assert.equal(defangText(h), h);
});

test("no duplicates in any category", () => {
  const r = extract("a.com a.com A.COM http://a.com/x http://a.com/x 1.1.1.1 1.1.1.1 u@a.com U@A.COM " +
    "44d88612fea8a8f36de82e1278abb02f 44D88612FEA8A8F36DE82E1278ABB02F CVE-2021-1234 cve-2021-1234 ::1 ::1");
  for (const k of Object.keys(r)) assert.equal(new Set(r[k]).size, r[k].length, k);
  assert.deepEqual(r.domains, ["a.com"]);
  assert.deepEqual(r.emails, ["u@a.com"]);
});

test("trailing punctuation is trimmed from URLs", () => {
  const cases = {
    "see http://a.com/x." : "http://a.com/x",
    "(http://a.com/x)": "http://a.com/x",
    "http://a.com/x, next": "http://a.com/x",
    '"http://a.com/x";': "http://a.com/x",
    "http://a.com/x?!": "http://a.com/x",
    "http://en.wikipedia.org/wiki/A_(b)": "http://en.wikipedia.org/wiki/A_(b)",
    "[http://a.com/x]": "http://a.com/x"
  };
  for (const [src, want] of Object.entries(cases)) assert.deepEqual(extract(src).urls, [want], src);
});

test("hashes are not cut out of longer hex strings", () => {
  const long = "a".repeat(33);
  const r = extract(long + " " + "b".repeat(65) + " " + "c".repeat(41));
  assert.deepEqual([r.md5, r.sha1, r.sha256], [[], [], []]);
});

test("IPv6 validation is conservative", () => {
  const r = extract("time 12:30:45 mac aa:bb:cc:dd:ee:ff ok fe80::1 full 2001:0db8:0000:0000:0000:ff00:0042:8329 bad 1::2::3");
  assert.deepEqual(r.ipv6, ["fe80::1", "2001:0db8:0000:0000:0000:ff00:0042:8329"]);
});
