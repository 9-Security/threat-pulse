/**
 * Run with: npm test  (node's own runner, stripping types -- no dependency)
 */
import assert from "node:assert/strict";
import test from "node:test";

import { classify, classifySearchText, MAX_BATCH, MAX_LABELS, MAX_VALUE_LENGTH, partition } from "./guard.ts";

const cases = (label: string, expected: string | null, values: string[]) =>
  test(`${label} -> ${expected ?? "looked up"}`, () => {
    for (const value of values) {
      assert.equal(classify(value), expected, value);
    }
  });

cases("non-global IPv4", "non_public_ip", [
  "0.1.2.3",
  "10.1.2.3",
  "100.64.0.1",
  "100.127.255.255",
  "127.0.0.1",
  "169.254.1.1",
  "172.16.0.1",
  "172.31.255.255",
  "192.0.0.1",
  "192.0.2.5",
  "192.168.1.1",
  "198.18.0.1",
  "198.19.255.255",
  "198.51.100.7",
  "203.0.113.9",
  "240.0.0.1",
  "255.255.255.255",
]);

cases("global IPv4, including the edges of each range", null, [
  "8.8.8.8",
  "1.1.1.1",
  "104.21.5.10",
  "100.63.255.255",
  "100.128.0.0",
  "172.15.255.255",
  "172.32.0.0",
  "192.0.0.9",
  "192.0.0.10",
  "198.17.255.255",
  "198.20.0.0",
  "224.0.0.251",
]);

cases("malformed dotted quads", "invalid_value", ["256.1.1.1", "010.1.1.1"]);

cases("non-global IPv6", "non_public_ip", [
  "::1",
  "::",
  "fe80::1",
  "fe80::1%eth0",
  "fc00::1",
  "fd12:3456::1",
  "2001:db8::1",
  "2002::1",
  "2001::1",
  "100::1",
  "64:ff9b:1::1",
  "::ffff:10.0.0.1",
  "::ffff:192.168.1.1",
]);

cases("global IPv6", null, [
  "2606:4700:4700::1111",
  "2001:4860:4860::8888",
  "::ffff:8.8.8.8",
  "2001:20::1",
  "64:ff9b::808:808",
  "ff02::1",
]);

cases("internal hostnames", "internal_hostname", [
  "dc01",
  "fileserver.corp",
  "a.b.local",
  "printer.home.arpa",
  "x.localdomain",
  "wiki.intranet",
  "build.internal",
  "nas.lan",
  "DC01.CORP.",
  "dc01:3389",
]);

cases("public hostnames", null, ["evil.example.com", "evil.com.", "EVIL.COM", "evil.com:8080", "tenant.github.io"]);

cases("URLs pointing inside", "non_public_ip", ["http://10.0.0.5/admin", "https://[fd00::1]:8443/", "http://10.0.0.1:22"]);
cases("URLs with internal hosts", "internal_hostname", ["https://intranet.corp/x", "http://dc01/share"]);
cases("URLs carrying credentials", "sensitive_url", ["https://user:pass@evil.com/x", "ftp://admin@evil.com/"]);
cases("public URLs", null, ["https://evil.com/path?q=1", "hxxp-not-a-scheme.evil.com"]);
cases("unparseable URLs", "invalid_value", ["http://[bad", "http://"]);

cases("hashes and CVEs are looked up as they are", null, [
  "d41d8cd98f00b204e9800998ecf8427e",
  "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "CVE-2026-1234",
  "cve-2026-123456",
]);

cases("values that cannot be a single observable", "invalid_value", [
  "evil .com",
  "evil.com\nsecond-line",
  "a".repeat(MAX_VALUE_LENGTH + 1),
]);

test("an empty value is its own reason", () => {
  assert.equal(classify(""), "empty_value");
});

test("nothing is dropped: past the limit every value is returned as skipped", () => {
  const values = Array.from({ length: MAX_BATCH + 5 }, (_, i) => `host${i}.example.com`);

  const result = partition(values);

  assert.equal(result.requested, MAX_BATCH + 5);
  assert.equal(result.truncated, true);
  assert.equal(result.accepted.length, MAX_BATCH);
  const overLimit = result.skipped.filter((s) => s.reason === "request_limit");
  assert.deepEqual(
    overLimit.map((s) => s.input_index),
    [100, 101, 102, 103, 104],
  );
  assert.equal(result.accepted.length + result.skipped.length, values.length);
});

test("every position appears exactly once, duplicates included", () => {
  const result = partition(["evil.com", "10.0.0.1", "evil.com", 42, "  CVE-2026-1234  ", ""]);

  const indexes = [...result.accepted, ...result.skipped].map((x) => x.input_index).sort((a, b) => a - b);
  assert.deepEqual(indexes, [0, 1, 2, 3, 4, 5]);
  assert.deepEqual(
    result.accepted.map((a) => [a.input_index, a.value]),
    [
      [0, "evil.com"],
      [2, "evil.com"],
      [4, "CVE-2026-1234"],
    ],
  );
  const reasons = Object.fromEntries(result.skipped.map((s) => [s.input_index, s.reason]));
  assert.deepEqual(reasons, { 1: "non_public_ip", 3: "invalid_value", 5: "empty_value" });
  assert.equal(result.truncated, false);
});

test("a skipped value past the limit reports the limit, not its own classification", () => {
  const values = [...Array.from({ length: MAX_BATCH }, () => "evil.com"), "10.0.0.1"];

  const result = partition(values);

  assert.deepEqual(result.skipped, [{ input_index: MAX_BATCH, value: "10.0.0.1", reason: "request_limit" }]);
});

test("a request that is not a list is an empty request, not an error", () => {
  const result = partition("evil.com");

  assert.equal(result.requested, 0);
  assert.equal(result.accepted.length, 0);
});

test("values with hyphens are looked up -- CVEs and most real domains have them", () => {
  for (const value of ["CVE-2026-1234", "m-doxa-apodo.duckdns.org", "a-b.example.co.uk", "https://x-y.example.com/a-b"]) {
    assert.equal(classify(value), null, value);
  }
});

test("free-text search refuses addresses and internal names, not words", () => {
  const expected: Array<[string, string | null]> = [
    ["ransomware", null],
    ["cobalt strike", null],
    ["dc01", null],
    ["evil.com", null],
    ["8.8.8.8", null],
    ["CVE-2026-1234", null],
    ["10.0.0.5", "non_public_ip"],
    ["fd00::1", "non_public_ip"],
    ["[fe80::1]", "non_public_ip"],
    ["dc01.corp", "internal_hostname"],
    ["https://user:pw@evil.com/", "sensitive_url"],
    ["http://intranet.corp/x", "internal_hostname"],
  ];
  for (const [text, reason] of expected) {
    assert.equal(classifySearchText(text), reason, text);
  }
});

test("a hostname past the label limit is refused, one at the limit is looked up", () => {
  const atLimit = Array.from({ length: MAX_LABELS - 1 }, (_, i) => `l${i}`).join(".") + ".com";
  const overLimit = "x." + atLimit;
  assert.equal(atLimit.split(".").length, MAX_LABELS);
  assert.equal(classify(atLimit), null);
  assert.equal(classify(overLimit), "invalid_value");
  assert.equal(classify(`https://${overLimit}/path`), "invalid_value");
});

test("the label limit counts the whole value, so a dotted URL path cannot slip past it", () => {
  const dottedPath = Array.from({ length: MAX_LABELS + 4 }, (_, i) => `p${i}`).join(".");
  assert.equal(classify(`https://evil.com/${dottedPath}`), "invalid_value");
  assert.equal(classify("https://evil.com/path/file.tar.gz"), null);
});
