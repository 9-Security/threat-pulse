/**
 * Run with: npm test  (node's own runner, stripping types -- no dependency)
 */
import assert from "node:assert/strict";
import test from "node:test";

import { assess, daysBetween, renderHeartbeat, taipeiDate } from "./heartbeat.ts";

test("today's report is not stale", () => {
  const verdict = assess({ newest: "2026-09-11", totalDays: 8 }, "2026-09-11");

  assert.equal(verdict.stale, false);
  assert.equal(verdict.reason, "current");
  assert.equal(renderHeartbeat(verdict, { newest: "2026-09-11", totalDays: 8 }, "2026-09-11"), null);
});

test("one day behind already alarms", () => {
  // Waiting for a second day to be sure costs a second day permanently: feeds
  // carry only their most recent items, so a missed window does not reopen.
  const verdict = assess({ newest: "2026-09-10", totalDays: 8 }, "2026-09-11");

  assert.equal(verdict.stale, true);
  assert.equal(verdict.daysBehind, 1);
});

test("a date in the future is not a stalled collector", () => {
  // A clock problem or a hand-loaded row. Real, but not what this alarm found,
  // and reporting it as a stall would send the operator to the wrong place.
  const verdict = assess({ newest: "2026-09-12", totalDays: 8 }, "2026-09-11");

  assert.equal(verdict.stale, false);
});

test("an unparseable date is reported, not silently treated as current", () => {
  // The bug this guards: a difference computed against a non-date yields NaN,
  // and `NaN <= 0` is false in one direction and true in none -- easy to write
  // a comparison that calls a broken corpus healthy.
  const verdict = assess({ newest: "not-a-date", totalDays: 8 }, "2026-09-11");

  assert.equal(verdict.stale, true);
  assert.equal(verdict.reason, "unreadable");
});

test("an empty corpus is its own message", () => {
  const state = { newest: null, totalDays: 0 };
  const mail = renderHeartbeat(assess(state, "2026-09-11"), state, "2026-09-11");

  assert.ok(mail);
  assert.match(mail.subject, /corpus is empty/);
});

test("the alert names the gap, the dates and where to look", () => {
  const state = { newest: "2026-09-08", totalDays: 8 };
  const mail = renderHeartbeat(assess(state, "2026-09-11"), state, "2026-09-11");

  assert.ok(mail);
  assert.equal(mail.subject, "[threat-pulse] no report for 3 days");
  assert.match(mail.body, /newest report in D1 is 2026-09-08/);
  assert.match(mail.body, /today in Taipei is 2026-09-11/);
  assert.match(mail.body, /journalctl -u threat-pulse-daily/);
  // It must not be read as a diagnosis it cannot make.
  assert.match(mail.body, /only that the day did not arrive/);
});

test("one day reads as a day, not days", () => {
  const state = { newest: "2026-09-10", totalDays: 8 };
  const mail = renderHeartbeat(assess(state, "2026-09-11"), state, "2026-09-11");

  assert.ok(mail);
  assert.equal(mail.subject, "[threat-pulse] no report for 1 day");
});

test("days are counted across a month boundary", () => {
  assert.equal(daysBetween("2026-08-31", "2026-09-01"), 1);
  assert.equal(daysBetween("2026-09-01", "2026-08-31"), -1);
  assert.equal(daysBetween("2026-02-28", "2026-03-01"), 1); // 2026 is not a leap year
  assert.equal(daysBetween("2026-09-11", "2026-09-11"), 0);
});

test("the Taipei date is the local one, not UTC", () => {
  // 2026-09-11T20:00Z is already the 12th in Taipei (UTC+8). Keying on UTC
  // would put the day boundary inside the Taipei working day and make the
  // verdict depend on when the cron fired.
  assert.equal(taipeiDate(new Date("2026-09-11T20:00:00Z")), "2026-09-12");
  assert.equal(taipeiDate(new Date("2026-09-11T04:00:00Z")), "2026-09-11");
  // Midnight Taipei is 16:00Z the previous day.
  assert.equal(taipeiDate(new Date("2026-09-11T16:00:00Z")), "2026-09-12");
  assert.equal(taipeiDate(new Date("2026-09-11T15:59:59Z")), "2026-09-11");
});
