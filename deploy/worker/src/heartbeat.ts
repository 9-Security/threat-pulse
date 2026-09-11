/**
 * Decides whether the collector has stopped collecting.
 *
 * Every alert the project had before this one is sent by the host that is
 * failing: the systemd `OnFailure=` unit, the corpus-stall mail, the
 * source-health mail. All three need the host to be alive and its network to
 * work. A host that is powered off, wedged, or cut off sends nothing, and the
 * absence of mail is indistinguishable from a quiet week.
 *
 * So this runs on Cloudflare instead, on a cron trigger, and asks D1 what the
 * newest report is. It deliberately checks the corpus rather than accepting a
 * ping: a ping proves a timer fired, while a row proves the day was collected,
 * enriched and pushed. Those come apart -- a host can boot, run, collect
 * nothing, and ping happily.
 *
 * Kept free of imports and of Worker types so it can be run under plain node
 * for tests; index.ts holds everything that touches D1 or the network.
 */

/** `report_date` is a plain YYYY-MM-DD key in the reports table. */
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

export interface HeartbeatState {
  /** MAX(report_date) in D1, or null when the table is empty. */
  newest: string | null;
  /** COUNT(*) of report rows, for the operator to see at a glance. */
  totalDays: number;
}

export type HeartbeatVerdict =
  | { stale: false; reason: "current"; newest: string; daysBehind: 0 }
  | { stale: true; reason: "behind"; newest: string; daysBehind: number }
  | { stale: true; reason: "empty"; newest: null; daysBehind: number }
  | { stale: true; reason: "unreadable"; newest: string | null; daysBehind: number };

/**
 * Today's date in Asia/Taipei, which is the timezone the report is keyed on.
 *
 * The run is scheduled at 06:00 Taipei and cannot exceed its 3h unit timeout,
 * so by the noon check a healthy corpus holds today's date. Using UTC here
 * would put the boundary in the middle of the Taipei working day and make the
 * verdict depend on when the cron happened to fire.
 */
export function taipeiDate(now: Date): string {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "Asia/Taipei",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(now);
  const get = (type: string) => parts.find((part) => part.type === type)?.value ?? "";
  return `${get("year")}-${get("month")}-${get("day")}`;
}

/** Whole days from `from` to `to`, both YYYY-MM-DD. Negative if `to` is earlier. */
export function daysBetween(from: string, to: string): number {
  const parse = (value: string) => {
    const [y, m, d] = value.split("-").map(Number);
    return Date.UTC(y, m - 1, d);
  };
  return Math.round((parse(to) - parse(from)) / 86_400_000);
}

/**
 * A corpus that has not gained today's report is a collector that is not
 * collecting. One day behind is already the alarm: feeds carry only their most
 * recent items, so a day missed today cannot be collected tomorrow, and waiting
 * for a second day of silence to be sure costs a second day permanently.
 */
export function assess(state: HeartbeatState, today: string): HeartbeatVerdict {
  if (state.newest === null) {
    return { stale: true, reason: "empty", newest: null, daysBehind: 0 };
  }
  if (!DATE_RE.test(state.newest)) {
    // Something wrote a shape nothing else here produces. Say so rather than
    // computing a difference against it, which would silently yield NaN and
    // compare false -- reporting a healthy corpus on the strength of a value
    // that could not be read.
    return { stale: true, reason: "unreadable", newest: state.newest, daysBehind: 0 };
  }
  const behind = daysBetween(state.newest, today);
  if (behind <= 0) {
    // Zero is today's report. A negative means D1 holds a date in the future,
    // which is a clock or a hand-loaded row, not a stalled collector -- and not
    // something a staleness alarm should claim to have found.
    return { stale: false, reason: "current", newest: state.newest, daysBehind: 0 };
  }
  return { stale: true, reason: "behind", newest: state.newest, daysBehind: behind };
}

export interface HeartbeatMail {
  subject: string;
  body: string;
}

export function renderHeartbeat(verdict: HeartbeatVerdict, state: HeartbeatState, today: string): HeartbeatMail | null {
  if (!verdict.stale) return null;

  const lines: string[] = [];
  let subject: string;

  if (verdict.reason === "empty") {
    subject = "[threat-pulse] the corpus is empty";
    lines.push("D1 holds no reports at all.");
  } else if (verdict.reason === "unreadable") {
    subject = "[threat-pulse] the newest report date cannot be read";
    lines.push(`The newest report_date in D1 is ${JSON.stringify(verdict.newest)},`);
    lines.push("which is not a YYYY-MM-DD key. Something wrote a row this project did not.");
  } else {
    const plural = verdict.daysBehind === 1 ? "day" : "days";
    subject = `[threat-pulse] no report for ${verdict.daysBehind} ${plural}`;
    lines.push(`The newest report in D1 is ${verdict.newest}; today in Taipei is ${today}.`);
    lines.push(`The corpus is ${verdict.daysBehind} ${plural} behind and holds ${state.totalDays} in total.`);
  }

  lines.push("");
  lines.push("This check runs on Cloudflare, not on the collecting host, because every");
  lines.push("other alert this project sends needs that host to be alive to send it.");
  lines.push("Nothing here can say why -- only that the day did not arrive.");
  lines.push("");
  lines.push("On the host:");
  lines.push("  systemctl status threat-pulse-daily.timer threat-pulse-daily.service");
  lines.push("  journalctl -u threat-pulse-daily.service -n 200 --no-pager");
  lines.push("");
  lines.push("A missed day cannot be collected later: the feeds carry only their most");
  lines.push("recent items, so the window closes for good. This repeats every day until");
  lines.push("a report arrives.");

  return { subject, body: lines.join("\n") };
}
