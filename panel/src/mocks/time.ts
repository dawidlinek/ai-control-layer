/**
 * Demo time helpers. Fixtures are relative to "now" (when the page loads), so "today", "2 m" and
 * countdowns always look right. The prototypes were drawn at 14:05 on the demo day; `demoClock("14:03:12")`
 * gives the instant that was 1 min 48 s before "now" - i.e. the prototype's relative spacing is preserved.
 */

/** The wall-clock time at which the prototypes were drawn. */
export const DEMO_NOW_CLOCK = "14:05:00";

const SEC = 1000;
const MIN = 60 * SEC;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

export const now = () => Date.now();

const iso = (ms: number) => new Date(ms).toISOString();

export const secondsAgo = (n: number) => iso(now() - n * SEC);
export const minutesAgo = (n: number) => iso(now() - n * MIN);
export const hoursAgo = (n: number) => iso(now() - n * HOUR);
export const daysAgo = (n: number) => iso(now() - n * DAY);
export const inSeconds = (n: number) => iso(now() + n * SEC);
export const inMinutes = (n: number) => iso(now() + n * MIN);
export const inHours = (n: number) => iso(now() + n * HOUR);
export const inDays = (n: number) => iso(now() + n * DAY);

function toSeconds(clock: string): number {
  const [h = 0, m = 0, s = 0] = clock.split(":").map(Number);
  return h * 3600 + m * 60 + s;
}

/**
 * Instant matching a prototype clock time, shifted so that the prototype's "now" (14:05:00) is the real now.
 * `demoClock("14:03:12")` = 1 min 48 s ago; `demoClock("13:20:02")` = 44 min 58 s ago.
 * Times later than the prototype's now (e.g. "14:10") are in the future.
 */
export function demoClock(clock: string): string {
  return iso(now() - (toSeconds(DEMO_NOW_CLOCK) - toSeconds(clock)) * SEC);
}

/** Yesterday at a given clock time, relative to now (approximate: 24 h before `demoClock`). */
export function demoClockYesterday(clock: string): string {
  return iso(new Date(demoClock(clock)).getTime() - DAY);
}
