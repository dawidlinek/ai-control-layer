/** Formatting helpers. All times are shown in the browser's local time zone, 24 h, mono-friendly. */

type DateInput = string | number | Date;

function toDate(v: DateInput): Date {
  return v instanceof Date ? v : new Date(v);
}

const pad = (n: number) => String(n).padStart(2, "0");

/** `14:03:12` */
export function formatTime(v: DateInput): string {
  const d = toDate(v);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** `14:03` */
export function formatClock(v: DateInput): string {
  const d = toDate(v);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function dayStart(d: Date): number {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

/** `today`, `yesterday`, or `1 Oct`. */
export function formatDay(v: DateInput, now: DateInput = Date.now()): string {
  const d = toDate(v);
  const diffDays = Math.round((dayStart(toDate(now)) - dayStart(d)) / 86_400_000);
  if (diffDays === 0) return "today";
  if (diffDays === 1) return "yesterday";
  return `${d.getDate()} ${MONTHS[d.getMonth()]}`;
}

/** `today 14:03`, `yesterday 16:40`, `1 Oct 10:12`. */
export function formatWhen(v: DateInput, now: DateInput = Date.now()): string {
  return `${formatDay(v, now)} ${formatClock(v)}`;
}

/** Compact age: `now`, `2 m`, `38 m`, `1 h`, `3 d`. */
export function formatAge(v: DateInput, now: DateInput = Date.now()): string {
  const s = Math.max(0, Math.round((toDate(now).getTime() - toDate(v).getTime()) / 1000));
  if (s < 45) return "now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} m`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h`;
  return `${Math.round(h / 24)} d`;
}

/** Countdown `9:40` for time left; `0:00` once passed. */
export function formatCountdown(until: DateInput, now: DateInput = Date.now()): string {
  const s = Math.max(0, Math.round((toDate(until).getTime() - toDate(now).getTime()) / 1000));
  return `${Math.floor(s / 60)}:${pad(s % 60)}`;
}

/** `1 284` (narrow no-break space as thousands separator, as in the prototypes). */
export function formatNumber(n: number): string {
  const [int, frac] = String(Math.round(n * 100) / 100).split(".");
  const grouped = int.replace(/\B(?=(\d{3})+(?!\d))/g, " ");
  return frac ? `${grouped}.${frac}` : grouped;
}

/** `3.12` for USD amounts (the unit is written next to it in the UI: "3.12 / 5.00 USD today"). */
export function formatUsd(n: number): string {
  return n.toFixed(2);
}

/** `0.31`. */
export function formatScore(n: number): string {
  return n.toFixed(2);
}
