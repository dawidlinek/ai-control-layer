import { formatClock, formatDay } from "@/lib/format";

/** `1.2M`, `310k`, `840` (prototype style for token counts). */
export function compactNumber(n: number): string {
  if (n >= 1_000_000) return `${(Math.round(n / 100_000) / 10).toString()}M`;
  if (n >= 1_000) return `${Math.round(n / 1_000)}k`;
  return String(n);
}

/** `1.2M / 310k` */
export const tokensInOut = (tin: number, tout: number) => `${compactNumber(tin)} / ${compactNumber(tout)}`;

/** Last active: `now`, `14:02` today, `yesterday`, `1 Oct`, `—`. */
export function lastActiveLabel(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (now - t < 60_000) return "now";
  const day = formatDay(t, now);
  return day === "today" ? formatClock(t) : day;
}

/** First name for sentences ("Give Jan access to ..."). */
export const firstName = (name: string) => name.split(/\s+/)[0] ?? name;
