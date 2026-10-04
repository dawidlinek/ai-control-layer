import { formatNumber } from "@/lib/format";

/**
 * "Showing the latest 200 of 340 incidents." Rendered under a list that was fetched with a limit when the server's
 * `X-Total-Count` says there are more rows than were loaded (tab counts then only cover the loaded rows). Renders nothing otherwise.
 */
export function LoadedOfTotal({ loaded, total, noun }: { loaded: number; total: number | undefined; noun: string }) {
  if (total === undefined || total <= loaded) return null;
  return (
    <p className="m-0 text-[12px] text-muted">
      Showing {formatNumber(loaded)} of {formatNumber(total)} {noun}. Counts cover the loaded ones.
    </p>
  );
}
