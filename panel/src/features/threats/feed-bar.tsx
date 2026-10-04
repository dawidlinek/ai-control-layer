"use client";

import type * as React from "react";
import { ErrorState, ICON_PATHS, LoadingRows, PathIcon, RelativeTime, StatusBox } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { useHasRole } from "@/lib/auth/user-context";
import { formatNumber } from "@/lib/format";
import { useFeedStatus, useSyncFeed } from "./api";

/** The feed's poll interval (concept / HANDOFF 7.5); not part of `FeedStatus`. */
const POLL = "every 30 s";

function hostOf(url: string | null): string {
  if (!url) return "not configured";
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function Item({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col">
      <dt className="text-[11px] text-muted">{label}</dt>
      <dd className="m-0">{children}</dd>
    </div>
  );
}

export function FeedBar() {
  const feed = useFeedStatus();
  const sync = useSyncFeed();
  const isAdmin = useHasRole("admin");
  if (feed.isPending) return <LoadingRows rows={1} />;
  if (feed.isError) return <ErrorState title="Could not load the feed status" error={feed.error} onRetry={() => void feed.refetch()} />;
  const f = feed.data;

  return (
    <div className="flex flex-col gap-2">
      <section aria-label="Signature feed" className="flex flex-wrap items-center gap-x-[22px] gap-y-2.5 rounded-[8px] border border-border bg-surface px-4 py-3 text-[13px]">
        <dl className="m-0 flex flex-wrap items-center gap-x-[22px] gap-y-2.5">
          <Item label="Signature feed">
            <span className="font-mono">
              {f.bundle_version != null ? `bundle ${f.bundle_version}` : "no bundle"} · {formatNumber(f.entries)} rules
            </span>
          </Item>
          <Item label="Checksum">
            {f.verified ? (
              <span className="inline-flex items-center gap-1 text-dec-allow">
                <PathIcon path={ICON_PATHS.check} size={12} strokeWidth={2.4} />
                verified
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-dec-block">
                <PathIcon path={ICON_PATHS.error} size={12} strokeWidth={2.4} />
                not verified
              </span>
            )}
          </Item>
          <Item label="Last sync">{f.last_sync_at ? <RelativeTime iso={f.last_sync_at} /> : "never"}</Item>
          <Item label="Source">
            <span className="font-mono">
              {hostOf(f.source_url)} · {POLL}
            </span>
          </Item>
        </dl>
        <div className="flex-1" />
        <Button
          disabled={!isAdmin || sync.isPending}
          title={isAdmin ? undefined : "Only admins can sync the feed"}
          onClick={() => sync.mutate()}
        >
          {sync.isPending ? "Syncing…" : "Sync now"}
        </Button>
      </section>
      {f.last_error && (
        <StatusBox variant="warning" title="The last sync failed">
          Rogatka keeps using the last good bundle. {f.last_error}
        </StatusBox>
      )}
      {sync.isSuccess && (
        <StatusBox variant="success" title="Feed synced">
          Bundle {sync.data.bundle_version ?? "—"} is active · {formatNumber(sync.data.entries)} rules · checksum{" "}
          {sync.data.verified ? "verified" : "not verified"}. New rules apply to the next request.
        </StatusBox>
      )}
      {sync.isError && (
        <StatusBox variant="error" title="Could not sync the feed">
          {sync.error.message}
        </StatusBox>
      )}
    </div>
  );
}
