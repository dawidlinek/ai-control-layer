import * as React from "react";
import { NuqsTestingAdapter, type OnUrlUpdateFunction } from "nuqs/adapters/testing";

/**
 * `renderApp` mounts a nuqs testing adapter without memory, so URL updates do not re-render. Wrap a screen in
 * this to get a URL that remembers updates (tabs, `?sel=`, `?range=`) in interaction tests.
 * (Could be promoted to `renderApp({ urlMemory: true })` in src/test/render.tsx.)
 */
export function WithUrl({
  search,
  onUrlUpdate,
  children,
}: {
  search?: string;
  onUrlUpdate?: OnUrlUpdateFunction;
  children: React.ReactNode;
}) {
  return (
    <NuqsTestingAdapter hasMemory searchParams={search} onUrlUpdate={onUrlUpdate}>
      {children}
    </NuqsTestingAdapter>
  );
}
