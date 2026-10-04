"use client";

import * as React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ApiError } from "@/lib/api/client";
import { ThemeProvider, type Theme } from "@/components/shell/theme";

/**
 * In mock mode (NEXT_PUBLIC_API_MOCKING=enabled) start the MSW service worker before the app renders,
 * so the very first request is already answered by the mock API. The literal `process.env` check lets the
 * bundler drop the whole mock layer from normal builds.
 */
function MswGate({ children }: { children: React.ReactNode }) {
  const mocking = process.env.NEXT_PUBLIC_API_MOCKING === "enabled";
  const [ready, setReady] = React.useState(!mocking);

  React.useEffect(() => {
    // Positive check wrapping the import: with the flag inlined as "" the bundler drops the block and the MSW chunk.
    if (process.env.NEXT_PUBLIC_API_MOCKING === "enabled") {
      let cancelled = false;
      void import("@/mocks/browser")
        .then(({ worker }) =>
          worker.start({ onUnhandledRequest: "bypass", quiet: true, serviceWorker: { url: "/mockServiceWorker.js" } }),
        )
        .catch((error: unknown) => {
          // e.g. a browser without service workers: render anyway, requests will fail visibly instead of hanging.
          console.error("[rogatka] could not start the mock API", error);
        })
        .then(() => {
          if (!cancelled) setReady(true);
        });
      return () => {
        cancelled = true;
      };
    }
  }, []);

  if (!ready) return <div role="status" data-msw-starting className="p-6 text-muted">Starting the mock API…</div>;
  return <>{children}</>;
}

/**
 * Retry policy for queries: transient failures (network, 5xx) retry twice; client errors (403/404 are answers, not
 * glitches) and 501 ("not implemented in this gateway") never retry.
 */
export function shouldRetry(count: number, error: unknown): boolean {
  if (error instanceof ApiError && ((error.status >= 400 && error.status < 500) || error.status === 501)) return false;
  return count < 2;
}

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: false,
        retry: shouldRetry,
      },
    },
  });
}

export function Providers({ theme, children }: { theme: Theme; children: React.ReactNode }) {
  const [client] = React.useState(makeQueryClient);
  return (
    <ThemeProvider initial={theme}>
      <MswGate>
        <QueryClientProvider client={client}>
          <NuqsAdapter>
            <TooltipProvider delayDuration={300}>{children}</TooltipProvider>
          </NuqsAdapter>
        </QueryClientProvider>
      </MswGate>
    </ThemeProvider>
  );
}
