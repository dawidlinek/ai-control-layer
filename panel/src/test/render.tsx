import * as React from "react";
import { render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { NuqsTestingAdapter, type OnUrlUpdateFunction } from "nuqs/adapters/testing";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider, type Theme } from "@/components/shell/theme";
import { UserProvider } from "@/lib/auth/user-context";
import { DEV_USER, type PanelUser } from "@/lib/auth/user";
import { setPathname } from "./router";

export interface RenderOptions {
  user?: PanelUser;
  devMode?: boolean;
  theme?: Theme;
  /** Initial query string, e.g. `?sel=tr_8f3a2c`. */
  searchParams?: string;
  pathname?: string;
  /**
   * Make the in-memory URL remember updates, so filters, tabs, `?sel=` and `?page=` written by the screen are read back
   * and re-render it. Off by default (updates are only reported to `onUrlUpdate`).
   */
  urlMemory?: boolean;
  onUrlUpdate?: OnUrlUpdateFunction;
}

/**
 * Render with every provider a screen needs: TanStack Query (no retries), nuqs (in-memory URL),
 * theme, user (demo admin by default) and tooltips. Returns a `user` from user-event.
 */
export function renderApp(ui: React.ReactElement, opts: RenderOptions = {}) {
  setPathname(opts.pathname ?? "/");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <ThemeProvider initial={opts.theme ?? "light"}>
        <QueryClientProvider client={client}>
          <NuqsTestingAdapter hasMemory={opts.urlMemory} searchParams={opts.searchParams} onUrlUpdate={opts.onUrlUpdate}>
            <UserProvider user={opts.user ?? DEV_USER} devMode={opts.devMode}>
              <TooltipProvider>{children}</TooltipProvider>
            </UserProvider>
          </NuqsTestingAdapter>
        </QueryClientProvider>
      </ThemeProvider>
    );
  }
  return { ...render(ui, { wrapper: Wrapper }), client, user: userEvent.setup() };
}
