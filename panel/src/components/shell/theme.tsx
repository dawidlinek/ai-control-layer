"use client";

import * as React from "react";

import { THEME_COOKIE, type Theme } from "@/lib/theme";

export { THEME_COOKIE, parseTheme, type Theme } from "@/lib/theme";

interface ThemeCtx {
  theme: Theme;
  setTheme: (t: Theme) => void;
}

const ThemeContext = React.createContext<ThemeCtx | null>(null);

/**
 * Dark / light theme. The server renders `<html data-theme>` from the `rogatka-theme` cookie, so there is no
 * flash on reload; switching sets the attribute and the cookie (1 year, same-site).
 */
export function ThemeProvider({ initial, children }: { initial: Theme; children: React.ReactNode }) {
  const [theme, setThemeState] = React.useState<Theme>(initial);
  const setTheme = React.useCallback((t: Theme) => {
    setThemeState(t);
    document.documentElement.dataset.theme = t;
    document.cookie = `${THEME_COOKIE}=${t}; path=/; max-age=31536000; samesite=lax`;
  }, []);
  const value = React.useMemo(() => ({ theme, setTheme }), [theme, setTheme]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeCtx {
  const ctx = React.useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used inside <ThemeProvider>");
  return ctx;
}
