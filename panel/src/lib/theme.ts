/** Theme constants shared by server and client code (no "use client" here: the root layout reads the cookie). */
export type Theme = "dark" | "light";
export const THEME_COOKIE = "rogatka-theme";

export function parseTheme(value: string | undefined | null): Theme {
  return value === "light" ? "light" : "dark";
}
