import type { Metadata, Viewport } from "next";
import { cookies } from "next/headers";
import { IBM_Plex_Mono, Instrument_Sans } from "next/font/google";
import { Providers } from "@/components/providers";
import { THEME_COOKIE, parseTheme } from "@/lib/theme";
import "./globals.css";

const instrumentSans = Instrument_Sans({
  subsets: ["latin", "latin-ext"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-instrument-sans",
  display: "swap",
});
const plexMono = IBM_Plex_Mono({
  subsets: ["latin", "latin-ext"],
  weight: ["400", "500"],
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: "Rogatka Dashboard", template: "%s — Rogatka Dashboard" },
  description: "Admin panel of Rogatka, the company AI gateway.",
};

export const viewport: Viewport = { themeColor: "#ffffff", width: "device-width", initialScale: 1 };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Theme comes from a cookie so the server renders the right colours: no flash on reload.
  const theme = parseTheme((await cookies()).get(THEME_COOKIE)?.value);
  return (
    <html lang="en" data-theme={theme} className={`${instrumentSans.variable} ${plexMono.variable}`} suppressHydrationWarning>
      <body>
        <Providers theme={theme}>{children}</Providers>
      </body>
    </html>
  );
}
