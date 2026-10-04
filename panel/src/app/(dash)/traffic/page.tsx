import type { Metadata } from "next";
import { PlaceholderScreen } from "@/components/shell/placeholder-screen";

export const metadata: Metadata = { title: "Traffic" };

// Thin route file: the screen lives in src/features/traffic/ (see panel/ARCHITECTURE.md).
export default function Page() {
  return <PlaceholderScreen title="Traffic" />;
}
