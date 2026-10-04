import type { Metadata } from "next";
import { PlaceholderScreen } from "@/components/shell/placeholder-screen";

export const metadata: Metadata = { title: "Automation Insights" };

// Thin route file: the screen lives in src/features/insights/ (see panel/ARCHITECTURE.md).
export default function Page() {
  return <PlaceholderScreen title="Automation Insights" />;
}
