import type { Metadata } from "next";
import { PlaceholderScreen } from "@/components/shell/placeholder-screen";

export const metadata: Metadata = { title: "Models & connectors" };

// Thin route file: the screen lives in src/features/models/ (see panel/ARCHITECTURE.md).
export default function Page() {
  return <PlaceholderScreen title="Models & connectors" />;
}
