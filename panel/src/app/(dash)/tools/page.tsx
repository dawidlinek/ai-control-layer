import type { Metadata } from "next";
import { PlaceholderScreen } from "@/components/shell/placeholder-screen";

export const metadata: Metadata = { title: "Tools & MCP" };

// Thin route file: the screen lives in src/features/tools/ (see panel/ARCHITECTURE.md).
export default function Page() {
  return <PlaceholderScreen title="Tools & MCP" />;
}
