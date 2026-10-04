import type { Metadata } from "next";
import { PlaceholderScreen } from "@/components/shell/placeholder-screen";

export const metadata: Metadata = { title: "Budgets & spend" };

// Thin route file: the screen lives in src/features/budgets/ (see panel/ARCHITECTURE.md).
export default function Page() {
  return <PlaceholderScreen title="Budgets & spend" />;
}
