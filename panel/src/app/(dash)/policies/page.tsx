import type { Metadata } from "next";
import { PlaceholderScreen } from "@/components/shell/placeholder-screen";

export const metadata: Metadata = { title: "Policies" };

// Thin route file: the screen lives in src/features/policies/ (see panel/ARCHITECTURE.md).
export default function Page() {
  return <PlaceholderScreen title="Policies" />;
}
