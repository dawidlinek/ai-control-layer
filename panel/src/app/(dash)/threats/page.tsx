import type { Metadata } from "next";
import { PlaceholderScreen } from "@/components/shell/placeholder-screen";

export const metadata: Metadata = { title: "Known threats" };

// Thin route file: the screen lives in src/features/threats/ (see panel/ARCHITECTURE.md).
export default function Page() {
  return <PlaceholderScreen title="Known threats" />;
}
