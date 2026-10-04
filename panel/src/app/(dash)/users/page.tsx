import type { Metadata } from "next";
import { PlaceholderScreen } from "@/components/shell/placeholder-screen";

export const metadata: Metadata = { title: "Users & groups" };

// Thin route file: the screen lives in src/features/users/ (see panel/ARCHITECTURE.md).
export default function Page() {
  return <PlaceholderScreen title="Users & groups" />;
}
