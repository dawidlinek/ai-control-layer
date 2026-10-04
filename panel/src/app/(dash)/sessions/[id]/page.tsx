import type { Metadata } from "next";
import { PlaceholderScreen } from "@/components/shell/placeholder-screen";

export const metadata: Metadata = { title: "Session" };

// Thin route file: the screen lives in src/features/sessions/ (owned by the Traffic screen agent).
export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <PlaceholderScreen title={`Session ${id}`} />;
}
