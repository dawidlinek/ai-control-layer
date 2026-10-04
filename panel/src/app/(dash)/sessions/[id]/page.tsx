import type { Metadata } from "next";
import { Suspense } from "react";
import { SessionScreen } from "@/features/sessions/session-screen";

export const metadata: Metadata = { title: "Session" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let sessionId = id;
  try {
    sessionId = decodeURIComponent(id);
  } catch {
    /* keep the raw segment */
  }
  return (
    <Suspense>
      <SessionScreen id={sessionId} />
    </Suspense>
  );
}
