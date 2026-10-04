import type { Metadata } from "next";
import { Suspense } from "react";
import { ThreatsScreen } from "@/features/threats/threats-screen";

export const metadata: Metadata = { title: "Known threats" };

export default function Page() {
  return (
    <Suspense>
      <ThreatsScreen />
    </Suspense>
  );
}
