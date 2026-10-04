import type { Metadata } from "next";
import { Suspense } from "react";
import { InsightsScreen } from "@/features/insights";

export const metadata: Metadata = { title: "Automation Insights" };

export default function Page() {
  return (
    <Suspense>
      <InsightsScreen />
    </Suspense>
  );
}
