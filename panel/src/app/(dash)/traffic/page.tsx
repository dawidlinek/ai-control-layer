import type { Metadata } from "next";
import { Suspense } from "react";
import { TrafficScreen } from "@/features/traffic/traffic-screen";

export const metadata: Metadata = { title: "Traffic" };

export default function Page() {
  return (
    <Suspense>
      <TrafficScreen />
    </Suspense>
  );
}
