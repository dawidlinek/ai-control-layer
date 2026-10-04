import { Suspense } from "react";
import type { Metadata } from "next";
import { IncidentsScreen } from "@/features/incidents/incidents-screen";

export const metadata: Metadata = { title: "Incidents" };

export default function Page() {
  return (
    <Suspense>
      <IncidentsScreen />
    </Suspense>
  );
}
