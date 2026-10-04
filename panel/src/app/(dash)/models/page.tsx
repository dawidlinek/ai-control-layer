import type { Metadata } from "next";
import { Suspense } from "react";
import { ModelsScreen } from "@/features/models/models-screen";

export const metadata: Metadata = { title: "Models & connectors" };

export default function Page() {
  return (
    <Suspense>
      <ModelsScreen />
    </Suspense>
  );
}
