import { Suspense } from "react";
import type { Metadata } from "next";
import { PoliciesScreen } from "@/features/policies/policies-screen";

export const metadata: Metadata = { title: "Policies" };

// Thin route file: the screen lives in src/features/policies/ (see panel/ARCHITECTURE.md).
export default function Page() {
  return (
    <Suspense>
      <PoliciesScreen />
    </Suspense>
  );
}
