import type { Metadata } from "next";
import { Suspense } from "react";
import { GrantsScreen } from "@/features/grants/grants-screen";

export const metadata: Metadata = { title: "Grants" };

export default function Page() {
  return (
    <Suspense>
      <GrantsScreen />
    </Suspense>
  );
}
