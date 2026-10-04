import { Suspense } from "react";
import type { Metadata } from "next";
import { ApprovalsScreen } from "@/features/approvals/approvals-screen";

export const metadata: Metadata = { title: "Approvals" };

export default function Page() {
  return (
    <Suspense>
      <ApprovalsScreen />
    </Suspense>
  );
}
