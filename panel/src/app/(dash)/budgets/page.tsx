import type { Metadata } from "next";
import { Suspense } from "react";
import { BudgetsScreen } from "@/features/budgets";

export const metadata: Metadata = { title: "Budgets & spend" };

export default function Page() {
  return (
    <Suspense>
      <BudgetsScreen />
    </Suspense>
  );
}
