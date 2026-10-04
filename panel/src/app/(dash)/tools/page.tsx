import type { Metadata } from "next";
import { Suspense } from "react";
import { ToolsScreen } from "@/features/tools/tools-screen";

export const metadata: Metadata = { title: "Tools & MCP" };

export default function Page() {
  return (
    <Suspense>
      <ToolsScreen />
    </Suspense>
  );
}
