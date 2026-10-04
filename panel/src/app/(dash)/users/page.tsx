import type { Metadata } from "next";
import { Suspense } from "react";
import { UsersScreen } from "@/features/users/users-screen";

export const metadata: Metadata = { title: "Users & groups" };

export default function Page() {
  return (
    <Suspense>
      <UsersScreen />
    </Suspense>
  );
}
