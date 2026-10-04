import Link from "next/link";
import { BrandLockup } from "@/components/rogatka/brand";
import { Button } from "@/components/ui/button";

export const metadata = { title: "Signed out" };

export default function SignedOutPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-bg p-6">
      <div className="flex w-full max-w-[380px] flex-col gap-3 rounded-[8px] border border-border bg-surface p-6">
        <BrandLockup className="mb-1" />
        <h1 className="m-0 text-[22px] font-semibold tracking-[-0.01em]">You are signed out</h1>
        <p className="m-0 text-muted">See you next time.</p>
        <div>
          <Button asChild variant="primary" size="lg">
            <Link href="/">Sign in again</Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
