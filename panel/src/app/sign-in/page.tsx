import { redirect } from "next/navigation";
import { signIn } from "@/auth";
import { BrandLockup } from "@/components/rogatka/brand";
import { Button } from "@/components/ui/button";
import { authMode } from "@/lib/auth/mode";
import { getPanelUser } from "@/lib/auth/server";

export const metadata = { title: "Sign in" };

export default async function SignInPage() {
  if (authMode() === "dev" || (await getPanelUser())) redirect("/");
  return (
    <div className="flex min-h-screen items-center justify-center bg-bg p-6">
      <form
        className="flex w-full max-w-[380px] flex-col gap-3 rounded-[8px] border border-border bg-surface p-6"
        action={async () => {
          "use server";
          await signIn("keycloak", { redirectTo: "/" });
        }}
      >
        <BrandLockup className="mb-1" />
        <h1 className="m-0 text-[22px] font-semibold tracking-[-0.01em]">Sign in to Rogatka Dashboard</h1>
        <p className="m-0 text-muted">Sign in with your company account to continue.</p>
        <Button type="submit" variant="primary" size="lg">
          Sign in with company SSO
        </Button>
      </form>
    </div>
  );
}
