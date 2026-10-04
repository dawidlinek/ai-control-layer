import { PageHeader } from "@/components/rogatka/layout";

/** Stand-in page body until a screen agent replaces it (see panel/ARCHITECTURE.md). */
export function PlaceholderScreen({ title }: { title: string }) {
  return (
    <>
      <PageHeader title={title} />
      <p className="m-0 text-muted">{title} — being built</p>
    </>
  );
}
