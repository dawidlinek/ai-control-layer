import { Button } from "@/components/ui/button";

export const NO_KEYCLOAK_LINK = "Not available in the admin API yet (no Keycloak console link)";

/** "Open Keycloak ↗" / "Manage in Keycloak ↗": people and membership live in Keycloak; the API exposes no console URL. */
export function KeycloakLink({ label }: { label: string }) {
  return (
    <Button variant="ghost" size="sm" disabled title={NO_KEYCLOAK_LINK}>
      {label} ↗
    </Button>
  );
}
