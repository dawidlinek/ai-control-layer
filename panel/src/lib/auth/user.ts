import { ROLE_LABEL, type Role } from "./roles";

/** What the browser may know about the signed-in person. Never contains tokens. */
export interface PanelUser {
  name: string;
  email: string;
  username: string;
  /** Job title shown under the name when known (demo user); otherwise the role label is shown. */
  title?: string;
  /** Realm roles from the access token (e.g. `acl-admin`). */
  roles: string[];
  /** Keycloak groups (full paths, e.g. `/security`). */
  groups: string[];
  /** Highest panel role, `null` = no access. */
  role: Role | null;
}

export function displayTitle(user: PanelUser): string {
  return user.title ?? (user.role ? ROLE_LABEL[user.role] : "No access");
}

/** Demo user of the mock / dev mode (HANDOFF section 6). Role `admin` so demo actions work. */
export const DEV_USER: PanelUser = {
  name: "Katarzyna Wójcik",
  email: "k.wojcik@corp.example",
  username: "k.wojcik",
  title: "Security analyst",
  roles: ["acl-admin"],
  groups: ["/security"],
  role: "admin",
};
