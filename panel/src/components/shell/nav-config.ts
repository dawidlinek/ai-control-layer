export interface NavItem {
  label: string;
  href: string;
  /** Which count badge to show (fetched from the API). */
  badge?: "incidents" | "approvals";
  /** Letter for the `g` + letter shortcut. */
  shortcut: string;
  /** Extra path prefixes that keep this item highlighted (e.g. `/sessions` belongs to Traffic). */
  alsoActiveFor?: string[];
}

export interface NavSection {
  /** Uppercase section header; none for Overview. */
  title?: string;
  items: NavItem[];
}

export const NAV: NavSection[] = [
  { items: [{ label: "Overview", href: "/", shortcut: "o" }] },
  {
    title: "Monitor",
    items: [
      { label: "Traffic", href: "/traffic", shortcut: "t", alsoActiveFor: ["/sessions"] },
      { label: "Incidents", href: "/incidents", badge: "incidents", shortcut: "i" },
      { label: "Approvals", href: "/approvals", badge: "approvals", shortcut: "a" },
    ],
  },
  {
    title: "Access",
    items: [
      { label: "Users & groups", href: "/users", shortcut: "u" },
      { label: "Grants", href: "/grants", shortcut: "g" },
    ],
  },
  {
    title: "Govern",
    items: [
      { label: "Policies", href: "/policies", shortcut: "p" },
      { label: "Models & connectors", href: "/models", shortcut: "m" },
      { label: "Tools & MCP", href: "/tools", shortcut: "l" },
      { label: "Known threats", href: "/threats", shortcut: "k" },
      { label: "Budgets & spend", href: "/budgets", shortcut: "b" },
    ],
  },
  { title: "Optimise", items: [{ label: "Automation Insights", href: "/insights", shortcut: "n" }] },
];

export function isActive(item: NavItem, pathname: string): boolean {
  if (item.href === "/") return pathname === "/";
  const prefixes = [item.href, ...(item.alsoActiveFor ?? [])];
  return prefixes.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

export const ALL_NAV_ITEMS: NavItem[] = NAV.flatMap((s) => s.items);
