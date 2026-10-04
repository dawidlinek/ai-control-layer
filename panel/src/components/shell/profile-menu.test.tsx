import { screen, within } from "@testing-library/react";
import * as React from "react";
import { describe, expect, it, vi } from "vitest";
import { renderApp } from "@/test/render";
import { DEV_USER } from "@/lib/auth/user";
import { ProfileMenu } from "./profile-menu";

const signOut = vi.fn().mockResolvedValue(undefined);
vi.mock("next-auth/react", () => ({ signOut: (...a: unknown[]) => signOut(...a) }));

function Harness() {
  const [open, setOpen] = React.useState(false);
  return <ProfileMenu shortcutsOpen={open} onShortcutsOpenChange={setOpen} />;
}

const assign = vi.fn();
Object.defineProperty(window, "location", { value: { ...window.location, assign, search: "" }, writable: true });

describe("ProfileMenu", () => {
  it("shows initials, name and role on the button", () => {
    renderApp(<Harness />);
    const button = screen.getByRole("button", { name: "Account menu" });
    expect(button).toHaveTextContent("KW");
    expect(button).toHaveTextContent("Katarzyna Wójcik");
    expect(button).toHaveTextContent("Security analyst");
  });

  it("opens a menu with e-mail, role chips and the four actions", async () => {
    const { user } = renderApp(<Harness />);
    await user.click(screen.getByRole("button", { name: "Account menu" }));
    const menu = await screen.findByRole("menu");
    expect(within(menu).getByText("k.wojcik@corp.example")).toBeInTheDocument();
    expect(within(menu).getByText("acl-admin")).toBeInTheDocument();
    expect(within(menu).getByText("Keycloak · /security")).toBeInTheDocument();
    expect(within(menu).getByRole("menuitem", { name: "Notifications" })).toBeInTheDocument();
    expect(within(menu).getByRole("menuitem", { name: /Keyboard shortcuts/ })).toBeInTheDocument();
    expect(within(menu).getByRole("group", { name: "Theme" })).toBeInTheDocument();
    expect(within(menu).getByRole("menuitem", { name: "Sign out" })).toBeInTheDocument();
  });

  it("switches the theme, persisted in a cookie", async () => {
    const { user } = renderApp(<Harness />);
    await user.click(screen.getByRole("button", { name: "Account menu" }));
    const group = await screen.findByRole("group", { name: "Theme" });
    expect(within(group).getByRole("button", { name: "Dark" })).toHaveAttribute("aria-pressed", "true");
    await user.click(within(group).getByRole("button", { name: "Light" }));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.cookie).toContain("rogatka-theme=light");
    expect(within(group).getByRole("button", { name: "Light" })).toHaveAttribute("aria-pressed", "true");
    await user.click(within(group).getByRole("button", { name: "Dark" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("opens the keyboard shortcuts dialog", async () => {
    const { user } = renderApp(<Harness />);
    await user.click(screen.getByRole("button", { name: "Account menu" }));
    await user.click(await screen.findByRole("menuitem", { name: /Keyboard shortcuts/ }));
    const dialog = await screen.findByRole("dialog", { name: "Keyboard shortcuts" });
    expect(within(dialog).getByText("Go to")).toBeInTheDocument();
    expect(within(dialog).getByText("Show this help")).toBeInTheDocument();
    expect(within(dialog).getByText("Incidents")).toBeInTheDocument();
  });

  it("opens notifications", async () => {
    const { user } = renderApp(<Harness />);
    await user.click(screen.getByRole("button", { name: "Account menu" }));
    await user.click(await screen.findByRole("menuitem", { name: "Notifications" }));
    expect(await screen.findByRole("dialog", { name: "Notifications" })).toBeInTheDocument();
  });

  it("signs out of the demo session by going to the signed-out page", async () => {
    const { user } = renderApp(<Harness />, { devMode: true });
    await user.click(screen.getByRole("button", { name: "Account menu" }));
    await user.click(await screen.findByRole("menuitem", { name: "Sign out" }));
    expect(assign).toHaveBeenCalledWith("/signed-out");
    expect(signOut).not.toHaveBeenCalled();
  });

  it("ends the Auth.js session and then the Keycloak one outside dev mode", async () => {
    const { user } = renderApp(<Harness />, { user: { ...DEV_USER, role: "analyst", roles: ["acl-analyst"], title: undefined } });
    expect(screen.getByRole("button", { name: "Account menu" })).toHaveTextContent("Security analyst");
    await user.click(screen.getByRole("button", { name: "Account menu" }));
    await user.click(await screen.findByRole("menuitem", { name: "Sign out" }));
    expect(signOut).toHaveBeenCalledWith({ redirect: false });
    expect(assign).toHaveBeenCalledWith("/api/auth/signout");
  });
});
