import { screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { renderApp } from "@/test/render";
import { router } from "@/test/router";
import { AppShell } from "./app-shell";

vi.mock("next-auth/react", () => ({ signOut: vi.fn() }));

describe("AppShell", () => {
  it("renders the logo lockup, navigation and content", () => {
    renderApp(
      <AppShell>
        <h1>Page</h1>
      </AppShell>,
    );
    const header = screen.getByRole("banner");
    expect(within(header).getByRole("link", { name: /Rogatka\s*Dashboard/ })).toHaveAttribute("href", "/");
    expect(within(header).getByText("Dashboard")).toHaveClass("bg-accent-text", "text-on-accent");
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByRole("main")).toContainElement(screen.getByRole("heading", { name: "Page" }));
  });

  it("has no search box, bell or status strip", () => {
    renderApp(<AppShell>x</AppShell>);
    expect(screen.queryByRole("searchbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /notifications/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/LIVE/)).not.toBeInTheDocument();
  });

  it("stacks the navigation above the content on narrow screens (wrapping flex)", () => {
    renderApp(<AppShell>x</AppShell>);
    expect(screen.getByRole("navigation", { name: "Main" }).parentElement).toHaveClass("flex-wrap");
  });

  it("goes to a screen with g then a letter", async () => {
    const { user } = renderApp(<AppShell>x</AppShell>);
    await user.keyboard("gi");
    expect(router.push).toHaveBeenCalledWith("/incidents");
    await user.keyboard("gt");
    expect(router.push).toHaveBeenCalledWith("/traffic");
  });

  it("opens shortcut help with ?", async () => {
    const { user } = renderApp(<AppShell>x</AppShell>);
    await user.keyboard("?");
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });

  it("does not hijack keys while typing", async () => {
    const { user } = renderApp(
      <AppShell>
        <input aria-label="q" />
      </AppShell>,
    );
    await user.click(screen.getByLabelText("q"));
    await user.keyboard("gi");
    expect(router.push).not.toHaveBeenCalled();
  });
});
