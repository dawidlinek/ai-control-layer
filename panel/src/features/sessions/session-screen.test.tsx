import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { renderApp } from "@/test/render";
import { SessionScreen } from "./session-screen";

describe("Session view", () => {
  it("renders the redacted transcript with label, chips and links back to Traffic", async () => {
    renderApp(<SessionScreen id="c_51a8" />, { pathname: "/sessions/c_51a8" });
    expect(screen.getByRole("heading", { level: 1, name: "Session c_51a8" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 1, name: "Conversation c_51a8" })).toBeInTheDocument();
    expect(await screen.findByText(/Anna Nowak · LibreChat · credit-analysts · 6 messages · started today \d\d:\d\d/)).toBeInTheDocument();
    expect(screen.getByText(/^Session confidential since \d\d:\d\d · local only$/)).toBeInTheDocument();

    const turns = within(screen.getByRole("list", { name: "Turns" })).getAllByRole("listitem");
    expect(turns).toHaveLength(6);
    expect(turns.map((t) => t.getAttribute("data-role"))).toEqual(["user", "assistant", "user", "assistant", "user", "assistant"]);

    const pesel = within(turns[4]);
    expect(pesel.getByText("Anna Nowak")).toBeInTheDocument();
    expect(pesel.getByText("<PESEL_1>", { selector: "[data-placeholder]" })).toBeInTheDocument();
    expect(pesel.getByText("pseudonymise")).toBeInTheDocument();
    expect(pesel.getByRole("link", { name: "SEC-PII-01" })).toHaveAttribute("href", "/policies?rule=SEC-PII-01");
    expect(pesel.getByRole("link", { name: "Open trace tr_8f3a2c in Traffic" })).toHaveAttribute("href", "/traffic?sel=tr_8f3a2c");
    expect(pesel.getByText(/contained a PESEL, an IBAN and a name/)).toBeInTheDocument();
    // Allowed turns carry no extra sentence.
    expect(within(turns[0]).queryByText(/Nothing sensitive/)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "All requests in Traffic →" })).toHaveAttribute("href", "/traffic?q=c_51a8");
  });

  it("shows tool calls of an agent session", async () => {
    renderApp(<SessionScreen id="s_9e21" />, { pathname: "/sessions/s_9e21" });
    expect(await screen.findByText("pip install litellm==1.82.8")).toBeInTheDocument();
    expect(screen.getByText(/^Session restricted since \d\d:\d\d · untrusted content · local only$/)).toBeInTheDocument();
    expect(screen.getByText("‹SECRET:api_key›", { selector: "[data-placeholder]" })).toBeInTheDocument();
  });

  it("shows a friendly empty state for an unknown session", async () => {
    renderApp(<SessionScreen id="s_nope" />, { pathname: "/sessions/s_nope" });
    expect(await screen.findByText("This session is not in the audit log")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to Traffic" })).toHaveAttribute("href", "/traffic");
  });

  it("shows an error with retry for other failures", async () => {
    server.use(http.get(adminPath("/sessions/:id/transcript"), () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    renderApp(<SessionScreen id="c_51a8" />, { pathname: "/sessions/c_51a8" });
    expect(await screen.findByText("Could not load this session")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
});
