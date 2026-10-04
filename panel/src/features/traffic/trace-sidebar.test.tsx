import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { renderApp } from "@/test/render";
import { TrafficScreen } from "./traffic-screen";

function openTrace(sel: string) {
  const r = renderApp(<TrafficScreen />, { pathname: "/traffic", searchParams: `?sel=${sel}`, urlMemory: true });
  return { ...r, aside: () => screen.getByRole("complementary", { name: "Trace" }) };
}

describe("Trace sidebar", () => {
  it("shows the trace id, decision chips, sentence and facts", async () => {
    const { aside } = openTrace("tr_8f3a2c");
    const a = within(await screen.findByRole("complementary", { name: "Trace" }));
    expect(a.getByText("tr_8f3a2c")).toBeInTheDocument();
    expect(a.getByRole("button", { name: "Copy trace ID" })).toBeInTheDocument();
    expect(await a.findByText(/Anna Nowak’s prompt contained a PESEL, an IBAN and a name/)).toBeInTheDocument();
    const facts = aside().querySelector("dl")!;
    await waitFor(() => expect(within(facts).getByText("Anna Nowak · LibreChat · credit-analysts")).toBeInTheDocument());
    expect(within(facts).getByText("local/qwen3.8-27b")).toBeInTheDocument();
    expect(within(facts).getByText("confidential")).toBeInTheDocument();
    expect(within(facts).getByText("0.31 · low")).toBeInTheDocument();
    expect(within(facts).getByText(/^today \d\d:\d\d:\d\d$/)).toBeInTheDocument();
    expect(a.getByText(/^Session confidential since \d\d:\d\d · local only$/)).toBeInTheDocument();
    expect(a.getByText("212 ms added by Rogatka")).toBeInTheDocument();
  });

  it("links to the full conversation with client, message count and start", async () => {
    openTrace("tr_8f3a2c");
    const a = within(await screen.findByRole("complementary", { name: "Trace" }));
    const link = await a.findByRole("link", { name: /Open full conversation/ });
    expect(link).toHaveAttribute("href", "/sessions/c_51a8");
    expect(link).toHaveTextContent(/c_51a8 · LibreChat · 6 messages · started \d\d:\d\d/);
  });

  it("says 'Open full session' for OpenCode and agents, and shows the command", async () => {
    openTrace("tr_9b21e4");
    const a = within(await screen.findByRole("complementary", { name: "Trace" }));
    const link = await a.findByRole("link", { name: /Open full session/ });
    expect(link).toHaveAttribute("href", "/sessions/s_9e21");
    expect(link).toHaveTextContent("OpenCode on dev-jk-01 · repo loan-calc · 14 messages");
    expect(await a.findByText("bash: git push origin feature/loan-calc")).toBeInTheDocument();
    // Held requests get the Approval step.
    expect(await a.findByText("waiting for security · auto-deny in 9:40")).toBeInTheDocument();
  });

  it("shows What the model saw with placeholder chips only when the content was changed", async () => {
    openTrace("tr_8f3a2c");
    const saw = await screen.findByTestId("model-saw");
    const chips = [...saw.querySelectorAll("[data-placeholder]")].map((c) => c.textContent);
    expect(chips).toEqual(["<PERSON_1>", "<PESEL_1>", "<IBAN_1>"]);
    expect(screen.getByText("PESEL ***-**-**123 · IBAN PL** … 2874 · put back in the answer for Anna only")).toBeInTheDocument();
  });

  it("shows the removed key and the removed injected sentence", async () => {
    openTrace("tr_9b1f07");
    expect(await screen.findByText("‹SECRET:api_key›", { selector: "[data-placeholder]" })).toBeInTheDocument();
    expect(screen.getByText("the key never reached the model")).toBeInTheDocument();
  });

  it("has no What the model saw section when nothing was changed", async () => {
    openTrace("tr_9a0c33");
    const a = within(await screen.findByRole("complementary", { name: "Trace" }));
    expect(await a.findByText("matches feed signature for litellm 1.82.8")).toBeInTheDocument();
    expect(a.queryByText("What the model saw")).not.toBeInTheDocument();
    expect(screen.queryByTestId("model-saw")).not.toBeInTheDocument();
  });

  it("marks changed steps and expands a step to show its controls", async () => {
    const { user } = openTrace("tr_8f3a2c");
    const timeline = await screen.findByRole("list", { name: "How the decision was made" });
    const steps = [...timeline.querySelectorAll("li")];
    expect(steps.map((s) => s.getAttribute("data-step"))).toEqual([
      "identity", "normalise", "rules", "similarity", "classifier", "judge", "decide", "route", "output",
    ]);
    expect(steps.filter((s) => s.hasAttribute("data-changed")).map((s) => s.getAttribute("data-step"))).toEqual([
      "rules", "classifier", "decide", "route",
    ]);
    // Rules (the first changed step with controls) is open by default.
    const rules = within(steps[2]);
    expect(rules.getByRole("button", { expanded: true })).toBeInTheDocument();
    expect(rules.getByText("PESEL found, checksum valid")).toBeInTheDocument();
    expect(rules.getAllByRole("link", { name: "SEC-PII-01" })[0]).toHaveAttribute("href", "/policies?rule=SEC-PII-01");

    // Expand the classifier: finding, score vs threshold, verdict chip.
    const classifier = within(steps[4]);
    await user.click(classifier.getByRole("button", { expanded: false }));
    expect(classifier.getByText("person name")).toBeInTheDocument();
    expect(classifier.getByText("0.97 ≥ 0.50")).toBeInTheDocument();
    expect(classifier.getByText("0.03 < 0.50")).toBeInTheDocument();
    expect(classifier.getByText("pass")).toBeInTheDocument();
    expect(classifier.getByText("pseudonymise")).toBeInTheDocument();
    expect(rules.queryByText("PESEL found, checksum valid")).not.toBeInTheDocument();

    // Steps without controls cannot be expanded.
    expect(within(steps[0]).getByRole("button")).toBeDisabled();
  });

  it("shows Replay and Add to incident disabled with an explanation (no endpoint)", async () => {
    openTrace("tr_8f3a2c");
    const a = within(await screen.findByRole("complementary", { name: "Trace" }));
    for (const name of ["Replay with live policy", "Add to incident"]) {
      const b = await a.findByRole("button", { name });
      expect(b).toBeDisabled();
      expect(b).toHaveAttribute("title", "Not available in the admin API yet");
    }
  });

  it("shows an error when the trace cannot be found", async () => {
    server.use(http.get(adminPath("/events/:id/trace"), () => HttpResponse.json({ detail: "event not found" }, { status: 404 })));
    openTrace("tr_missing");
    const a = within(await screen.findByRole("complementary", { name: "Trace" }));
    expect(await a.findByText("Could not load this trace")).toBeInTheDocument();
    expect(a.getByText("event not found")).toBeInTheDocument();
  });
});
