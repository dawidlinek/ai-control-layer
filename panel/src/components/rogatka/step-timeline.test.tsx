import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { StepTimeline, type TimelineStep } from "./step-timeline";

const steps: TimelineStep[] = [
  { id: "identity", name: "Identity", result: "user identified", meta: "0.6 ms" },
  { id: "rules", name: "Rules", result: "found a PESEL and an IBAN", meta: "7 ms", changed: true, detail: <div>SEC-PII-01 detail</div> },
  { id: "decide", name: "Decide", result: "pseudonymise", changed: true },
];

describe("StepTimeline", () => {
  it("lists the steps and marks changed ones", () => {
    const { container } = render(<StepTimeline steps={steps} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(container.querySelector('[data-step="rules"]')).toHaveAttribute("data-changed", "true");
    expect(container.querySelector('[data-step="identity"]')).not.toHaveAttribute("data-changed");
    expect(screen.getByText("Rules")).toHaveClass("font-semibold");
    expect(screen.getByText("Identity")).toHaveClass("text-muted");
    expect(screen.getByText("7 ms")).toHaveClass("font-mono");
  });

  it("expands a step with detail on click, collapses on second click", async () => {
    render(<StepTimeline steps={steps} />);
    const rules = screen.getByRole("button", { name: /Rules/ });
    expect(rules).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(rules);
    expect(screen.getByText("SEC-PII-01 detail")).toBeInTheDocument();
    expect(rules).toHaveAttribute("aria-expanded", "true");
    await userEvent.click(rules);
    expect(screen.queryByText("SEC-PII-01 detail")).not.toBeInTheDocument();
  });

  it("does not make steps without detail clickable", () => {
    render(<StepTimeline steps={steps} />);
    expect(screen.getByRole("button", { name: /Identity/ })).toBeDisabled();
  });

  it("can start open", () => {
    render(<StepTimeline steps={steps} defaultOpenId="rules" />);
    expect(screen.getByText("SEC-PII-01 detail")).toBeInTheDocument();
  });
});
