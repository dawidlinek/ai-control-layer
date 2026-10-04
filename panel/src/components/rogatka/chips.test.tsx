import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DECISIONS, DECISION_ICON, SEVERITIES } from "@/lib/decisions";
import {
  DecisionBadge,
  DecisionChips,
  MaskedValue,
  PlaceholderChip,
  RuleChip,
  SeverityChip,
  ToggleChip,
} from "./chips";

describe("DecisionBadge", () => {
  it.each(DECISIONS)("renders %s as an icon plus a mono label", (decision) => {
    const { container } = render(<DecisionBadge decision={decision} />);
    const badge = container.querySelector(`[data-decision="${decision}"]`) as HTMLElement;
    expect(badge).toHaveTextContent(decision);
    expect(badge).toHaveClass("font-mono", "tint");
    expect(badge.style.getPropertyValue("--c")).toContain(decision === "route_local" ? "route-local" : decision.replace("_", "-"));
    expect(badge.querySelector("path")).toHaveAttribute("d", DECISION_ICON[decision]);
    expect(badge.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });

  it("supports sizes and trailing content (legend counts)", () => {
    render(
      <DecisionBadge decision="block" size="lg">
        <b>44</b>
      </DecisionBadge>,
    );
    expect(screen.getByText("44")).toBeInTheDocument();
  });
});

describe("DecisionChips", () => {
  it("lists several decisions", () => {
    render(<DecisionChips decisions={["pseudonymise", "route_local"]} />);
    expect(screen.getByText("pseudonymise")).toBeInTheDocument();
    expect(screen.getByText("route_local")).toBeInTheDocument();
  });

  it("shows a dash when empty", () => {
    render(<DecisionChips decisions={[]} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });
});

describe("SeverityChip", () => {
  it.each(SEVERITIES)("renders %s", (severity) => {
    const { container } = render(<SeverityChip severity={severity} />);
    expect(container.querySelector(`[data-severity="${severity}"]`)).toHaveTextContent(severity);
  });

  it("renders info as low", () => {
    const { container } = render(<SeverityChip severity="info" />);
    expect(container.querySelector('[data-severity="low"]')).toBeInTheDocument();
  });
});

describe("RuleChip", () => {
  it("links to the rule in Policies", () => {
    render(<RuleChip ruleId="SEC-PII-01" />);
    const link = screen.getByRole("link", { name: "SEC-PII-01" });
    expect(link).toHaveAttribute("href", "/policies?rule=SEC-PII-01");
    expect(link).toHaveClass("font-mono", "bg-raised", "border-border-strong");
  });

  it("shows a lock for org locks", () => {
    render(<RuleChip ruleId="LOCK-01" locked />);
    expect(screen.getByRole("img", { name: "Org lock" })).toBeInTheDocument();
  });

  it("can render without a link", () => {
    render(<RuleChip ruleId="FEED-PKG-0007" href={false} />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText("FEED-PKG-0007")).toBeInTheDocument();
  });
});

describe("PlaceholderChip", () => {
  it("renders the placeholder with the pseudonymise tint", () => {
    render(<PlaceholderChip>{"<PESEL_1>"}</PlaceholderChip>);
    const chip = screen.getByText("<PESEL_1>");
    expect(chip).toHaveAttribute("data-placeholder");
    expect(chip.style.getPropertyValue("--c")).toContain("pseudonymise");
  });
});

describe("MaskedValue", () => {
  it("renders an already masked value with its label", () => {
    render(<MaskedValue label="PESEL" value="***-**-**123" />);
    expect(screen.getByText("***-**-**123", { exact: false })).toHaveAttribute("data-masked");
    expect(screen.getByText("PESEL")).toBeInTheDocument();
  });
});

describe("ToggleChip", () => {
  it("shows the state and toggles", async () => {
    const onChange = vi.fn();
    const { rerender } = render(<ToggleChip label="smart" on={false} onChange={onChange} />);
    const chip = screen.getByRole("switch", { name: /smart/ });
    expect(chip).toHaveAttribute("aria-checked", "false");
    expect(chip).toHaveTextContent("+");
    await userEvent.click(chip);
    expect(onChange).toHaveBeenCalledWith(true);
    rerender(<ToggleChip label="smart" on onChange={onChange} />);
    expect(screen.getByRole("switch", { name: /smart/ })).toHaveTextContent("✓");
  });
});
