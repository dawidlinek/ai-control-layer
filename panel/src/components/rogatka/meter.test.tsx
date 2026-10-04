import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Meter, meterState } from "./meter";

describe("meterState", () => {
  it.each([
    [10, 100, false, "normal"],
    [79, 100, false, "normal"],
    [80, 100, false, "warning"],
    [100, 100, false, "danger"],
    [120, 120, false, "danger"],
    [10, 100, true, "danger"],
  ] as const)("%s of %s (forced=%s) is %s", (used, limit, force, expected) => {
    expect(meterState(used, limit, force)).toBe(expected);
  });
});

describe("Meter", () => {
  it("is accent below 80 %", () => {
    const { container } = render(<Meter label="Spend today" value={3.12} max={5} />);
    const meter = screen.getByRole("meter", { name: "Spend today" });
    expect(meter).toHaveAttribute("aria-valuenow", "3.12");
    expect(meter).toHaveAttribute("data-state", "normal");
    expect(container.querySelector(".bg-accent")).toHaveStyle({ width: "62.4%" });
  });

  it("turns orange at 80 % and red when over", () => {
    const { rerender } = render(<Meter label="Spend" value={4} max={5} />);
    expect(screen.getByRole("meter")).toHaveAttribute("data-state", "warning");
    rerender(<Meter label="Spend" value={6} max={5} />);
    expect(screen.getByRole("meter")).toHaveAttribute("data-state", "danger");
  });

  it("draws a forecast tick", () => {
    const { container } = render(<Meter label="Spend" value={3.12} max={5} forecast={4.4} />);
    expect(container.querySelector("[data-forecast]")).toHaveStyle({ left: "calc(88% - 1px)" });
  });

  it("is red when forced (open breaker)", () => {
    render(<Meter label="GPU" value={10} max={100} danger />);
    expect(screen.getByRole("meter")).toHaveAttribute("data-state", "danger");
  });
});
