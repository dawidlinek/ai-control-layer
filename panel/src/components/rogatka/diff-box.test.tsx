import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DiffBox } from "./diff-box";

const lines = [
  { sign: " " as const, text: "Reads a file." },
  { sign: "-" as const, text: "old line" },
  { sign: "+" as const, text: "new line" },
  { sign: "~" as const, text: "changed" },
];

describe("DiffBox", () => {
  it("renders a titled figure with one row per line", () => {
    const { container } = render(<DiffBox title="git diff" lines={lines} ariaLabel="Preview" />);
    const fig = screen.getByRole("figure", { name: "Preview" });
    expect(fig).toHaveTextContent("git diff");
    expect(container.querySelectorAll("[data-sign]")).toHaveLength(4);
    expect(container.querySelector('[data-sign="context"]')).toHaveTextContent("Reads a file.");
    expect(container.querySelector('[data-sign="+"]')?.getAttribute("style")).toContain("--dec-allow");
    expect(container.querySelector('[data-sign="-"]')?.getAttribute("style")).toContain("--dec-block");
    expect(container.querySelector('[data-sign="~"]')?.getAttribute("style")).toContain("--dec-downgrade");
  });

  it("paints added lines red with addedTone=bad and removed lines green with removedTone=good", () => {
    const { container } = render(<DiffBox lines={lines} addedTone="bad" removedTone="good" ariaLabel="Diff" />);
    expect(container.querySelector("figcaption")).toBeNull();
    expect(container.querySelector('[data-sign="+"]')?.getAttribute("style")).toContain("--dec-block");
    expect(container.querySelector('[data-sign="-"]')?.getAttribute("style")).toContain("--dec-allow");
  });
});
