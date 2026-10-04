import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Card, FactsGrid, PageHeader, PlainSentence, SidebarSection } from "./layout";

describe("PageHeader", () => {
  it("renders title, subtitle and right-hand actions", () => {
    render(<PageHeader title="Grants" subtitle="personal and temporary access" actions={<button>New grant</button>} />);
    expect(screen.getByRole("heading", { level: 1, name: "Grants" })).toHaveClass("text-[20px]", "font-semibold");
    expect(screen.getByText("personal and temporary access")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New grant" })).toBeInTheDocument();
  });
});

describe("PlainSentence", () => {
  it("renders the sentence", () => {
    render(<PlainSentence>Anna Nowak’s prompt contained a PESEL.</PlainSentence>);
    expect(screen.getByText(/Anna Nowak/)).toBeInTheDocument();
  });
});

describe("FactsGrid", () => {
  it("renders label / value pairs in two columns", () => {
    const { container } = render(
      <FactsGrid
        facts={[
          { label: "Who", value: "Anna Nowak" },
          { label: "Risk score", value: "0.31 · low", mono: true },
        ]}
      />,
    );
    expect(container.querySelector("dl")).toHaveClass("grid-cols-2");
    expect(screen.getByText("Who")).toBeInTheDocument();
    expect(screen.getByText("0.31 · low")).toHaveClass("font-mono");
  });
});

describe("SidebarSection", () => {
  it("renders an uppercase section label as a heading of its region", () => {
    render(
      <SidebarSection title="What the model saw" aside="212 ms">
        body
      </SidebarSection>,
    );
    const region = screen.getByRole("region", { name: "What the model saw" });
    expect(within(region).getByRole("heading", { level: 3 })).toHaveClass("uppercase", "tracking-[.08em]");
    expect(within(region).getByText("212 ms")).toBeInTheDocument();
  });
});

describe("Card", () => {
  it("renders a titled card", () => {
    render(<Card title="What is happening?">content</Card>);
    expect(screen.getByRole("region", { name: "What is happening?" })).toHaveTextContent("content");
  });
});
