import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import * as React from "react";
import { describe, expect, it, vi } from "vitest";
import { FilterMenuButton, FilterRow, LabeledSwitch, SearchInput, Segmented, SegmentedTabs } from "./filters";

describe("FilterRow", () => {
  it("wraps its children", () => {
    render(
      <FilterRow data-testid="row">
        <span>a</span>
      </FilterRow>,
    );
    expect(screen.getByTestId("row")).toHaveClass("flex-wrap");
  });
});

describe("SegmentedTabs", () => {
  const tabs = [
    { value: "open", label: "Open", count: 7 },
    { value: "resolved", label: "Resolved", count: 2 },
    { value: "all", label: "All", count: 9 },
  ];

  it("shows tabs with counts and the selected one", () => {
    render(<SegmentedTabs tabs={tabs} value="open" onChange={() => {}} ariaLabel="Status" />);
    expect(screen.getByRole("tablist", { name: "Status" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Open 7" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "Resolved 2" })).toHaveAttribute("aria-selected", "false");
  });

  it("reports the clicked tab", async () => {
    const onChange = vi.fn();
    render(<SegmentedTabs tabs={tabs} value="open" onChange={onChange} />);
    await userEvent.click(screen.getByRole("tab", { name: "All 9" }));
    expect(onChange).toHaveBeenCalledWith("all");
  });
});

describe("Segmented", () => {
  it("is a pressed-button group", async () => {
    const onChange = vi.fn();
    render(
      <Segmented
        ariaLabel="Theme"
        value="dark"
        onChange={onChange}
        options={[
          { value: "dark", label: "Dark" },
          { value: "light", label: "Light" },
        ]}
      />,
    );
    const group = screen.getByRole("group", { name: "Theme" });
    expect(within(group).getByRole("button", { name: "Dark" })).toHaveAttribute("aria-pressed", "true");
    await userEvent.click(within(group).getByRole("button", { name: "Light" }));
    expect(onChange).toHaveBeenCalledWith("light");
  });

  it("disables a single option: disabled + aria-disabled, no onChange", async () => {
    const onChange = vi.fn();
    render(
      <Segmented
        ariaLabel="Mode"
        value="a"
        onChange={onChange}
        options={[
          { value: "a", label: "A" },
          { value: "b", label: "B", disabled: true },
          { value: "c", label: "C" },
        ]}
      />,
    );
    const b = screen.getByRole("button", { name: "B" });
    expect(b).toBeDisabled();
    expect(b).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("button", { name: "C" })).not.toBeDisabled();
    await userEvent.click(b);
    expect(onChange).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "C" }));
    expect(onChange).toHaveBeenCalledWith("c");
  });

  it("disables the whole control", async () => {
    const onChange = vi.fn();
    render(
      <Segmented
        ariaLabel="Mode"
        value="a"
        disabled
        onChange={onChange}
        options={[
          { value: "a", label: "A" },
          { value: "b", label: "B" },
        ]}
      />,
    );
    expect(screen.getByRole("group", { name: "Mode" })).toHaveAttribute("aria-disabled", "true");
    for (const name of ["A", "B"]) {
      expect(screen.getByRole("button", { name })).toBeDisabled();
      expect(screen.getByRole("button", { name })).toHaveAttribute("aria-disabled", "true");
    }
    await userEvent.click(screen.getByRole("button", { name: "B" }));
    expect(onChange).not.toHaveBeenCalled();
  });
});

describe("FilterMenuButton", () => {
  const options = [
    { value: "block", label: "block" },
    { value: "allow", label: "allow" },
  ];

  function Harness({ multiple = true }: { multiple?: boolean }) {
    const [sel, setSel] = React.useState<string[]>([]);
    return <FilterMenuButton label="Decision" options={options} selected={sel} onChange={setSel} multiple={multiple} />;
  }

  it("opens a checkable menu and keeps it open while ticking several options", async () => {
    render(<Harness />);
    await userEvent.click(screen.getByRole("button", { name: "Decision" }));
    const menu = await screen.findByRole("menu");
    await userEvent.click(within(menu).getByRole("menuitemcheckbox", { name: "block" }));
    await userEvent.click(within(menu).getByRole("menuitemcheckbox", { name: "allow" }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    expect(within(screen.getByRole("menu")).getByRole("menuitemcheckbox", { name: "block" })).toHaveAttribute("aria-checked", "true");
    // the page behind an open menu is aria-hidden, hence `hidden: true`
    expect(screen.getByRole("button", { name: /Decision/, hidden: true })).toHaveTextContent("· 2");
  });

  it("single mode picks one option and shows it on the button", async () => {
    render(<Harness multiple={false} />);
    await userEvent.click(screen.getByRole("button", { name: "Decision" }));
    await userEvent.click(await screen.findByRole("menuitemcheckbox", { name: "allow" }));
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "allow" })).toBeInTheDocument();
  });
});

describe("SearchInput", () => {
  it("is a labelled search field", async () => {
    const onChange = vi.fn();
    render(<SearchInput value="" onChange={onChange} placeholder="Rule, trace ID or text" ariaLabel="Filter events" />);
    await userEvent.type(screen.getByRole("searchbox", { name: "Filter events" }), "x");
    expect(onChange).toHaveBeenCalledWith("x");
    expect(screen.getByPlaceholderText("Rule, trace ID or text")).toBeInTheDocument();
  });
});

describe("LabeledSwitch", () => {
  it("toggles by label click", async () => {
    const onChange = vi.fn();
    render(<LabeledSwitch label="Hide allowed" checked={false} onCheckedChange={onChange} />);
    const sw = screen.getByRole("switch", { name: "Hide allowed" });
    expect(sw).toHaveAttribute("aria-checked", "false");
    await userEvent.click(screen.getByText("Hide allowed"));
    expect(onChange).toHaveBeenCalledWith(true);
  });
});
