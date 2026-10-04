import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import * as React from "react";
import { describe, expect, it, vi } from "vitest";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./select";

function Harness({ onChange = () => {} }: { onChange?: (v: string) => void }) {
  const [value, setValue] = React.useState("");
  return (
    <Select
      value={value}
      onValueChange={(v) => {
        setValue(v);
        onChange(v);
      }}
    >
      <SelectTrigger aria-label="Resource">
        <SelectValue placeholder="Choose…" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="github">GitHub</SelectItem>
        <SelectItem value="jira">Jira</SelectItem>
        <SelectItem value="slack" disabled>
          Slack
        </SelectItem>
      </SelectContent>
    </Select>
  );
}

describe("Select", () => {
  it("shows the placeholder, opens a listbox and reports the picked value", async () => {
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    const trigger = screen.getByRole("combobox", { name: "Resource" });
    expect(trigger).toHaveTextContent("Choose…");
    await userEvent.click(trigger);
    expect(screen.getByRole("listbox")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("option", { name: "Jira" }));
    expect(onChange).toHaveBeenCalledWith("jira");
    expect(screen.getByRole("combobox", { name: "Resource" })).toHaveTextContent("Jira");
    expect(screen.queryByRole("listbox")).toBeNull();
  });

  it("supports the keyboard and keeps disabled options unselectable", async () => {
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    screen.getByRole("combobox", { name: "Resource" }).focus();
    await userEvent.keyboard("{Enter}");
    expect(screen.getByRole("option", { name: "Slack" })).toHaveAttribute("aria-disabled", "true");
    await userEvent.keyboard("{ArrowDown}{Enter}");
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).not.toHaveBeenCalledWith("slack");
  });

  it("can be disabled", () => {
    render(
      <Select disabled>
        <SelectTrigger aria-label="Locked">
          <SelectValue placeholder="Choose…" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="a">A</SelectItem>
        </SelectContent>
      </Select>,
    );
    expect(screen.getByRole("combobox", { name: "Locked" })).toBeDisabled();
  });
});
