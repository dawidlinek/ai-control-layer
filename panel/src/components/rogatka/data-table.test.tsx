import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ColumnDef } from "@tanstack/react-table";
import { describe, expect, it, vi } from "vitest";
import { DataTable } from "./data-table";

interface Row {
  id: string;
  who: string;
  rule: string;
}

const data: Row[] = [
  { id: "tr_1", who: "Anna Nowak", rule: "SEC-PII-01" },
  { id: "tr_2", who: "Jan Kowalski", rule: "SEC-FLOW-01" },
  { id: "tr_3", who: "research-bot", rule: "BUDGET-LOOP-01" },
];

const columns: ColumnDef<Row, string>[] = [
  { accessorKey: "who", header: "Who" },
  { accessorKey: "rule", header: "Rule", meta: { className: "font-mono" } },
  { id: "link", header: "", cell: ({ row }) => (
      <a href={`/x/${row.original.id}`} onClick={(e) => e.preventDefault()}>
        open
      </a>
    ),
  },
];

function table(props: Partial<React.ComponentProps<typeof DataTable<Row>>> = {}) {
  return <DataTable<Row> data={data} columns={columns} getRowId={(r) => r.id} ariaLabel="Events" {...props} />;
}

describe("DataTable", () => {
  it("renders headers and rows", () => {
    render(table());
    const t = screen.getByRole("table", { name: "Events" });
    expect(within(t).getByRole("columnheader", { name: "Who" })).toHaveClass("uppercase", "text-[10.5px]");
    expect(within(t).getAllByRole("row")).toHaveLength(4);
    expect(within(t).getByText("SEC-FLOW-01")).toHaveClass("font-mono");
  });

  it("makes the whole row clickable, but not links inside it", async () => {
    const onRowClick = vi.fn();
    render(table({ onRowClick }));
    await userEvent.click(screen.getByText("Jan Kowalski"));
    expect(onRowClick).toHaveBeenCalledWith(data[1]);
    onRowClick.mockClear();
    await userEvent.click(screen.getAllByRole("link", { name: "open" })[0]);
    expect(onRowClick).not.toHaveBeenCalled();
  });

  it("marks the selected row", () => {
    render(table({ selectedId: "tr_2", onRowClick: () => {} }));
    const rows = screen.getAllByRole("row");
    expect(rows[2]).toHaveAttribute("aria-selected", "true");
    expect(rows[2]).toHaveClass("bg-accent-soft");
    expect(rows[2].querySelector("td")).toHaveClass("shadow-[inset_3px_0_0_var(--accent)]");
    expect(rows[1]).toHaveAttribute("aria-selected", "false");
  });

  it("opens a row with Enter when focused", async () => {
    const onRowClick = vi.fn();
    render(table({ onRowClick }));
    screen.getAllByRole("row")[1].focus();
    await userEvent.keyboard("{Enter}");
    expect(onRowClick).toHaveBeenCalledWith(data[0]);
  });

  it("moves with j / k and opens with Enter when keyboardNav is on", async () => {
    const onRowClick = vi.fn();
    render(table({ onRowClick, keyboardNav: true }));
    await userEvent.keyboard("j");
    await userEvent.keyboard("j");
    await userEvent.keyboard("k");
    await userEvent.keyboard("{Enter}");
    expect(onRowClick).toHaveBeenLastCalledWith(data[0]);
  });

  it("moves the open sidebar along with j / k", async () => {
    const onRowClick = vi.fn();
    render(table({ onRowClick, keyboardNav: true, selectedId: "tr_1" }));
    await userEvent.keyboard("j");
    expect(onRowClick).toHaveBeenCalledWith(data[1]);
  });

  it("ignores j / k while typing", async () => {
    const onRowClick = vi.fn();
    render(
      <>
        <input aria-label="q" />
        {table({ onRowClick, keyboardNav: true, selectedId: "tr_1" })}
      </>,
    );
    await userEvent.type(screen.getByLabelText("q"), "jk");
    expect(onRowClick).not.toHaveBeenCalled();
  });

  it("shows loading, error and empty states", async () => {
    const onRetry = vi.fn();
    const { rerender } = render(table({ loading: true }));
    expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
    rerender(table({ error: new Error("boom"), onRetry }));
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalled();
    rerender(table({ data: [], emptyTitle: "No events", emptyMessage: "Change the filters." }));
    expect(screen.getByText("No events")).toBeInTheDocument();
  });

  it("scrolls horizontally inside its box", () => {
    const { container } = render(table({ minWidth: 900 }));
    expect(container.firstElementChild).toHaveClass("overflow-x-auto");
    expect(screen.getByRole("table")).toHaveStyle({ minWidth: "900px" });
  });
});
