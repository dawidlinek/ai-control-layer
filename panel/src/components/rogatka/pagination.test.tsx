import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Pagination, pageWindow } from "./pagination";

describe("pageWindow", () => {
  it("shows the first pages when near the start", () => {
    expect(pageWindow(1, 52)).toEqual([1, 2, 3, null, 52]);
  });
  it("shows the neighbours of a middle page", () => {
    expect(pageWindow(10, 52)).toEqual([1, null, 9, 10, 11, null, 52]);
  });
  it("has no gaps for few pages", () => {
    expect(pageWindow(2, 3)).toEqual([1, 2, 3]);
  });
});

describe("Pagination", () => {
  it("renders rows per page and numbered pages", () => {
    render(<Pagination page={1} pageCount={52} pageSize={25} onPageChange={() => {}} />);
    expect(screen.getByText("Rows per page")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rows per page" })).toHaveTextContent("25");
    expect(screen.getByRole("button", { name: "1" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
  });

  it("changes page", async () => {
    const onPageChange = vi.fn();
    render(<Pagination page={2} pageCount={5} pageSize={25} onPageChange={onPageChange} />);
    await userEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(onPageChange).toHaveBeenCalledWith(3);
    await userEvent.click(screen.getByRole("button", { name: "Previous page" }));
    expect(onPageChange).toHaveBeenCalledWith(1);
  });

  it("changes the page size from the menu", async () => {
    const onPageSizeChange = vi.fn();
    render(<Pagination page={1} pageCount={2} pageSize={25} onPageChange={() => {}} onPageSizeChange={onPageSizeChange} />);
    await userEvent.click(screen.getByRole("button", { name: "Rows per page" }));
    await userEvent.click(await screen.findByRole("menuitemradio", { name: "50" }));
    expect(onPageSizeChange).toHaveBeenCalledWith(50);
  });

  it("works without a known total (cursor APIs)", () => {
    render(<Pagination page={3} hasNext pageSize={25} onPageChange={() => {}} />);
    expect(screen.getByRole("button", { name: "Next page" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "1" })).not.toBeInTheDocument();
  });
});
