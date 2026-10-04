import { screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { renderApp } from "@/test/render";
import { ListWithSidebar, SidebarActions, SidebarBlock, SidebarHeader, useSelectedId } from "./list-with-sidebar";

function Screen() {
  const [sel, setSel] = useSelectedId();
  return (
    <ListWithSidebar
      open={!!sel}
      onClose={() => void setSel(null)}
      sidebarLabel="Trace"
      list={
        <>
          <button onClick={() => void setSel("tr_8f3a2c")}>row</button>
          <input aria-label="q" />
        </>
      }
      sidebar={
        <>
          <SidebarHeader label="Trace" title={sel} copyText={sel ?? ""} />
          <SidebarBlock>facts</SidebarBlock>
          <SidebarActions>
            <button>Replay</button>
          </SidebarActions>
        </>
      }
    />
  );
}

describe("ListWithSidebar", () => {
  it("shows only the list when nothing is selected", () => {
    renderApp(<Screen />);
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "List" })).toHaveClass("flex-[999_1_560px]");
  });

  it("opens the sidebar from ?sel= and closes it with the x", async () => {
    const onUrlUpdate = vi.fn();
    const { user } = renderApp(<Screen />, { searchParams: "?sel=tr_8f3a2c", onUrlUpdate });
    const aside = screen.getByRole("complementary", { name: "Trace" });
    expect(aside).toHaveClass("flex-[1_1_440px]");
    expect(aside).toHaveTextContent("tr_8f3a2c");
    await user.click(screen.getByRole("button", { name: "Close trace" }));
    await waitFor(() => expect(screen.queryByRole("complementary")).not.toBeInTheDocument());
    expect(onUrlUpdate).toHaveBeenLastCalledWith(expect.objectContaining({ queryString: "" }));
  });

  it("writes the selection to the URL", async () => {
    const onUrlUpdate = vi.fn();
    const { user } = renderApp(<Screen />, { onUrlUpdate });
    await user.click(screen.getByRole("button", { name: "row" }));
    await waitFor(() => expect(screen.getByRole("complementary")).toBeInTheDocument());
    expect(onUrlUpdate).toHaveBeenLastCalledWith(expect.objectContaining({ queryString: "?sel=tr_8f3a2c" }));
  });

  it("closes with Esc but not while typing", async () => {
    const { user } = renderApp(<Screen />, { searchParams: "?sel=tr_8f3a2c" });
    await user.click(screen.getByLabelText("q"));
    await user.keyboard("{Escape}");
    expect(screen.getByRole("complementary")).toBeInTheDocument();
    await user.click(document.body);
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("complementary")).not.toBeInTheDocument());
  });

  it("copies the id", async () => {
    const { user } = renderApp(<Screen />, { searchParams: "?sel=tr_8f3a2c" });
    await user.click(screen.getByRole("button", { name: "Copy trace ID" }));
    expect(await navigator.clipboard.readText()).toBe("tr_8f3a2c"); // user-event's clipboard stub
  });
});
