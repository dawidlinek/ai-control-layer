import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { renderApp } from "@/test/render";
import { DEV_USER } from "@/lib/auth/user";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { feedStatus } from "@/mocks/db/feed";
import { ThreatsScreen } from "./threats-screen";

const VIEWER = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"] };

describe("ThreatsScreen", () => {
  it("shows the feed status bar and the signatures", async () => {
    renderApp(<ThreatsScreen />);
    const bar = await screen.findByRole("region", { name: "Signature feed" });
    expect(within(bar).getByText("bundle 412 · 214 rules")).toBeInTheDocument();
    expect(within(bar).getByText("verified")).toBeInTheDocument();
    expect(within(bar).getByText("feed.corp:8080 · every 30 s")).toBeInTheDocument();

    const table = screen.getByRole("table", { name: "Signatures" });
    for (const id of ["FEED-PKG-0007", "FEED-PKG-0012", "FEED-PKG-0142", "FEED-EXF-0044", "FEED-MCP-0009", "FEED-URL-0031", "FEED-CMD-0102"]) {
      expect(within(table).getByText(id)).toBeInTheDocument();
    }
    expect(within(table).getByText("litellm 1.82.7 and 1.82.8 — backdoored PyPI releases")).toBeInTheDocument();
    // Hits are counted from the last 24 h of traffic: the litellm install was blocked by FEED-PKG-0007.
    const pkgRow = within(table).getByText("FEED-PKG-0007").closest("tr")!;
    await waitFor(() => expect(pkgRow.querySelectorAll("td")[4]).not.toHaveTextContent("—"));
    expect(Number(pkgRow.querySelectorAll("td")[4].textContent)).toBeGreaterThan(0);

    const add = screen.getByRole("button", { name: "+ Add rule" });
    expect(add).toBeDisabled();
    expect(add).toHaveAttribute("title", expect.stringContaining("Not available in the admin API yet"));
  });

  it("opens a signature: explanation, pattern, facts and recent hits linking to Traffic", async () => {
    const { user } = renderApp(<ThreatsScreen />);
    const table = await screen.findByRole("table", { name: "Signatures" });
    await user.click(within(table).getByText("FEED-PKG-0007"));
    const side = screen.getByRole("complementary", { name: "Signature" });
    expect(within(side).getByText(/Blocks installing the two litellm releases/)).toBeInTheDocument();
    expect(within(side).getByLabelText("Pattern")).toHaveTextContent("pypi: litellm == 1.82.7 | 1.82.8");
    expect(within(side).getByText("AML.T0010 · LLM03")).toBeInTheDocument();
    expect(within(side).getByText("OSV · March 2026")).toBeInTheDocument();
    const hits = await within(side).findByRole("list", { name: "Recent hits" });
    expect(within(hits).getAllByRole("link")[0].getAttribute("href")).toMatch(/^\/traffic\?sel=/);
    expect(within(side).getByRole("link", { name: "All in Traffic →" })).toHaveAttribute("href", "/traffic?rule=FEED-PKG-0007");
  });

  it("a signature without hits says so", async () => {
    renderApp(<ThreatsScreen />, { searchParams: "?sel=FEED-URL-0031" });
    const side = await screen.findByRole("complementary", { name: "Signature" });
    expect(await within(side).findByText("No hits in the last 24 hours.")).toBeInTheDocument();
  });

  it("Sync now syncs the feed and reports the result inline", async () => {
    const before = feedStatus.last_sync_at;
    const { user } = renderApp(<ThreatsScreen />);
    await user.click(await screen.findByRole("button", { name: "Sync now" }));
    const box = await screen.findByText("Feed synced");
    expect(box.closest("[role=status]")).toHaveTextContent("Bundle 412 is active · 214 rules · checksum verified.");
    expect(feedStatus.last_sync_at).not.toBe(before);
  });

  it("Sync now shows an error inline", async () => {
    server.use(http.post(adminPath("/feed/sync"), () => HttpResponse.json({ detail: "feed server unreachable" }, { status: 502 })));
    const { user } = renderApp(<ThreatsScreen />);
    await user.click(await screen.findByRole("button", { name: "Sync now" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("feed server unreachable");
  });

  it("model files tab: results from the scanner and the file sidebar", async () => {
    const { user } = renderApp(<ThreatsScreen />);
    await user.click(await screen.findByRole("tab", { name: /Model files/ }));
    const table = await screen.findByRole("table", { name: "Model files" });
    expect(await within(table).findByText("finetune-v2.bin")).toBeInTheDocument();
    const row = within(table).getByText("finetune-v2.bin").closest("tr")!;
    expect(within(row).getByText("blocked")).toBeInTheDocument();
    expect(within(row).getByText("runs code when loaded (pickle)")).toBeInTheDocument();
    expect(within(within(table).getByText("qwen3.8-27b-instruct-q4_k_m.gguf").closest("tr")!).getByText("passed")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "+ Add rule" })).toBeNull();
  });

  it("model file sidebar: result, explanation, technical detail, sha256", async () => {
    const { user } = renderApp(<ThreatsScreen />, { searchParams: "?tab=files" });
    const table = await screen.findByRole("table", { name: "Model files" });
    await user.click(await within(table).findByText("finetune-v2.bin"));
    const side = screen.getByRole("complementary", { name: "Model file" });
    expect(within(side).getByText(/would run a shell command the moment someone loads it/)).toBeInTheDocument();
    expect(within(side).getByLabelText("Technical detail")).toHaveTextContent("GLOBAL os.system");
    expect(within(side).getByText("a4f1…0c77")).toBeInTheDocument();
    expect(within(side).getByText("ART-PICKLE-01")).toBeInTheDocument();
  });

  it("viewer: Sync now is read-only", async () => {
    renderApp(<ThreatsScreen />, { user: VIEWER });
    expect(await screen.findByRole("button", { name: "Sync now" })).toBeDisabled();
  });
});
