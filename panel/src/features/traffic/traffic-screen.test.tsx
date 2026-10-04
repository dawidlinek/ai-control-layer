import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { DEV_USER } from "@/lib/auth/user";
import { renderApp } from "@/test/render";
import { TrafficScreen } from "./traffic-screen";
import { WithUrl } from "./test-url";

type UrlEvent = { queryString: string; searchParams: URLSearchParams };

function setup(search = "", opts: Parameters<typeof renderApp>[1] = {}) {
  const onUrlUpdate = vi.fn<(e: UrlEvent) => void>();
  const r = renderApp(
    <WithUrl search={search} onUrlUpdate={onUrlUpdate}>
      <TrafficScreen />
    </WithUrl>,
    { pathname: "/traffic", ...opts },
  );
  const lastUrl = () => onUrlUpdate.mock.calls.at(-1)?.[0].searchParams ?? new URLSearchParams(search);
  return { ...r, onUrlUpdate, lastUrl };
}

const table = () => screen.getByRole("table", { name: "Events" });
const rowOf = (id: string) => table().querySelector<HTMLElement>(`[data-row-id="${id}"]`);

async function waitForRows() {
  await waitFor(() => expect(rowOf("evt_8f3a2c")).not.toBeNull());
}

describe("Traffic", () => {
  it("lists past requests with who, point, model, decisions, rule and the session label chip", async () => {
    setup();
    expect(screen.getByRole("heading", { level: 1, name: "Traffic" })).toBeInTheDocument();
    await waitForRows();
    const anna = within(rowOf("evt_8f3a2c")!);
    await waitFor(() => expect(anna.getByText("Anna Nowak")).toBeInTheDocument());
    expect(anna.getByText("LibreChat · credit-analysts")).toBeInTheDocument();
    expect(anna.getByText("prompt")).toBeInTheDocument();
    expect(anna.getByText("local/qwen3.8-27b")).toBeInTheDocument();
    expect(anna.getByText("pseudonymise")).toBeInTheDocument();
    expect(anna.getByText("route_local")).toBeInTheDocument();
    expect(anna.getByText("SEC-PII-01")).toBeInTheDocument();
    expect(anna.getByText("today")).toBeInTheDocument();
    expect(anna.getByLabelText(/Session confidential since \d\d:\d\d · local only/)).toBeInTheDocument();

    const jan = within(rowOf("evt_9b21e4")!);
    expect(jan.getByText("tool call")).toBeInTheDocument();
    expect(jan.getByText("require_approval")).toBeInTheDocument();
    expect(within(rowOf("evt_8c9911")!).getByText("tool list")).toBeInTheDocument();
    expect(within(rowOf("evt_8c9911")!).getByText("MCP docs-search")).toBeInTheDocument();
    // An allowed request in a normal session has no label chip.
    expect(rowOf("evt_8d5e10")!.querySelector("[data-session-label]")).toBeNull();
    // Highlighted time range, no live badge.
    expect(screen.getByRole("button", { name: /Last 24 hours/ })).toBeInTheDocument();
    expect(screen.queryByText(/live/i)).not.toBeInTheDocument();
  });

  it("puts the Decision filter in the URL and shows only matching rows", async () => {
    const { user, lastUrl } = setup();
    await waitForRows();
    await user.click(screen.getByRole("button", { name: "Decision" }));
    await user.click(await screen.findByRole("menuitemcheckbox", { name: "block" }));
    await user.keyboard("{Escape}");
    await waitFor(() => expect(lastUrl().get("decision")).toBe("block"));
    await waitFor(() => expect(rowOf("evt_8f3a2c")).toBeNull());
    expect(rowOf("evt_9a0c33")).not.toBeNull();
    expect(rowOf("evt_8c9911")).not.toBeNull();
  });

  it("puts the time range, Who and Point filters in the URL", async () => {
    const { user, lastUrl } = setup();
    await waitForRows();
    await user.click(screen.getByRole("button", { name: /Last 24 hours/ }));
    await user.click(await screen.findByRole("menuitemcheckbox", { name: "Last 7 days" }));
    await waitFor(() => expect(lastUrl().get("range")).toBe("7d"));
    expect(screen.getByRole("button", { name: /Last 7 days/ })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Point" }));
    await user.click(await screen.findByRole("menuitemcheckbox", { name: "tool call" }));
    await user.keyboard("{Escape}");
    await waitFor(() => expect(lastUrl().get("point")).toBe("tool_call"));
    await waitFor(() => expect(rowOf("evt_8f3a2c")).toBeNull());
    expect(rowOf("evt_9b21e4")).not.toBeNull();

    await user.click(screen.getByRole("button", { name: "Who" }));
    await user.click(await screen.findByRole("menuitemcheckbox", { name: "Jan Kowalski" }));
    await waitFor(() => expect(lastUrl().get("who")).toBe("j.kowalski"));
    await waitFor(() => expect(rowOf("evt_8e77a2")).toBeNull()); // Anna's bash call
    expect(rowOf("evt_9a0c33")).not.toBeNull();
  });

  it("searches rule, trace id or text and writes q to the URL", async () => {
    const { user, lastUrl } = setup();
    await waitForRows();
    await user.type(screen.getByRole("searchbox", { name: "Filter events" }), "litellm");
    await waitFor(() => expect(lastUrl().get("q")).toBe("litellm"));
    await waitFor(() => expect(rowOf("evt_8f3a2c")).toBeNull());
    expect(rowOf("evt_9a0c33")).not.toBeNull();
  });

  it("starts from the URL filters (rule id search, data class)", async () => {
    setup("?q=SEC-FLOW-01");
    await waitFor(() => expect(rowOf("evt_9b21e4")).not.toBeNull());
    expect(table().querySelectorAll("tbody tr")).toHaveLength(1);
  });

  it("Hide allowed removes allowed requests and is kept in the URL", async () => {
    const { user, lastUrl } = setup();
    await waitForRows();
    expect(rowOf("evt_8d5e10")).not.toBeNull();
    await user.click(screen.getByRole("switch", { name: "Hide allowed" }));
    await waitFor(() => expect(lastUrl().get("hide")).toBe("true"));
    await waitFor(() => expect(rowOf("evt_8d5e10")).toBeNull());
    expect(rowOf("evt_8b6f55")).not.toBeNull(); // monitor stays
    expect(table().querySelectorAll('[data-decision="allow"]')).toHaveLength(0);
  });

  it("pages with the before_seq cursor", async () => {
    const seen: (string | null)[] = [];
    server.events.on("request:start", ({ request }) => {
      const u = new URL(request.url);
      if (u.pathname.endsWith("/admin/v1/events")) seen.push(u.searchParams.get("before_seq"));
    });
    const { user, lastUrl } = setup();
    await waitForRows();
    expect(table().querySelectorAll("tbody tr")).toHaveLength(25);
    await user.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(lastUrl().get("page")).toBe("2"));
    await waitFor(() => expect(rowOf("evt_8f3a2c")).toBeNull());
    expect(seen.some((s) => s !== null)).toBe(true);
    await user.click(screen.getByRole("button", { name: "Previous page" }));
    await waitForRows();
    server.events.removeAllListeners();
  });

  it("opens the trace sidebar on row click and closes it with ×", async () => {
    const { user, lastUrl } = setup();
    await waitForRows();
    await user.click(within(rowOf("evt_8f3a2c")!).getByText("prompt"));
    await waitFor(() => expect(lastUrl().get("sel")).toBe("tr_8f3a2c"));
    const aside = await screen.findByRole("complementary", { name: "Trace" });
    expect(within(aside).getByText("tr_8f3a2c")).toBeInTheDocument();
    expect(await within(aside).findByText(/contained a PESEL, an IBAN and a name/)).toBeInTheDocument();
    expect(rowOf("evt_8f3a2c")).toHaveAttribute("aria-selected", "true");
    await user.click(within(aside).getByRole("button", { name: "Close trace" }));
    await waitFor(() => expect(screen.queryByRole("complementary", { name: "Trace" })).not.toBeInTheDocument());
    expect(lastUrl().get("sel")).toBeNull();
  });

  it("opens from a deep link and closes with Esc", async () => {
    const { user } = setup("?sel=tr_9a0c33");
    const aside = await screen.findByRole("complementary", { name: "Trace" });
    expect(await within(aside).findByText(/known backdoored release/)).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("complementary", { name: "Trace" })).not.toBeInTheDocument());
  });

  it("shows an error state when the list cannot be loaded", async () => {
    server.use(http.get(adminPath("/events"), () => HttpResponse.json({ detail: "audit store unavailable" }, { status: 503 })));
    setup();
    expect(await screen.findByText("audit store unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("shows an empty state when nothing matches", async () => {
    setup("?q=nothing-matches-this");
    expect(await screen.findByText("No requests match these filters")).toBeInTheDocument();
  });

  it("hides Add to incident from viewers", async () => {
    setup("?sel=tr_8f3a2c", { user: { ...DEV_USER, role: "viewer", roles: ["acl-viewer"] } });
    const aside = await screen.findByRole("complementary", { name: "Trace" });
    expect(await within(aside).findByRole("button", { name: "Replay with live policy" })).toBeDisabled();
    expect(within(aside).queryByRole("button", { name: "Add to incident" })).not.toBeInTheDocument();
  });
});
