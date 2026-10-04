import { afterEach, describe, expect, it } from "vitest";
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
  afterEach(() => server.events.removeAllListeners());

  it("shows the feed status bar and the signatures", async () => {
    renderApp(<ThreatsScreen />);
    const bar = await screen.findByRole("region", { name: "Signature feed" });
    expect(within(bar).getByText("bundle 412 · 214 rules")).toBeInTheDocument();
    expect(within(bar).getByText("verified")).toBeInTheDocument();
    expect(within(bar).getByText("feed.corp:8080 · every 30 s")).toBeInTheDocument();

    const table = await screen.findByRole("table", { name: "Signatures" });
    for (const id of ["FEED-PKG-0007", "FEED-PKG-0012", "FEED-PKG-0142", "FEED-EXF-0044", "FEED-MCP-0009", "FEED-URL-0031", "FEED-CMD-0102"]) {
      expect(await within(table).findByText(id)).toBeInTheDocument();
    }
    expect(within(table).getByText("Blocks installing the two litellm releases that were published with a backdoor.")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Signatures/ })).toHaveTextContent("7");
    // The old demo note is gone: the list now comes from the admin API.
    expect(screen.queryByText(/does not list/)).toBeNull();
    // Hits come from the API's `hits_24h`: the litellm install was blocked by FEED-PKG-0007.
    const pkgRow = within(table).getByText("FEED-PKG-0007").closest("tr")!;
    expect(Number(pkgRow.querySelectorAll("td")[4].textContent)).toBeGreaterThan(0);

    expect(screen.getByRole("button", { name: "+ Add rule" })).toBeEnabled();
  });

  it("opens a signature: explanation, pattern, facts and recent hits linking to Traffic", async () => {
    const { user } = renderApp(<ThreatsScreen />);
    const table = await screen.findByRole("table", { name: "Signatures" });
    await user.click(await within(table).findByText("FEED-PKG-0007"));
    const side = screen.getByRole("complementary", { name: "Signature" });
    expect(within(side).getByText(/Blocks installing the two litellm releases/)).toBeInTheDocument();
    expect(within(side).getByText(/^\d+ · last /)).toBeInTheDocument();
    expect(within(side).getByLabelText("Pattern")).toHaveTextContent("pypi: litellm == 1.82.7 | 1.82.8");
    expect(within(side).getByText("AML.T0010 · LLM03")).toBeInTheDocument();
    expect(within(side).getByText("OSV · March 2026")).toBeInTheDocument();
    const hits = await within(side).findByRole("list", { name: "Recent hits" });
    expect(within(hits).getAllByRole("link")[0].getAttribute("href")).toMatch(/^\/traffic\?sel=/);
    // A tool call shows the gateway's tool_preview.
    expect(within(hits).getAllByRole("link")[0]).toHaveTextContent("bash: pip install litellm==1.82.8");
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

  it("viewer: Sync now and + Add rule are read-only", async () => {
    renderApp(<ThreatsScreen />, { user: VIEWER });
    expect(await screen.findByRole("button", { name: "Sync now" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "+ Add rule" })).toBeDisabled();
  });

  it("search and the Looks at filter go to the API as query params", async () => {
    const urls: string[] = [];
    server.events.on("request:start", ({ request }) => {
      if (request.url.includes("/feed/signatures")) urls.push(request.url);
    });
    const { user } = renderApp(<ThreatsScreen />, { urlMemory: true });
    const table = await screen.findByRole("table", { name: "Signatures" });
    await within(table).findByText("FEED-CMD-0102");

    await user.type(screen.getByRole("searchbox", { name: "Search signatures" }), "torchtriton");
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Signatures" })).queryByText("FEED-PKG-0007")).toBeNull());
    expect(within(screen.getByRole("table", { name: "Signatures" })).getByText("FEED-PKG-0142")).toBeInTheDocument();
    expect(urls.some((u) => new URL(u).searchParams.get("q") === "torchtriton")).toBe(true);
    await waitFor(() => expect(screen.getByRole("tab", { name: /Signatures/ })).toHaveTextContent("1"));

    await user.clear(screen.getByRole("searchbox", { name: "Search signatures" }));
    await user.click(screen.getByRole("button", { name: "Looks at" }));
    await user.click(await screen.findByRole("menuitemcheckbox", { name: "shell command" }));
    await waitFor(() => expect(urls.some((u) => new URL(u).searchParams.get("target") === "command")).toBe(true));
    const filtered = await screen.findByRole("table", { name: "Signatures" });
    await waitFor(() => expect(within(filtered).queryByText("FEED-PKG-0007")).toBeNull());
    expect(within(filtered).getByText("FEED-CMD-0102")).toBeInTheDocument();
  });

  it("says how many signatures were loaded when the list is cut off", async () => {
    server.use(http.get(adminPath("/feed/signatures"), () => HttpResponse.json([], { headers: { "X-Total-Count": "812" } })));
    renderApp(<ThreatsScreen />);
    expect(await screen.findByText(/Showing 0 of 812 signatures/)).toBeInTheDocument();
  });

  describe("Add rule (F11)", () => {
    async function openForm() {
      const ctx = renderApp(<ThreatsScreen />, { urlMemory: true });
      await ctx.user.click(await screen.findByRole("button", { name: "+ Add rule" }));
      const side = await screen.findByRole("complementary", { name: "New rule" });
      const form = within(side).getByRole("form", { name: "Add rule" });
      // The id suggestion waits for the signatures list.
      await waitFor(() => expect(within(form).getByLabelText("Rule ID")).toHaveValue("FEED-LOCAL-0001"));
      return { ...ctx, side, form: within(form) };
    }

    it("publishes a package rule, reports bundle and sync inline, and the list and feed bar update", async () => {
      const { user, form, side } = await openForm();
      await user.type(form.getByLabelText("What it catches"), "Blocks the fake torchtriton package.");
      await user.type(form.getByLabelText("Package"), "torchtriton-fake");
      await user.click(form.getByRole("button", { name: "Publish rule" }));

      const box = await within(side).findByText("Added FEED-LOCAL-0001");
      expect(box.closest("[role=status]")).toHaveTextContent("feed bundle v413 · synced");
      // The next id is suggested for the next rule.
      await waitFor(() => expect(form.getByLabelText("Rule ID")).toHaveValue("FEED-LOCAL-0002"));
      expect(await screen.findByText("bundle 413 · 215 rules")).toBeInTheDocument();
      const table = screen.getByRole("table", { name: "Signatures" });
      expect(await within(table).findByText("FEED-LOCAL-0001")).toBeInTheDocument();
      expect(within(table).getByText("Blocks the fake torchtriton package.")).toBeInTheDocument();
    });

    it("sends the target-specific fields: command rules need a pattern and may name tools", async () => {
      let body: Record<string, unknown> | undefined;
      server.events.on("request:start", async ({ request }) => {
        if (request.method === "POST" && request.url.endsWith("/feed/rules")) body = (await request.clone().json()) as Record<string, unknown>;
      });
      const { user, form } = await openForm();
      await user.click(form.getByRole("combobox", { name: "Looks at" }));
      await user.click(await screen.findByRole("option", { name: "Shell command" }));
      await user.type(form.getByLabelText("What it catches"), "Blocks curl piped into sh.");
      await user.click(form.getByRole("button", { name: "Publish rule" }));
      expect(await form.findByText("Enter the pattern.")).toBeInTheDocument();
      await user.type(form.getByLabelText("Pattern (regular expression)"), "curl .* sh");
      await user.type(form.getByLabelText("Only for tools"), "*bash*, *shell*");
      await user.click(form.getByRole("button", { name: "Publish rule" }));
      await screen.findByText("Added FEED-LOCAL-0001");
      await waitFor(() => expect(body).toBeDefined());
      expect(body).toMatchObject({
        id: "FEED-LOCAL-0001",
        target: "command",
        pattern: "curl .* sh",
        tools: ["*bash*", "*shell*"],
        severity: "high",
        action: "block",
        sync_now: true,
      });
      expect(body).not.toHaveProperty("package");
    });

    it("validates the id and the description before sending", async () => {
      const { user, form } = await openForm();
      await user.clear(form.getByLabelText("Rule ID"));
      await user.type(form.getByLabelText("Rule ID"), "feed local");
      await user.click(form.getByRole("button", { name: "Publish rule" }));
      expect(await form.findByText(/Use capitals, digits and dashes/)).toBeInTheDocument();
      expect(form.getByText(/Say what the rule catches/)).toBeInTheDocument();
    });

    it("409: the id is taken, shown under the id field", async () => {
      const { user, form } = await openForm();
      await user.clear(form.getByLabelText("Rule ID"));
      await user.type(form.getByLabelText("Rule ID"), "FEED-PKG-0007");
      await user.type(form.getByLabelText("What it catches"), "Duplicate of an existing rule.");
      await user.type(form.getByLabelText("Package"), "litellm");
      await user.click(form.getByRole("button", { name: "Publish rule" }));
      expect(await form.findByText(/already exists/)).toBeInTheDocument();
      expect(form.getByLabelText("Rule ID")).toHaveAttribute("aria-invalid", "true");
    });

    it.each([
      [422, "pattern does not compile", "The rule is not valid"],
      [502, "feed server unreachable", "The feed server did not accept the rule"],
      [503, "FEED_ADMIN_URL is not set", "Rule editing is not set up"],
    ])("%i: shows the detail in an inline error box", async (status, detail, title) => {
      server.use(http.post(adminPath("/feed/rules"), () => HttpResponse.json({ detail }, { status })));
      const { user, form, side } = await openForm();
      await user.type(form.getByLabelText("What it catches"), "Some rule that the server refuses.");
      await user.type(form.getByLabelText("Package"), "whatever");
      await user.click(form.getByRole("button", { name: "Publish rule" }));
      const box = await within(side).findByRole("alert");
      expect(box).toHaveTextContent(title);
      expect(box).toHaveTextContent(detail);
    });

    it("without 'sync now' the box says the gateway has not loaded the rule yet", async () => {
      const { user, form, side } = await openForm();
      await user.click(form.getByRole("checkbox", { name: "Ask the gateway to sync now" }));
      await user.type(form.getByLabelText("What it catches"), "A rule that waits for the next poll.");
      await user.type(form.getByLabelText("Package"), "slowpkg");
      await user.click(form.getByRole("button", { name: "Publish rule" }));
      const box = await within(side).findByText("Added FEED-LOCAL-0001");
      expect(box.closest("[role=status]")).toHaveTextContent("not synced yet");
    });

    it("viewers cannot open the form", async () => {
      renderApp(<ThreatsScreen />, { user: VIEWER, searchParams: "?sel=new" });
      await screen.findByRole("table", { name: "Signatures" });
      expect(screen.queryByRole("form", { name: "Add rule" })).toBeNull();
    });
  });
});
