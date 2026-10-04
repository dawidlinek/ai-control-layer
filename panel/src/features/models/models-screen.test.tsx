import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { renderApp } from "@/test/render";
import { DEV_USER } from "@/lib/auth/user";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { connectors } from "@/mocks/db/models";
import { ModelsScreen } from "./models-screen";

const VIEWER = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"] };

describe("ModelsScreen", () => {
  it("shows the connector cards and the model table with the new lineup", async () => {
    renderApp(<ModelsScreen />);
    const gemini = await screen.findByRole("region", { name: "Gemini connector" });
    expect(within(gemini).getByText("healthy")).toBeInTheDocument();
    expect(within(gemini).getByText("820 ms")).toBeInTheDocument();
    expect(within(gemini).getByText("1.98 USD")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Local connector" })).getByText("1 562 GPU-s")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "+ Add connector" })).toBeDisabled();

    const table = await screen.findByRole("table", { name: "Models" });
    for (const id of ["gemini/flash", "gemini/pro", "local/qwen3.8-27b", "local/loan-memo", "local/bielik"]) {
      expect(within(table).getByText(id)).toBeInTheDocument();
    }
    // Embeddings and judge are guard models, listed separately and read-only.
    expect(within(table).queryByText("local/embed")).toBeNull();
    const guard = screen.getByRole("table", { name: "Guard models" });
    expect(within(guard).getByText("Injection classifier")).toBeInTheDocument();
    expect(within(guard).getByText("PII NER")).toBeInTheDocument();
    expect(within(guard).getByText("local/embed")).toBeInTheDocument();
    expect(within(guard).getByText("local/judge")).toBeInTheDocument();
  });

  it("opens the model sidebar with who can use it, how auto picks it and the model file", async () => {
    const { user } = renderApp(<ModelsScreen />);
    await user.click(await screen.findByText("gemini/flash"));
    const side = screen.getByRole("complementary", { name: "Model" });
    expect(within(side).getByText(/Google Gemini Flash/)).toBeInTheDocument();
    expect(within(side).getByText("smart")).toBeInTheDocument();
    expect(within(side).getByText("0.0003 / 0.0025 USD per 1k tokens in / out")).toBeInTheDocument();
    expect(within(side).getByRole("link", { name: /Jan Kowalski/ })).toHaveAttribute("href", "/grants?sel=g-0412");
    expect(within(side).getByText("41%")).toBeInTheDocument();
    expect(within(side).getByText("complexity up to 0.6, public or internal data")).toBeInTheDocument();
    expect(within(side).getByText("212")).toBeInTheDocument();
    expect(within(side).getByText(/no model file to scan/)).toBeInTheDocument();
    expect(within(side).getByRole("link", { name: "Edit in Policies" })).toHaveAttribute("href", "/policies?tab=yaml");
    expect(within(side).getByRole("button", { name: "Turn off model" })).toBeDisabled();
  });

  it("explains how auto picks Bielik: Polish legal text, a fixed detector, normal rules as the fallback", async () => {
    renderApp(<ModelsScreen />, { searchParams: "?sel=local/bielik" });
    const side = await screen.findByRole("complementary", { name: "Model" });
    expect(within(side).getByText(/A fixed detector decides, with no model call/)).toBeInTheDocument();
    expect(within(side).getByText(/Polish wording combined with legal vocabulary/)).toBeInTheDocument();
    expect(within(side).getByText(/auto uses the normal rules instead \(confidential data stays on local Qwen\)/)).toBeInTheDocument();
    expect(within(side).getByText("Polish legal text, fixed detector (≥ 0.50)")).toBeInTheDocument();
    expect(within(side).getByText("bielik")).toBeInTheDocument();
  });

  it("shows the scanned model file of a local model", async () => {
    renderApp(<ModelsScreen />, { searchParams: "?sel=local/qwen3.8-27b" });
    const side = await screen.findByRole("complementary", { name: "Model" });
    expect(await within(side).findByText(/qwen3.8-27b-instruct-q4_k_m.gguf · GGUF scan passed · sha256 3d0a…91c2/)).toBeInTheDocument();
    expect(within(side).getByText("all classes")).toBeInTheDocument();
  });

  it("kill switch: requires a reason, then switches Gemini off and says what it means", async () => {
    const { user } = renderApp(<ModelsScreen />);
    await user.click(await screen.findByRole("switch", { name: "Gemini on" }));
    const dialog = screen.getByRole("dialog", { name: "Switch off Gemini?" });
    await user.click(within(dialog).getByRole("button", { name: "Switch off Gemini" }));
    expect(await within(dialog).findByText(/Write a reason/)).toBeInTheDocument();
    expect(connectors.items.find((c) => c.id === "gemini")?.kill_switch).toBe(false);

    await user.type(within(dialog).getByLabelText("Reason (required)"), "provider incident");
    await user.click(within(dialog).getByRole("button", { name: "Switch off Gemini" }));

    const msg = await screen.findByText(/Gemini is switched off\./);
    expect(msg.closest("[role=status]")).toHaveTextContent(
      "Gemini is switched off. Requests for smart and smart-pro now go to local models and their answers are marked as degraded. Saved as policy v9.",
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    await waitFor(() => expect(screen.getByRole("switch", { name: "Gemini on" })).not.toBeChecked());
    expect(within(screen.getByRole("region", { name: "Gemini connector" })).getByText("off")).toBeInTheDocument();
    expect(await screen.findByText(/fast cloud · default for normal work · off/)).toBeInTheDocument();
  });

  it("kill switch: shows the error inline and keeps the reason", async () => {
    server.use(http.post(adminPath("/connectors/:id/kill-switch"), () => HttpResponse.json({ detail: "gateway busy" }, { status: 503 })));
    const { user } = renderApp(<ModelsScreen />);
    await user.click(await screen.findByRole("switch", { name: "Gemini on" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason (required)"), "test");
    await user.click(within(dialog).getByRole("button", { name: "Switch off Gemini" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("gateway busy");
    expect(within(dialog).getByLabelText("Reason (required)")).toHaveValue("test");
  });

  it("viewer: connector switches are read-only", async () => {
    renderApp(<ModelsScreen />, { user: VIEWER });
    expect(await screen.findByRole("switch", { name: "Gemini on" })).toBeDisabled();
    expect(screen.getByRole("switch", { name: "Local on" })).toBeDisabled();
  });

  it("shows an error state when models cannot be loaded", async () => {
    server.use(http.get(adminPath("/models"), () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    renderApp(<ModelsScreen />);
    expect(await screen.findByText("boom")).toBeInTheDocument();
  });
});
