import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, vi } from "vitest";
import { server } from "@/mocks/server";
import { resetMockDb } from "@/mocks/db/registry";

// `next/navigation` has no router outside Next: use the stand-in from src/test/router.ts.
vi.mock("next/navigation", async () => (await import("@/test/router")).navigationMock);

// jsdom gaps that Radix UI and layout code touch.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;
Element.prototype.scrollIntoView ??= () => {};
Element.prototype.hasPointerCapture ??= () => false;
Element.prototype.setPointerCapture ??= () => {};
Element.prototype.releasePointerCapture ??= () => {};
window.matchMedia ??= ((query: string) => ({
  matches: false,
  media: query,
  onchange: null,
  addEventListener() {},
  removeEventListener() {},
  addListener() {},
  removeListener() {},
  dispatchEvent: () => false,
})) as typeof window.matchMedia;

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  vi.clearAllMocks();
  cleanup();
  server.resetHandlers();
  resetMockDb();
  document.documentElement.removeAttribute("data-theme");
  try {
    window.localStorage.clear();
  } catch {
    /* ignore */
  }
  document.cookie = "rogatka-theme=; max-age=0; path=/";
});
afterAll(() => server.close());
