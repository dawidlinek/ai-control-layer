import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { secondsUntil, useNow } from "./use-now";

describe("useNow", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("ticks every interval", () => {
    const { result } = renderHook(() => useNow(1000));
    const first = result.current;
    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(result.current - first).toBeGreaterThanOrEqual(3000);
  });

  it("does not tick while inactive", () => {
    const { result } = renderHook(() => useNow(1000, false));
    const first = result.current;
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(result.current).toBe(first);
  });
});

describe("secondsUntil", () => {
  it("is negative once passed", () => {
    const now = Date.parse("2026-01-01T10:00:00Z");
    expect(secondsUntil("2026-01-01T10:00:30Z", now)).toBe(30);
    expect(secondsUntil("2026-01-01T09:59:00Z", now)).toBe(-60);
  });
});
