import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { formatAge, formatClock, formatCountdown, formatDay, formatNumber, formatTime, formatWhen } from "@/lib/format";
import { RelativeTime, TimeCell } from "./time";

const at = (h: number, m: number, s = 0, dayOffset = 0) => new Date(2026, 9, 3 + dayOffset, h, m, s);
const NOW = at(14, 5);

describe("format helpers", () => {
  it("formats times", () => {
    expect(formatTime(at(14, 3, 12))).toBe("14:03:12");
    expect(formatClock(at(9, 5))).toBe("09:05");
  });

  it("names the day", () => {
    expect(formatDay(at(14, 3), NOW)).toBe("today");
    expect(formatDay(at(16, 40, 0, -1), NOW)).toBe("yesterday");
    expect(formatDay(at(10, 12, 0, -2), NOW)).toBe("1 Oct");
    expect(formatWhen(at(16, 40, 0, -1), NOW)).toBe("yesterday 16:40");
  });

  it("formats ages", () => {
    expect(formatAge(at(14, 4, 40), NOW)).toBe("now");
    expect(formatAge(at(14, 3), NOW)).toBe("2 m");
    expect(formatAge(at(13, 27), NOW)).toBe("38 m");
    expect(formatAge(at(12, 5), NOW)).toBe("2 h");
    expect(formatAge(at(14, 5, 0, -3), NOW)).toBe("3 d");
  });

  it("formats countdowns and numbers", () => {
    expect(formatCountdown(at(14, 14, 40), NOW)).toBe("9:40");
    expect(formatCountdown(at(14, 0), NOW)).toBe("0:00");
    expect(formatNumber(1284)).toBe("1 284");
    expect(formatNumber(3.12)).toBe("3.12");
  });
});

describe("TimeCell", () => {
  it("shows mono time and today", () => {
    const iso = new Date().toISOString();
    render(<TimeCell iso={iso} />);
    expect(screen.getByText("today")).toBeInTheDocument();
    expect(screen.getByText(formatTime(iso))).toHaveClass("font-mono");
  });
});

describe("RelativeTime", () => {
  it("shows a compact age with the absolute time on hover", () => {
    const iso = new Date(Date.now() - 38 * 60_000).toISOString();
    render(<RelativeTime iso={iso} />);
    const el = screen.getByText("38 m");
    expect(el.tagName).toBe("TIME");
    expect(el).toHaveAttribute("title", expect.stringContaining("today"));
  });
});
