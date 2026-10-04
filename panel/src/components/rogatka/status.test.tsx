import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { EmptyState, ErrorState, LoadingRows, StatusBox } from "./status";

describe("StatusBox", () => {
  it.each(["success", "info", "warning"] as const)("%s is announced politely", (variant) => {
    render(<StatusBox variant={variant} title="v9 is live">Saved as policy v9.</StatusBox>);
    const box = screen.getByRole("status");
    expect(box).toHaveAttribute("data-variant", variant);
    expect(box).toHaveTextContent("v9 is live");
    expect(box).toHaveTextContent("Saved as policy v9.");
  });

  it("error is an alert", () => {
    render(<StatusBox variant="error">Publish failed</StatusBox>);
    expect(screen.getByRole("alert")).toHaveTextContent("Publish failed");
  });

  it("uses the matching decision colour", () => {
    render(<StatusBox variant="success">ok</StatusBox>);
    expect(screen.getByRole("status").style.getPropertyValue("--c")).toBe("var(--dec-allow)");
  });
});

describe("EmptyState", () => {
  it("renders title, message and action", () => {
    render(<EmptyState title="Nothing assigned to you here." action={<button>Reset</button>}>Try another filter.</EmptyState>);
    expect(screen.getByText("Nothing assigned to you here.")).toBeInTheDocument();
    expect(screen.getByText("Try another filter.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reset" })).toBeInTheDocument();
  });
});

describe("ErrorState", () => {
  it("shows the error and retries", async () => {
    const onRetry = vi.fn();
    render(<ErrorState error={new Error("Gateway unreachable")} onRetry={onRetry} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Gateway unreachable");
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalled();
  });
});

describe("LoadingRows", () => {
  it("renders skeleton rows with a status role", () => {
    const { container } = render(<LoadingRows rows={3} />);
    expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
    expect(container.querySelectorAll(".animate-pulse").length).toBe(12);
  });
});
