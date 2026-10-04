import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Avatar, initialsOf } from "./avatar";

describe("initialsOf", () => {
  it.each([
    ["Katarzyna Wójcik", "KW"],
    ["k.wojcik", "KW"],
    ["research-bot", "RB"],
    ["Madonna", "MA"],
    ["  ", "?"],
  ])("%s -> %s", (name, expected) => {
    expect(initialsOf(name)).toBe(expected);
  });
});

describe("Avatar", () => {
  it("shows initials at the requested size", () => {
    const { container } = render(<Avatar name="Anna Nowak" size={38} />);
    const el = container.querySelector("[data-avatar]") as HTMLElement;
    expect(el).toHaveTextContent("AN");
    expect(el.style.width).toBe("38px");
    expect(screen.queryByRole("img")).not.toBeInTheDocument(); // decorative
  });
});
