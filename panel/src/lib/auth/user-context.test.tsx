import { screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderApp } from "@/test/render";
import { DEV_USER } from "./user";
import { RequireRole, useRole, useUser } from "./user-context";

function WhoAmI() {
  const user = useUser();
  const role = useRole();
  return (
    <p>
      {user.name} is {role}
    </p>
  );
}

describe("user context", () => {
  it("exposes the user and role", () => {
    renderApp(<WhoAmI />);
    expect(screen.getByText("Katarzyna Wójcik is admin")).toBeInTheDocument();
  });

  it("RequireRole shows children when the role is high enough", () => {
    renderApp(
      <RequireRole min="admin" fallback={<span>read only</span>}>
        <button>Publish</button>
      </RequireRole>,
    );
    expect(screen.getByRole("button", { name: "Publish" })).toBeInTheDocument();
    expect(screen.queryByText("read only")).not.toBeInTheDocument();
  });

  it("RequireRole hides admin actions from viewers (fallback or nothing)", () => {
    const viewer = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"] };
    renderApp(
      <>
        <RequireRole min="admin" fallback={<button disabled>Publish</button>}>
          <button>Publish</button>
        </RequireRole>
        <RequireRole min="analyst">
          <button>Assign to me</button>
        </RequireRole>
      </>,
      { user: viewer },
    );
    expect(screen.getByRole("button", { name: "Publish" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Assign to me" })).not.toBeInTheDocument();
  });

  it("dev mode: ?role= overrides the role and is remembered for the tab", async () => {
    window.history.replaceState(null, "", "/?role=viewer");
    const { unmount } = renderApp(<WhoAmI />, { devMode: true });
    await waitFor(() => expect(screen.getByText("Katarzyna Wójcik is viewer")).toBeInTheDocument());
    unmount();
    window.history.replaceState(null, "", "/traffic");
    renderApp(<WhoAmI />, { devMode: true });
    await waitFor(() => expect(screen.getByText("Katarzyna Wójcik is viewer")).toBeInTheDocument());
    window.sessionStorage.clear();
    window.history.replaceState(null, "", "/");
  });

  it("ignores ?role= outside dev mode", () => {
    window.history.replaceState(null, "", "/?role=viewer");
    renderApp(<WhoAmI />);
    expect(screen.getByText("Katarzyna Wójcik is admin")).toBeInTheDocument();
    window.history.replaceState(null, "", "/");
  });
});
