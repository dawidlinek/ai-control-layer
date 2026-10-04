import { describe, expect, it } from "vitest";
import { decodeJwtPayload, hasRole, parseRole, realmRolesFromAccessToken, roleFromRealmRoles } from "./roles";

function jwt(payload: object) {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none" })}.${b64(payload)}.sig`;
}

describe("roleFromRealmRoles", () => {
  it("picks the highest panel role", () => {
    expect(roleFromRealmRoles(["offline_access", "acl-viewer", "acl-admin"])).toBe("admin");
    expect(roleFromRealmRoles(["acl-viewer", "acl-analyst"])).toBe("analyst");
    expect(roleFromRealmRoles(["acl-viewer"])).toBe("viewer");
  });
  it("returns null without any panel role", () => {
    expect(roleFromRealmRoles(["offline_access"])).toBeNull();
    expect(roleFromRealmRoles([])).toBeNull();
    expect(roleFromRealmRoles(undefined)).toBeNull();
  });
});

describe("hasRole", () => {
  it("orders admin > analyst > viewer", () => {
    expect(hasRole("admin", "analyst")).toBe(true);
    expect(hasRole("analyst", "admin")).toBe(false);
    expect(hasRole("viewer", "viewer")).toBe(true);
    expect(hasRole(null, "viewer")).toBe(false);
  });
});

describe("parseRole", () => {
  it("accepts only the three roles", () => {
    expect(parseRole("viewer")).toBe("viewer");
    expect(parseRole("root")).toBeNull();
    expect(parseRole(null)).toBeNull();
  });
});

describe("token claims", () => {
  it("reads realm roles from an access token", () => {
    const token = jwt({ realm_access: { roles: ["acl-analyst", "x"] } });
    expect(realmRolesFromAccessToken(token)).toEqual(["acl-analyst", "x"]);
  });
  it("tolerates garbage", () => {
    expect(decodeJwtPayload("nope")).toEqual({});
    expect(realmRolesFromAccessToken(undefined)).toEqual([]);
  });
  it("decodes non-ASCII claims", () => {
    expect(decodeJwtPayload(jwt({ name: "Katarzyna Wójcik" }))).toEqual({ name: "Katarzyna Wójcik" });
  });
});
