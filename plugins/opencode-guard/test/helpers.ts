import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { loadConfig, type GuardConfig } from "../src/config.js";

export function testConfig(overrides: Record<string, unknown> = {}): GuardConfig {
  return loadConfig(
    {
      gatewayUrl: "http://gateway.test:8000",
      issuer: "http://localhost:8180/realms/acl",
      oidcBaseUrl: "http://keycloak.test:8080/realms/acl",
      deviceId: "dev-test-0001",
      approvalPollMs: 1,
      approvalTimeoutMs: 1000,
      ...overrides,
    },
    {},
  );
}

export interface Recorded {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export type Handler = (req: Recorded, res: ServerResponse) => void;

export interface TestServer {
  url: string;
  requests: Recorded[];
  close(): Promise<void>;
  setHandler(h: Handler): void;
}

export async function startServer(handler: Handler): Promise<TestServer> {
  let current = handler;
  const requests: Recorded[] = [];
  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const rec: Recorded = {
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      requests.push(rec);
      current(rec, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    setHandler: (h) => {
      current = h;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

export function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

export const DECIDE_OK = {
  decision_id: "dec_1",
  trace_id: "trace_1",
  action: "allow",
  rule_ids: [],
  reason: "",
  policy_version: "v1",
};
