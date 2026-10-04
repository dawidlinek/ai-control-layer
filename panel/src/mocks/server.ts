/** MSW server for Vitest (Node). Started in vitest.setup.ts. */
import { setupServer } from "msw/node";
import { handlers } from "./handlers";

export const server = setupServer(...handlers);
