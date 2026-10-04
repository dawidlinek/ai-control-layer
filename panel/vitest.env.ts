/**
 * Vitest environment = the built-in jsdom, but keeping Node's own AbortController / AbortSignal.
 * Node's fetch (used by openapi-fetch and MSW) rejects jsdom's AbortSignal ("Expected signal to be an
 * instance of AbortSignal"), which breaks every TanStack Query request that passes `signal`.
 */
import { builtinEnvironments, type Environment } from "vitest/environments";

const env: Environment = {
  name: "jsdom-node-abort",
  transformMode: "web",
  async setup(global, options) {
    const { AbortController, AbortSignal } = global as unknown as typeof globalThis;
    const result = await builtinEnvironments.jsdom.setup(global, options);
    Object.assign(global, { AbortController, AbortSignal });
    return result;
  },
};

export default env;
