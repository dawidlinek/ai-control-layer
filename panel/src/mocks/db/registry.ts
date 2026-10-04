/**
 * Every mock-db domain file calls `registerReset(reset)` once so tests can restore the seed data
 * with `resetMockDb()` (done after each test in vitest.setup.ts).
 */
const resets: Array<() => void> = [];

export function registerReset(fn: () => void): void {
  resets.push(fn);
}

export function resetMockDb(): void {
  for (const fn of resets) fn();
}

/** Seed a mutable array in place so handlers and tests keep a stable reference. */
export function seeded<T>(seed: () => T[]): { items: T[]; reset: () => void } {
  const items = seed();
  const reset = () => {
    items.splice(0, items.length, ...seed());
  };
  registerReset(reset);
  return { items, reset };
}
