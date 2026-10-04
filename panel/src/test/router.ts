import { vi } from "vitest";

/** Stand-in for `next/navigation` in unit tests (mocked globally in vitest.setup.ts). */
export const router = {
  push: vi.fn(),
  replace: vi.fn(),
  back: vi.fn(),
  forward: vi.fn(),
  refresh: vi.fn(),
  prefetch: vi.fn(),
};

let pathname = "/";
export const setPathname = (p: string) => {
  pathname = p;
};

export const navigationMock = {
  usePathname: () => pathname,
  useRouter: () => router,
  useSearchParams: () => new URLSearchParams(),
  redirect: vi.fn(),
  notFound: vi.fn(),
};
