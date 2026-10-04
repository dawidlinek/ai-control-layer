import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Self-contained server for the Docker image (panel/Dockerfile).
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  // Always inline the mock flag (empty when unset) so the bundler drops the whole MSW layer from normal builds.
  env: { NEXT_PUBLIC_API_MOCKING: process.env.NEXT_PUBLIC_API_MOCKING ?? "" },
};

export default nextConfig;
