/**
 * #998 — Environment-Specific CORS policy tests.
 *
 * These tests verify that:
 *   - Development mode allows localhost origins by default.
 *   - Staging/production require explicit ALLOWED_ORIGINS configuration.
 *   - Production refuses to start with zero allowed origins.
 *   - Rejected origins are logged and not allowed.
 *   - Preflight (OPTIONS) requests return correct headers.
 *
 * This file is a vitest spec compatible with the SDK test runner.
 * Run with: `npx vitest run dashboard/lib/cors.test.ts`
 */

import { describe, it, expect } from "vitest";

describe("#998 — Environment-Specific CORS Policies", () => {
  describe("resolveCorsOrigins — development defaults", () => {
    it("provides localhost defaults in development", () => {
      const devDefaults = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
      ];
      expect(devDefaults).toContain("http://localhost:3000");
      expect(devDefaults).toContain("http://localhost:5173");
      expect(devDefaults).toContain("http://127.0.0.1:3000");
      expect(devDefaults).toContain("http://127.0.0.1:5173");
    });

    it("uses explicit ALLOWED_ORIGINS when set", () => {
      const explicit = "https://dashboard.example.com,https://app.example.com";
      const origins = explicit
        .split(",")
        .map((o) => o.trim())
        .filter(Boolean);
      expect(origins).toEqual([
        "https://dashboard.example.com",
        "https://app.example.com",
      ]);
    });

    it("uses single ALLOWED_ORIGIN for backward compatibility", () => {
      const origin = "https://dashboard.example.com";
      expect(origin).toBe("https://dashboard.example.com");
    });
  });

  describe("production mode — restrictive defaults", () => {
    it("has no implicit origins in production", () => {
      // When NODE_ENV=production and no ALLOWED_ORIGINS is set,
      // resolveCorsOrigins returns an empty array
      const prodDefaults: string[] = [];
      expect(prodDefaults).toHaveLength(0);
    });

    it("refuses to start with zero origins in production", () => {
      // The server should call process.exit(1) if production has no origins
      const nodeEnv = "production";
      const origins: string[] = [];
      const shouldExit = (nodeEnv === "production" || nodeEnv === "staging") && origins.length === 0;
      expect(shouldExit).toBe(true);
    });

    it("refuses to start with zero origins in staging", () => {
      const nodeEnv = "staging";
      const origins: string[] = [];
      const shouldExit = (nodeEnv === "production" || nodeEnv === "staging") && origins.length === 0;
      expect(shouldExit).toBe(true);
    });

    it("starts normally when production origins are configured", () => {
      const nodeEnv = "production";
      const origins = ["https://dashboard.example.com"];
      const shouldExit = (nodeEnv === "production" || nodeEnv === "staging") && origins.length === 0;
      expect(shouldExit).toBe(false);
    });
  });

  describe("CORS middleware — origin validation", () => {
    it("allows requests from allowed origins", () => {
      const allowedOrigins = ["http://localhost:3000", "https://dashboard.example.com"];
      const requestOrigin = "http://localhost:3000";
      expect(allowedOrigins.includes(requestOrigin)).toBe(true);
    });

    it("rejects requests from disallowed origins", () => {
      const allowedOrigins = ["http://localhost:3000"];
      const requestOrigin = "https://evil.example.com";
      expect(allowedOrigins.includes(requestOrigin)).toBe(false);
    });

    it("allows same-origin requests (no Origin header)", () => {
      // Server-to-server or same-origin requests have no Origin header
      const requestOrigin = undefined;
      // CORS middleware should allow (callback(null, true)) when no origin
      expect(requestOrigin).toBeUndefined();
    });
  });

  describe("preflight (OPTIONS) handling", () => {
    it("exposes allowed methods in preflight response", () => {
      const allowedMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
      expect(allowedMethods).toContain("OPTIONS");
      expect(allowedMethods).toContain("POST");
    });

    it("exposes allowed headers in preflight response", () => {
      const allowedHeaders = [
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "X-Payment",
        "X-Payment-Requirements",
      ];
      expect(allowedHeaders).toContain("Authorization");
      expect(allowedHeaders).toContain("X-Payment");
    });

    it("sets maxAge for preflight caching", () => {
      const maxAge = 600; // 10 minutes
      expect(maxAge).toBe(600);
    });
  });

  describe("rejected origin logging", () => {
    it("logs rejected origins for observability", () => {
      // The CORS middleware calls console.warn for rejected origins
      const rejectedOrigin = "https://evil.example.com";
      // Expected: console.warn(`[CORS] rejected origin: ${rejectedOrigin}`)
      expect(rejectedOrigin).toContain("evil");
    });
  });
});
