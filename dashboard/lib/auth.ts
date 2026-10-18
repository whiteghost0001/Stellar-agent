import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { Keypair, TransactionBuilder, Networks, StrKey } from "@stellar/stellar-sdk";

const nonceStore = new Map<string, { nonce: string; timestamp: number }>();
const NONCE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const MAX_CLOCK_SKEW_SECONDS = 300; // Allow 5 minutes clock skew for signature timestamps

function cleanupExpiredNonces(now = Date.now()): void {
  for (const [key, value] of nonceStore.entries()) {
    if (now - value.timestamp > NONCE_EXPIRY_MS) {
      nonceStore.delete(key);
    }
  }
}

export function generateNonce(publicKey: string): string {
  const nonce = crypto.randomBytes(32).toString("hex");
  nonceStore.set(publicKey, { nonce, timestamp: Date.now() });
  cleanupExpiredNonces();
  return nonce;
}

/**
The client should sign the nonce with their Freighter wallet.
 *
 * @param publicKey - The signer's public key
 * @param nonce - The challenge nonce (from generateNonce)
 * @param signature - The XDR of a transaction signed by the nonce
 * @returns true if signature is valid and nonce hasn't expired
 */
export function verifyNonceSignature(publicKey: string, nonce: string, signature: string): boolean {
  try {
    // Verify public key format
    if (!StrKey.isValidEd25519PublicKey(publicKey)) {
      return false;
    }

    const storedNonce = nonceStore.get(publicKey);
    if (!storedNonce) {
      return false;
    }

    // Check nonce hasn't expired
    if (Date.now() - storedNonce.timestamp > NONCE_EXPIRY_MS) {
      nonceStore.delete(publicKey);
      return false;
    }

    // Verify nonce matches
    if (storedNonce.nonce !== nonce) {
      return false;
    }

    // Verify the signature by checking if the provided XDR was signed by this publicKey
    try {
      const tx = TransactionBuilder.fromXDR(signature, Networks.TESTNET);
      const keypair = Keypair.fromPublicKey(publicKey);

      const hasNonceOperation = tx.operations.some(
        (operation) =>
          operation.type === "manageData" &&
          operation.name === "marc-auth" &&
          operation.value?.toString() === nonce,
      );
      if (!hasNonceOperation) return false;

      // Check if the transaction is signed by the claimed public key
      // by attempting to verify the signature
      const txHash = tx.hash();
      let isValidSignature = false;

      for (const sig of tx.signatures) {
        try {
          // Verify signature using the public key
          if (keypair.verify(txHash, sig.signature())) {
            isValidSignature = true;
            break;
          }
        } catch {
          // Continue to next signature
        }
      }

      if (isValidSignature) {
        // Invalidate this nonce so it can't be reused
        nonceStore.delete(publicKey);
        return true;
      }
    } catch {
      return false;
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Session token for authenticated users.
 * Tracks verified wallet ownership.
 */
interface AuthSession {
  publicKey: string;
  timestamp: number;
  expiresAt: number;
}

const SESSION_DURATION_MS = 30 * 60 * 1000; // 30 minutes
const sessionStore = new Map<string, AuthSession>();

function cleanupExpiredSessions(now = Date.now()): void {
  for (const [token, session] of sessionStore.entries()) {
    if (now > session.expiresAt) {
      sessionStore.delete(token);
    }
  }
}

/**
 * Create an authenticated session after successful wallet verification.
 */
export function createSession(publicKey: string): string {
  cleanupExpiredSessions();
  const token = crypto.randomBytes(32).toString("hex");
  sessionStore.set(token, {
    publicKey,
    timestamp: Date.now(),
    expiresAt: Date.now() + SESSION_DURATION_MS,
  });
  return token;
}

/**
 * Verify and get the public key from a session token.
 */
export function verifySession(token: string): string | null {
  const session = sessionStore.get(token);
  if (!session) {
    return null;
  }

  if (Date.now() > session.expiresAt) {
    sessionStore.delete(token);
    return null;
  }

  return session.publicKey;
}

/**
 * Invalidate a session token.
 */
export function invalidateSession(token: string): void {
  sessionStore.delete(token);
}

export function refreshSession(token: string): string | null {
  const publicKey = verifySession(token);
  if (!publicKey) return null;
  sessionStore.delete(token);
  return createSession(publicKey);
}

/**
 * Middleware: Require valid authentication token.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) {
    res.status(401).json({ error: "Missing authentication token" });
    return;
  }

  const publicKey = verifySession(token);
  if (!publicKey) {
    res.status(401).json({ error: "Invalid or expired token" });
    return;
  }

  // Attach public key to request for later use
  (req as any).walletAddress = publicKey;
  next();
}

// ── #997: Separate Administrative Operations from Read-Only Access ───────────
//
// The dashboard API serves two distinct consumer classes:
//
//   1. Read-only consumers — public endpoints that list agents, jobs,
//      balances, and stats. No authentication or wallet matching required.
//      These routes are safe to expose to any caller (subject to CORS).
//
//   2. Administrative consumers — mutating endpoints that create jobs,
//      submit deliverables, approve, cancel, build transactions, or
//      submit signed XDR. These require wallet authentication and
//      ownership matching so a caller cannot act on behalf of another
//      wallet.
//
// The `ADMIN_WALLETS` env var is a comma-separated allow-list of Stellar
// public keys that are permitted to perform administrative operations even
// outside DEMO_MODE. When unset, any authenticated wallet matching the
// requested resource is treated as an admin (dashboard-owner model).
//
// In DEMO_MODE, the "buyer" and "seller" demo wallets bypass the session
// token requirement so the dashboard works without Freighter. This is safe
// because DEMO_MODE is explicitly opt-in and uses fixed testnet keypairs.

import { getKeypair, DEMO_MODE } from "./config.js";

/**
 * Set of admin wallet public keys loaded from the `ADMIN_WALLETS` env var.
 * Used by {@link requireAdmin} to enforce route-level authorization (#997).
 */
const ADMIN_WALLETS: Set<string> = new Set(
  (process.env.ADMIN_WALLETS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
);

/**
 * Whether admin wallet allow-listing is enabled.
 * When `true`, only wallets in {@link ADMIN_WALLETS} may call admin routes.
 * When `false`, any authenticated wallet is an admin (dashboard-owner model).
 */
const ADMIN_ALLOWLIST_ENABLED = ADMIN_WALLETS.size > 0;

/**
 * Route-level authorization boundary for administrative (mutating) operations.
 *
 * #997 — privileged routes must:
 *   1. Require a valid authenticated session (not anonymous), OR operate in
 *      DEMO_MODE with a recognized demo wallet alias ("buyer" / "seller").
 *   2. Match the requested wallet to the session wallet (no acting on behalf
 *      of another account).
 *   3. If an admin allow-list is configured via `ADMIN_WALLETS`, the session
 *      wallet must appear in it.
 *
 * Unauthorized access is rejected with 401 (unauthenticated) or 403
 * (authenticated but not permitted).
 *
 * @example
 * ```ts
 * app.post("/api/jobs/create", requireAdmin, handler);
 * ```
 *
 * Permission requirement (documented for each admin route):
 *   - Requires: `admin` — wallet must be authenticated and match the
 *     requested resource. If `ADMIN_WALLETS` is set, the wallet must be
 *     in the allow-list.
 */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  // 1. DEMO_MODE shortcut: recognize "buyer"/"seller" wallet aliases.
  if (DEMO_MODE) {
    const wallet = req.body?.wallet || req.body?.publicKey;
    if (wallet === "buyer" || wallet === "seller") {
      try {
        (req as any).walletAddress = getKeypair(wallet).publicKey();
        next();
        return;
      } catch {
        // fall through to normal auth
      }
    }
  }

  // 2. Must be authenticated.
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) {
    res.status(401).json({
      error: "Authentication required for administrative operations. Use /api/auth/challenge and /api/auth/verify.",
      permission: "admin",
    });
    return;
  }

  const publicKey = verifySession(token);
  if (!publicKey) {
    res.status(401).json({ error: "Invalid or expired authentication token", permission: "admin" });
    return;
  }

  (req as any).walletAddress = publicKey;

  // 3. If an admin allow-list is configured, the session wallet must be in it.
  if (ADMIN_ALLOWLIST_ENABLED && !ADMIN_WALLETS.has(publicKey)) {
    res.status(403).json({
      error: "Forbidden: wallet is not in the administrative allow-list",
      permission: "admin",
    });
    return;
  }

  // 4. If a specific wallet/publicKey is requested, it must match the session.
  const requestedWallet = req.body?.publicKey || req.body?.wallet;
  if (requestedWallet && requestedWallet !== publicKey && !ADMIN_WALLETS.has(publicKey)) {
    res.status(403).json({
      error: "Cannot act on behalf of another wallet",
      permission: "admin",
    });
    return;
  }

  next();
}

/**
 * Helper to annotate which routes are read-only. Currently a no-op marker
 * used for documentation; future versions can add rate-limiting or caching
 * scoped to read-only consumers.
 *
 * @example
 * ```ts
 * app.get("/api/jobs", readOnly, handler);
 * ```
 */
export function readOnly(req: Request, res: Response, next: NextFunction): void {
  // Read-only routes are open to all callers (subject to CORS).
  // This middleware exists to make the authorization boundary explicit.
  next();
}

/**
 * Middleware: Verify that the wallet in the request matches the authenticated session.
 * Only allows authenticated users to act on their own wallets.
 */
export function requireMatchingWallet(req: Request, res: Response, next: NextFunction): void {
  const walletAddress = (req as any).walletAddress;
  if (!walletAddress) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const requestedWallet = req.body.publicKey || req.body.wallet;
  if (requestedWallet && requestedWallet !== walletAddress) {
    res.status(403).json({ error: "Cannot act on behalf of another wallet" });
    return;
  }

  next();
}
