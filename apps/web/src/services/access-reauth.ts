/**
 * Cloudflare Access session-expiry handling.
 *
 * When this app is deployed behind Cloudflare Access (see README → Security)
 * and the browser's Access session cookie is missing or expired, every /api/*
 * request is redirected at the edge to the Access login page. A fetch() can
 * NEVER complete that login — the login page lives on a cross-origin host
 * (cloudflareaccess.com) that sends no CORS headers, so the browser blocks the
 * redirected response and the fetch rejects with a bare TypeError. In the
 * console this reads as a confusing CORS error; in the UI it reads as a
 * generic network failure. Neither tells the user what to actually do.
 *
 * apiFetch() in services/api.ts therefore issues API requests with
 * redirect: "manual", which surfaces the redirect as an *observable*
 * opaque-redirect response instead of an opaque network failure. When that
 * is detected we call noteAccessRedirect(), which:
 *
 *   1. Reloads the page exactly once per tab (sessionStorage-guarded). A
 *      top-level navigation is the only way to complete Access login —
 *      Access shows its login page (or transparently re-authenticates a
 *      WARP-enrolled device) and returns the user via redirect_url.
 *   2. If the session is still invalid after that one attempt, does NOT
 *      reload again — it throws AccessSessionExpiredError so the UI can tell
 *      the user to log in manually. The guard makes a reload loop impossible.
 */

const REAUTH_FLAG = "cf-access-reauth-attempted";

export class AccessSessionExpiredError extends Error {
  constructor(reloading: boolean) {
    super(
      reloading
        ? "Your Cloudflare Access session has expired — reloading the page to re-authenticate…"
        : "Your Cloudflare Access session has expired. Open this site in a new tab to log in again, then return here."
    );
    this.name = "AccessSessionExpiredError";
  }
}

export function isAccessSessionError(e: unknown): boolean {
  return e instanceof AccessSessionExpiredError;
}

/**
 * Called when an API fetch came back as an opaque redirect — i.e. something at
 * the edge (in this deployment: Cloudflare Access) tried to send the request
 * to a login page instead of the API. Returns the error the caller should
 * throw, after arranging the reload if this is the first detection in the tab.
 */
export function noteAccessRedirect(): AccessSessionExpiredError {
  let reloading = false;
  try {
    if (!sessionStorage.getItem(REAUTH_FLAG)) {
      sessionStorage.setItem(REAUTH_FLAG, "1");
      reloading = true;
      // Brief delay so the current render can show the "reloading…" message
      // before navigation, in case the reload is slow or fails.
      window.setTimeout(() => window.location.reload(), 100);
    }
  } catch {
    // sessionStorage unavailable (hardened privacy modes). We refuse to
    // auto-reload without a loop guard — surface the manual-recovery error.
  }
  return new AccessSessionExpiredError(reloading);
}

/** Manual recovery action: clear the once-per-tab guard and reload now. */
export function reauthenticateNow(): void {
  try {
    sessionStorage.removeItem(REAUTH_FLAG);
  } catch {
    // Even without storage, a manual action may safely reload the page.
  }
  window.location.reload();
}
