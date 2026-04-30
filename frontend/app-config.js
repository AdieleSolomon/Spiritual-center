// Frontend runtime configuration.
// These pages are deployed as static HTML, so production needs an explicit
// backend URL instead of relying on build-time NEXT_PUBLIC_* variables.
(() => {
  // Allow runtime override via window.API_BASE_URL (set in a <script> tag before this file)
  const existingConfig = window.APP_CONFIG || {};
  const host = String(window.location.hostname || "").toLowerCase();
  const currentPort = String(window.location.port || "").trim();
  const localApiPortOverride = String(
    window.LOCAL_API_PORT || existingConfig.LOCAL_API_PORT || "",
  ).trim();
  const knownLocalBackendPorts = new Set(["5501", "8080"]);
  const localBackendOrigin = (() => {
    if (!host) {
      return "http://127.0.0.1:5501";
    }

    const protocol = window.location.protocol === "https:" ? "https:" : "http:";
    if (knownLocalBackendPorts.has(currentPort)) {
      return `${protocol}//${host}${currentPort ? `:${currentPort}` : ""}`;
    }

    const resolvedLocalApiPort =
      localApiPortOverride || existingConfig.API_PORT || "5501";
    return `${protocol}//${host}:${resolvedLocalApiPort}`;
  })();
  const isLocalHost =
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(host);

  // Use window.API_BASE_URL if set, else fallback to existingConfig, else default
  const runtimeApiBase =
    window.API_BASE_URL ||
    existingConfig.API_BASE ||
    (isLocalHost
      ? `${localBackendOrigin}/api`
      : "https://center-of-knowledge-production.up.railway.app/api");

  window.APP_CONFIG = {
    API_BASE: runtimeApiBase,
    GOOGLE_ANALYTICS_ID: existingConfig.GOOGLE_ANALYTICS_ID || "",
    GOOGLE_MAPS_EMBED_URL:
      existingConfig.GOOGLE_MAPS_EMBED_URL ||
      "https://www.google.com/maps?q=Center+of+Knowledge+and+Spiritual+Enrichment&output=embed",
    GOOGLE_MAPS_DIRECTIONS_URL:
      existingConfig.GOOGLE_MAPS_DIRECTIONS_URL ||
      "https://www.google.com/maps/search/?api=1&query=Center+of+Knowledge+and+Spiritual+Enrichment",
  };
})();

// To override the API base URL in production, add this to your index.html <head>:
// <script>window.API_BASE_URL = "https://your-backend-domain/api";</script>
// This allows you to change the backend URL without rebuilding the frontend.
