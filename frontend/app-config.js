// Frontend runtime configuration.
// These pages are deployed as static HTML, so production needs an explicit
// backend URL instead of relying on build-time NEXT_PUBLIC_* variables.
(() => {
  const existingConfig = window.APP_CONFIG || {};
  const host = String(window.location.hostname || "").toLowerCase();
  const isLocalHost =
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(host);

  window.APP_CONFIG = {
    API_BASE:
      existingConfig.API_BASE ||
      (isLocalHost
        ? ""
        : "https://center-of-knowledge-production.up.railway.app/api"),
    GOOGLE_ANALYTICS_ID: existingConfig.GOOGLE_ANALYTICS_ID || "",
    GOOGLE_MAPS_EMBED_URL:
      existingConfig.GOOGLE_MAPS_EMBED_URL ||
      "https://www.google.com/maps?q=Center+of+Knowledge+and+Spiritual+Enrichment&output=embed",
    GOOGLE_MAPS_DIRECTIONS_URL:
      existingConfig.GOOGLE_MAPS_DIRECTIONS_URL ||
      "https://www.google.com/maps/search/?api=1&query=Center+of+Knowledge+and+Spiritual+Enrichment",
  };
})();
