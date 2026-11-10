// Public configuration for the static site.
//
// Replace every SETUP value after you fork or publish this repository.
// These values are public: never put a client secret here.
window.ION_CONFIG = {
  // Root zone name, without a leading dot.
  zoneName: "ion",

  // GitHub repository that stores the zone, in owner/name form.
  zoneRepo: "Git-DNS/zone-ion",

  // Branch that the registration bot commits to.
  branch: "main",

  // GitHub OAuth App client ID. The matching client secret lives only in the
  // Cloudflare Worker (see oauth-worker/README.md).
  oauthClientId: "Ov23li4dxxLaWTAthUeg",

  // URL of the deployed OAuth Worker.
  oauthWorkerUrl: "https://ion-oauth.gitdns.workers.dev",

  // Repository with the GitDNS source code, used for the footer link.
  sourceRepo: "Git-DNS/GitDNS",
};
