// GitHub OAuth code exchange for the static .ion registry.
//
// GitHub Pages cannot call https://github.com/login/oauth/access_token from a
// browser because that endpoint has no CORS support. This tiny Worker holds the
// OAuth App client secret and performs the exchange. It never logs or stores a
// token.
//
// Environment:
//   GITHUB_CLIENT_ID       OAuth App client ID (secret binding recommended)
//   GITHUB_CLIENT_SECRET   OAuth App client secret (secret binding)
//   ALLOWED_ORIGINS        comma-separated site origins, for example
//                          https://owner.github.io
//   ALLOWED_REDIRECT_URIS  comma-separated exact callback URLs, for example
//                          https://owner.github.io/zone-ion/

function parseList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function allowedOrigin(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin) {
    return null;
  }
  const allowed = parseList(env.ALLOWED_ORIGINS);
  return allowed.includes(origin) || allowed.includes("*") ? origin : false;
}

function corsHeaders(origin) {
  const headers = new Headers({
    Vary: "Origin",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  });
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
  }
  return headers;
}

function json(body, status, origin) {
  const headers = corsHeaders(origin);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(JSON.stringify(body), { status, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = allowedOrigin(request, env);

    if (request.method === "OPTIONS") {
      if (origin === false) {
        return new Response(null, { status: 403 });
      }
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (request.method === "GET" && url.pathname === "/healthz") {
      return json({ ok: true }, 200, origin === false ? null : origin);
    }

    if (request.method !== "POST" || url.pathname !== "/") {
      return json({ error: "not found" }, 404, origin === false ? null : origin);
    }

    if (origin === false) {
      return json({ error: "origin is not allowed" }, 403, null);
    }

    let input;
    try {
      input = await request.json();
    } catch {
      return json({ error: "request body must be JSON" }, 400, origin);
    }

    const code = typeof input.code === "string" ? input.code : "";
    const redirectUri = typeof input.redirect_uri === "string" ? input.redirect_uri : "";
    if (!code || !redirectUri) {
      return json({ error: "code and redirect_uri are required" }, 400, origin);
    }

    const allowedRedirects = parseList(env.ALLOWED_REDIRECT_URIS);
    if (!allowedRedirects.includes(redirectUri)) {
      return json({ error: "redirect_uri is not allowed" }, 400, origin);
    }

    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
      return json({ error: "the OAuth Worker is not configured" }, 500, origin);
    }

    let response;
    try {
      response = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "User-Agent": "ion-registry-oauth-worker",
        },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: redirectUri,
        }),
      });
    } catch {
      return json({ error: "could not reach GitHub" }, 502, origin);
    }

    let data;
    try {
      data = await response.json();
    } catch {
      return json({ error: "GitHub returned an invalid response" }, 502, origin);
    }

    if (!response.ok || data.error || !data.access_token) {
      return json(
        {
          error:
            data.error_description ||
            data.error ||
            `GitHub returned ${response.status}`,
        },
        400,
        origin,
      );
    }

    // Only the fields the browser needs. No refresh token is issued for this
    // OAuth App flow, so there is nothing else to pass through.
    return json(
      {
        access_token: data.access_token,
        token_type: data.token_type || "bearer",
        scope: data.scope || "",
      },
      200,
      origin,
    );
  },
};
