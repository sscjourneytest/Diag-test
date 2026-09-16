/*
 * Authorized API compatibility / security diagnostic Worker.
 *
 * Use only with an API you own or are explicitly authorized to test.
 *
 * Required Worker Secrets:
 *   UPSTREAM_URL          Full API endpoint, e.g. https://api.example.com/api/score/calculate-and-rank
 *
 * Optional Worker Secrets:
 *   ALLOWED_UI_ORIGIN             Comma-separated list of exact origins hosting
 *                                 diagnostic.html, e.g. "https://mockmatrixhub.in,http://localhost:8080"
 *                                 Defaults to https://mockmatrixhub.in and
 *                                 http://localhost:8080 if not set.
 *   UPSTREAM_ORIGIN               Expected frontend origin, e.g. https://app.example.com
 *   UPSTREAM_REFERER              Expected frontend referer, e.g. https://app.example.com/
 *   UPSTREAM_TEST_SESSION_COOKIE  Short-lived test-account application session cookie
 *   UPSTREAM_BEARER_TOKEN         Documented server-to-server bearer token
 *   UPSTREAM_API_KEY              Documented API key, sent as X-API-Key
 */

const MAX_REQUEST_BYTES = 256 * 1024;
const MAX_RESPONSE_PREVIEW_BYTES = 16 * 1024;

const PROFILES = new Set([
  "anonymous",
  "browser-shaped",
  "session",
  "service",
  "full"
]);

const SAFE_RESPONSE_HEADERS = [
  "content-type",
  "content-length",
  "cache-control",
  "retry-after",
  "server",
  "cf-ray",
  "www-authenticate",
  "location",
  "x-request-id",
  "x-ratelimit-limit",
  "x-ratelimit-remaining",
  "x-ratelimit-reset"
];

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowedOrigins = env.ALLOWED_UI_ORIGIN
      ? env.ALLOWED_UI_ORIGIN.split(",").map((value) => value.trim())
      : ["https://mockmatrixhub.in", "http://localhost:8080"];
    const corsHeaders = makeCorsHeaders(origin, allowedOrigins);

    if (request.method === "OPTIONS") {
      if (!originAllowed(origin, allowedOrigins)) {
        return new Response("Origin not allowed", { status: 403 });
      }
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const pathname = new URL(request.url).pathname;

    if (pathname === "/health" && request.method === "GET") {
      return json({
        ok: true,
        message: "Diagnostic Worker is running.",
        upstreamConfigured: Boolean(env.UPSTREAM_URL)
      }, 200, corsHeaders);
    }

    if (!originAllowed(origin, allowedOrigins)) {
      return json({
        ok: false,
        code: "UI_ORIGIN_NOT_ALLOWED",
        message: "The HTML page origin does not match ALLOWED_UI_ORIGIN."
      }, 403, corsHeaders);
    }

    if (pathname !== "/probe" || request.method !== "POST") {
      return json({
        ok: false,
        code: "NOT_FOUND",
        message: "Use POST /probe."
      }, 404, corsHeaders);
    }

    if (!env.UPSTREAM_URL) {
      return json({
        ok: false,
        code: "UPSTREAM_NOT_CONFIGURED",
        message: "Set UPSTREAM_URL as a Worker Secret."
      }, 500, corsHeaders);
    }

    let upstreamUrl;
    try {
      upstreamUrl = new URL(env.UPSTREAM_URL);
      if (upstreamUrl.protocol !== "https:") {
        throw new Error("Only HTTPS upstream URLs are allowed.");
      }
    } catch (error) {
      return json({
        ok: false,
        code: "INVALID_UPSTREAM_URL",
        message: error.message
      }, 500, corsHeaders);
    }

    const rawInput = await request.text();
    if (rawInput.length > MAX_REQUEST_BYTES) {
      return json({
        ok: false,
        code: "PAYLOAD_TOO_LARGE",
        message: "Diagnostic payload exceeds 256 KB."
      }, 413, corsHeaders);
    }

    let input;
    try {
      input = JSON.parse(rawInput);
    } catch {
      return json({
        ok: false,
        code: "INVALID_JSON",
        message: "Request body must be valid JSON."
      }, 400, corsHeaders);
    }

    const profile = String(input.profile || "anonymous");
    const method = String(input.method || "POST").toUpperCase();
    const payload = input.payload ?? null;

    if (!PROFILES.has(profile)) {
      return json({
        ok: false,
        code: "INVALID_PROFILE",
        message: `Use one of: ${[...PROFILES].join(", ")}`
      }, 400, corsHeaders);
    }

    if (!["GET", "POST"].includes(method)) {
      return json({
        ok: false,
        code: "INVALID_METHOD",
        message: "Only GET and POST are enabled."
      }, 400, corsHeaders);
    }

    const configProblem = profileConfigProblem(profile, env);
    if (configProblem) {
      return json({
        ok: false,
        code: "PROFILE_SECRET_MISSING",
        message: configProblem
      }, 400, corsHeaders);
    }

    const headers = buildUpstreamHeaders(profile, env, upstreamUrl);

    const startedAt = Date.now();

    try {
      const upstreamResponse = await fetch(upstreamUrl.toString(), {
        method,
        headers,
        body: method === "POST" ? JSON.stringify(payload) : undefined,
        redirect: "manual"
      });

      const preview = await readResponsePreview(
        upstreamResponse,
        MAX_RESPONSE_PREVIEW_BYTES
      );

      const elapsedMs = Date.now() - startedAt;
      const diagnostic = classifyResponse(
        upstreamResponse.status,
        upstreamResponse.headers,
        preview.text
      );

      // Safe Worker log: no request payload, cookies, credentials, or body.
      console.log(JSON.stringify({
        event: "api_compatibility_probe",
        upstreamHost: upstreamUrl.host,
        profile,
        method,
        status: upstreamResponse.status,
        elapsedMs,
        category: diagnostic.category
      }));

      return json({
        ok: upstreamResponse.ok,
        profile,
        method,
        note: "This is the Worker-to-upstream result. Browser CORS is not evaluated on a Worker subrequest.",
        upstream: {
          host: upstreamUrl.host,
          status: upstreamResponse.status,
          statusText: upstreamResponse.statusText,
          elapsedMs,
          headers: selectedHeaders(upstreamResponse.headers),
          bodyPreview: preview.text,
          bodyPreviewTruncated: preview.truncated
        },
        diagnostic
      }, 200, corsHeaders);
    } catch (error) {
      const elapsedMs = Date.now() - startedAt;

      return json({
        ok: false,
        profile,
        method,
        upstream: {
          host: upstreamUrl.host,
          elapsedMs
        },
        diagnostic: {
          category: "upstream_network_or_platform_failure",
          confidence: "observed",
          message: "The Worker did not receive an HTTP response. This can be DNS, TLS, routing, connection reset, upstream firewall/WAF behavior, or another Worker-runtime fetch failure. The runtime did not expose a more exact reason.",
          workerError: String(error?.message || error)
        }
      }, 200, corsHeaders);
    }
  }
};

function profileConfigProblem(profile, env) {
  if ((profile === "session" || profile === "full") &&
      !env.UPSTREAM_TEST_SESSION_COOKIE) {
    return "Set UPSTREAM_TEST_SESSION_COOKIE for the selected session profile.";
  }

  if ((profile === "service" || profile === "full") &&
      !env.UPSTREAM_BEARER_TOKEN &&
      !env.UPSTREAM_API_KEY) {
    return "Set UPSTREAM_BEARER_TOKEN or UPSTREAM_API_KEY for the selected service profile.";
  }

  return null;
}

function buildUpstreamHeaders(profile, env, upstreamUrl) {
  const headers = new Headers({
    "Accept": "application/json, text/plain, */*"
  });

  if (profile !== "anonymous") {
    headers.set(
      "Accept-Language",
      env.UPSTREAM_ACCEPT_LANGUAGE || "en-US,en;q=0.9"
    );

    headers.set(
      "User-Agent",
      env.UPSTREAM_USER_AGENT || "Authorized-API-Compatibility-Probe/1.0"
    );

    // These values are configured by the API owner in Worker Secrets,
    // not taken from browser input.
    headers.set(
      "Origin",
      env.UPSTREAM_ORIGIN || upstreamUrl.origin
    );

    headers.set(
      "Referer",
      env.UPSTREAM_REFERER || `${upstreamUrl.origin}/`
    );
  }

  if (profile === "session" || profile === "full") {
    headers.set("Cookie", env.UPSTREAM_TEST_SESSION_COOKIE);
  }

  if (profile === "service" || profile === "full") {
    if (env.UPSTREAM_BEARER_TOKEN) {
      headers.set(
        "Authorization",
        `Bearer ${env.UPSTREAM_BEARER_TOKEN}`
      );
    }

    if (env.UPSTREAM_API_KEY) {
      headers.set("X-API-Key", env.UPSTREAM_API_KEY);
    }
  }

  return headers;
}

function classifyResponse(status, headers, bodyText) {
  const text = String(bodyText || "").toLowerCase();
  const server = headers.get("server") || "";

  const looksLikeCloudflareChallenge =
    /just a moment|attention required|cf-chl|challenge-platform|verify you are human/.test(text) ||
    (/cloudflare/i.test(server) && status === 403);

  if (status >= 200 && status < 300) {
    return {
      category: "success",
      confidence: "observed",
      message: "The upstream returned a successful HTTP response to this Worker profile."
    };
  }

  if (status === 401) {
    return {
      category: "authentication_required_or_invalid",
      confidence: "observed",
      message: "The upstream returned HTTP 401. The supplied profile lacks valid documented authentication."
    };
  }

  if (status === 403 && looksLikeCloudflareChallenge) {
    return {
      category: "cloudflare_or_bot_protection",
      confidence: "observed",
      message: "The upstream returned HTTP 403 with Cloudflare/challenge indicators. Use documented API authentication or configure an authorized server-to-server path; do not depend on challenge-cookie replay."
    };
  }

  if (status === 403) {
    return {
      category: "authorization_or_upstream_policy_denied",
      confidence: "observed",
      message: "The upstream returned HTTP 403. Browser CORS is not the blocker here; the upstream denied this Worker request."
    };
  }

  if (status === 404) {
    return {
      category: "endpoint_not_found",
      confidence: "observed",
      message: "The upstream returned HTTP 404. Verify the endpoint path/version."
    };
  }

  if (status === 405) {
    return {
      category: "upstream_method_not_allowed",
      confidence: "observed",
      message: "The upstream rejected the selected HTTP method."
    };
  }

  if ([400, 415, 422].includes(status)) {
    return {
      category: "request_schema_or_content_type_rejected",
      confidence: "observed",
      message: `The upstream returned HTTP ${status}. Check required fields, JSON schema, and content type.`
    };
  }

  if (status === 419 || status === 440) {
    return {
      category: "session_expired_or_csrf_rejected",
      confidence: "observed",
      message: `The upstream returned HTTP ${status}, which commonly indicates an expired session or CSRF/session validation failure.`
    };
  }

  if (status === 429) {
    return {
      category: "rate_limited",
      confidence: "observed",
      message: "The upstream returned HTTP 429. Check Retry-After and your documented rate limit."
    };
  }

  if (status >= 500) {
    return {
      category: "upstream_server_error",
      confidence: "observed",
      message: `The request reached the upstream, which returned HTTP ${status}.`
    };
  }

  return {
    category: "upstream_rejected_request",
    confidence: "observed",
    message: `The upstream returned HTTP ${status}. Review the safe headers and capped response preview.`
  };
}

function originAllowed(origin, allowedOrigins) {
  return Boolean(origin) && allowedOrigins.includes(origin);
}

function makeCorsHeaders(origin, allowedOrigins) {
  const headers = new Headers({
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "600"
  });

  if (originAllowed(origin, allowedOrigins)) {
    headers.set("Access-Control-Allow-Origin", origin);
  }

  return headers;
}

function json(data, status, corsHeaders) {
  const headers = new Headers(corsHeaders);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");

  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers
  });
}

function selectedHeaders(headers) {
  const result = {};

  for (const name of SAFE_RESPONSE_HEADERS) {
    const value = headers.get(name);
    if (value) result[name] = value;
  }

  return result;
}

async function readResponsePreview(response, maxBytes) {
  if (!response.body) {
    return { text: "", truncated: false };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const available = maxBytes - total;

      if (available <= 0) {
        truncated = true;
        await reader.cancel();
        break;
      }

      if (value.byteLength > available) {
        chunks.push(value.slice(0, available));
        total += available;
        truncated = true;
        await reader.cancel();
        break;
      }

      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const joined = new Uint8Array(total);
  let offset = 0;

  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return {
    text: new TextDecoder().decode(joined),
    truncated
  };
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return diff === 0;
}
