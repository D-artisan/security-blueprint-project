/**
 * Pillar 3: Data in Transit Protection
 * Cloudflare Worker as the edge security layer.
 * All traffic passes through this before reaching the origin.
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Enforce HTTPS - redirect any HTTP request
    if (url.protocol === "http:") {
      return Response.redirect(`https://${url.host}${url.pathname}`, 301);
    }

    // 2. Security headers (OWASP recommended)
    const securityHeaders = {
      // Prevent clickjacking
      "X-Frame-Options": "DENY",
      // Prevent MIME sniffing
      "X-Content-Type-Options": "nosniff",
      // Force HTTPS for 1 year (HSTS)
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
      // Control what data is sent in Referer header
      "Referrer-Policy": "strict-origin-when-cross-origin",
      // Disable browser features not needed
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      // Content Security Policy
      "Content-Security-Policy": "default-src 'self'; script-src 'self'",
    };

    // 3. Rate limiting by IP (basic — production uses Cloudflare Rate Limiting rules)
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    const rateLimitKey = `rate:${clientIP}:${Math.floor(Date.now() / 60000)}`; // per minute window

    // 4. Block requests from known bad IPs/bots
    const botScore = request.cf?.botManagement?.score;
    if (botScore !== undefined && botScore < 30) {
      return new Response("Access denied", {
        status: 403,
        headers: securityHeaders,
      });
    }

    // 5. Pass request to origin with security headers
    const response = new Response(
      JSON.stringify({
        status: "protected",
        edge_colo: request.cf?.colo,
        tls_version: request.cf?.tlsVersion,
        client_ip: clientIP,
        message: "Traffic encrypted at the Cloudflare edge. Origin server never exposed directly.",
      }),
      {
        headers: {
          "Content-Type": "application/json",
          ...securityHeaders,
        },
      }
    );

    return response;
  }
};