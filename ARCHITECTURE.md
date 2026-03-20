# Architecture: php-cors

## Purpose

A framework-agnostic Cross-Origin Resource Sharing (CORS) middleware service for PHP, originally extracted from `asm89/stack-cors`. Handles preflight OPTIONS requests and injects CORS headers into actual responses.

## Directory Structure

```
src/
  Cors_Service.php   — Core service: validates origins, builds CORS response headers
```

## Key Design Decisions

- **Single-class design**: All CORS logic lives in `Cors_Service`, keeping the surface area minimal
- **Symfony HttpFoundation dependency**: Uses `Request`/`Response` objects for HTTP abstraction
- **Security guard**: Throws `\LogicException` if `allowedOrigins: ['*']` is combined with `supportsCredentials: true` — this combination reflects any origin with credentials, bypassing the intent of the wildcard
- **Wildcard patterns**: Origins containing `*` (e.g., `*.example.com`) are compiled to regex patterns at configuration time, not per-request
- **Vary header management**: Adds `Vary: Origin` when origin is dynamic, ensuring CDN/proxy caches do not serve incorrect CORS headers

## Extension Points

- Instantiate `Cors_Service` with a `CorsInputOptions` array and use it as middleware
- Override per-route by constructing multiple `Cors_Service` instances with different configs

## Dependency Flow

```
Cors_Service
  └── Symfony\Component\HttpFoundation\{Request, Response}
```

## CORS Flow

```
Incoming request
  ├── is_cors_request()?  No → pass through unchanged
  ├── is_preflight_request()?
  │     Yes → handle_preflight_request() → 204 with CORS headers
  └── No  → add_actual_request_headers() → inject Access-Control-Allow-Origin etc.
```
