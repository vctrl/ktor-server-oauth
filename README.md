# ktor-server-oauth

A Ktor plugin for building **OAuth 2.0 authorization servers** with JWT tokens, bearer-bound sessions, and **Interactive Resource Setup**.

> **Note:** This is for creating OAuth servers (issuing tokens), not OAuth clients. For connecting to external OAuth providers like Google or GitHub, use Ktor's built-in [OAuth authentication](https://ktor.io/docs/oauth.html).

## Features

- **Interactive Resource Setup** - collect credentials during OAuth flow with direct user interaction
- **Bearer-Bound Sessions** - session data automatically scoped to access tokens
- **OAuth 2.0 Authorization Code Flow** with PKCE
- **Dynamic Client Registration** (RFC 7591)
- **JWT Access Tokens** with configurable claims
- **Protected Resource Metadata** (RFC 9728)
- **Multiple Auth Providers** - support named providers for multi-tenant scenarios

## Why Interactive Resource Setup?

Standard OAuth handles **authorization** ("Allow this app to access your data?") but not **configuration** ("How should I connect to your resources?").

Many applications need user-provided configuration that OAuth alone can't handle:

| Scenario | What you need |
|----------|---------------|
| MCP server connecting to external APIs | User's API keys (OpenAI, Stripe, etc.) |
| Multi-tenant SaaS | Which workspace/account to connect |
| Enterprise integrations | Internal credentials or connection details |
| Self-hosted services | Custom endpoints or authentication |

**Interactive Resource Setup** (provision) solves this by adding a user-facing configuration step to the OAuth flow:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Standard OAuth Flow                         │
├─────────────────────────────────────────────────────────────────┤
│  Client → Auth Server → [Consent] → Token → Resource Server     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                 With Interactive Resource Setup                  │
├─────────────────────────────────────────────────────────────────┤
│  Client → Auth Server → Resource Server → [Setup Form] → Token  │
│                                              ↓                   │
│                                    User provides API keys,       │
│                                    selects workspace, etc.       │
│                                              ↓                   │
│                                    Stored in bearer-bound        │
│                                    session for later use         │
└─────────────────────────────────────────────────────────────────┘
```

**Key benefits:**
- **Direct user interaction** - forms, selections, validation (not just API-to-API)
- **Seamless UX** - happens during OAuth flow, no separate setup step
- **Secure storage** - credentials stored in bearer-bound sessions, isolated per client
- **Flexible output** - store in sessions, embed as JWT claims, or both
- **Automatic scoping** - data tied to access token lifecycle

## Installation

```kotlin
dependencies {
    implementation("com.vcontrol:ktor-server-oauth:0.5.0")
}
```

## Quick Start

```kotlin
import com.vcontrol.ktor.oauth.*
import com.vcontrol.ktor.oauth.route.provision
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*

fun Application.module() {
    // 1. Install OAuth plugin with local authorization server
    install(OAuth) {
        server {
            clients {
                registration = true  // Accept all registrations
            }
        }
    }

    // 2. Install OAuth sessions for bearer-bound session storage
    install(OAuthSessions) {
        session<MySession>()
    }

    // 3. Install authentication (pick one)
    install(Authentication) {
        oauthJwt()              // Shorthand with session integration
        // Or: jwt { oauthDefaults() }  // Manual with Ktor's jwt()
    }

    // 4. Standard Ktor routing with provision and authenticate
    routing {
        // Provision flow (OAuth setup phase)
        provision {
            get { call.respondText(formHtml, ContentType.Text.Html) }
            post {
                val params = call.receiveParameters()
                call.sessions.set(MySession(apiKey = params["api_key"]))
                call.provision.complete {
                    withClaim("username", params["username"])
                }
            }
        }

        // Protected routes
        authenticate {
            get("/api/data") {
                val session = call.sessions.get<MySession>()
                call.respond(session?.apiKey ?: "no session")
            }
        }
    }
}

@Serializable
data class MySession(val apiKey: String)
```

## OAuth Endpoints

The plugin automatically configures these endpoints:

| Endpoint | Description |
|----------|-------------|
| `POST /register` | Dynamic client registration |
| `GET /authorize` | Authorization endpoint (redirects to provision) |
| `POST /token` | Token exchange |
| `GET /provision` | Provision flow (resource setup) |
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata |
| `GET /.well-known/oauth-protected-resource` | Protected resource metadata |

## Error Responses

All error responses follow [RFC 6749 Section 5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2):

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid or expired authorization code"
}
```

| Error Code | HTTP Status | When |
|------------|-------------|------|
| `invalid_request` | 400 | Missing or malformed parameters |
| `invalid_client` | 401 | Bad client_id or client_secret |
| `invalid_grant` | 400 | Expired/invalid auth code, PKCE failure, redirect_uri mismatch |
| `unsupported_grant_type` | 400 | Grant type not enabled |

For `invalid_client`, the response includes a `WWW-Authenticate: Bearer` header per RFC 6750.

Protected routes (behind `authenticate { }`) return `401 Unauthorized` with `WWW-Authenticate: Bearer` for missing/invalid/expired tokens - this is standard Ktor JWT authentication behavior.

## Defaults

| Setting | Default | Notes                                  |
|---------|---------|----------------------------------------|
| Token expiration | 90 days | JWT `exp` claim                        |
| Session TTL | 90 days | Matches token lifetime                 |
| Session storage | File-based | `~/.ktor-oauth/sessions/`              |
| Session encryption | Enabled | AES-256-GCM with per-client key in JWT |
| Session cleanup | Enabled, 1 hour | Removes expired session files          |
| Route prefix | `/.oauth` | All internal endpoints under this path |
| Auth code storage | In-memory | Lost on restart (stateless by design)  |

**Security notes:**
- JWT signing key is auto-generated and stored at `~/.ktor-oauth/jwt.secret`
- Session encryption keys are embedded in each JWT token, so sessions can only be decrypted by the token holder
- Without cleanup, session files accumulate on disk (one file per session per type)

## Configuration

### Plugin Configuration

```kotlin
install(OAuth) {
    server {
        // Client validation
        clients {
            // Dynamic registration (RFC 7591) - public clients only
            // Has access to: origin, headers, resource, request
            registration = true  // or:
            // registration { clientName ->
            //     origin.remoteHost in allowedIps
            // }

            // Confidential clients with pre-configured credentials
            // Validated at /token (RFC 6749 Section 2.3)
            // Has access to: origin, headers, resource, request
            credentials { clientId, secret ->
                clientId == "my-app" && secret == "my-secret"
            }
            // Or static: credentials("app" to "secret", "app2" to "secret2")
        }

        // Token lifetime
        tokenExpiration = 90.days

        // Custom JWT claims
        claims(SessionKeyClaimsProvider)
        claims { builder, clientId ->
            builder.withClaim("tenant_id", lookupTenant(clientId))
        }
    }
}
```

### Session Configuration

```kotlin
install(OAuthSessions) {
    // Use a custom claim as session key (default: jti)
    sessionKeyClaim = "username"

    // Or use a resolver for complex logic
    sessionKeyResolver { payload ->
        payload.getClaim("tenant_id").asString()
            ?: payload.getClaim("client_id").asString()
    }

    // Register session types
    session<MySession>()
    session<ShortLivedSession> {
        ttl = 1.hours
    }
}
```

### Disk-Based Sessions

```kotlin
install(OAuthSessions) {
    storage(DiskSessions) {
        dataPath = "/var/lib/myapp/sessions"
        ttl = 30.days
    }
    session<MySession>()
}
```

### Encrypted Sessions

Session encryption is enabled by default. Sessions are encrypted with AES-256-GCM using
a per-client key embedded in the JWT token. To disable encryption:

```kotlin
install(OAuthSessions) {
    encrypted = false
    session<MySession>()
}
```

### Session Cleanup

Expired sessions can be automatically cleaned up with a background job:

```kotlin
install(OAuthSessions) {
    cleanup {
        interval = 1.hours
    }
    session<MySession>()
}
```

Or via application.conf:

```hocon
oauth.sessions.cleanup.interval = "PT1H"
```

Cleanup is enabled by default (1 hour interval). The job runs on the configured interval
and properly shuts down when the application stops.

### Relationship with Ktor Sessions

`OAuthSessions` internally installs Ktor's `Sessions` plugin - do not install both.

```kotlin
// ✅ Correct - OAuthSessions manages Sessions internally
install(OAuthSessions) {
    session<MySession>()
}

// ❌ Wrong - will conflict
install(Sessions) { ... }  // Don't do this
install(OAuthSessions) { ... }
```

**What OAuthSessions provides:**

- Bearer-bound sessions (`session<T>()`) - stored server-side, keyed by JWT claims
- Standard Ktor sessions (`cookie<T>()`, `header<T>()`) - available through the same DSL
- Internal OAuth cookies (auth_request, provision_session)

**Mixing session types:**

```kotlin
install(OAuthSessions) {
    // Bearer-bound session (server-side, keyed by JWT)
    session<UserPreferences>()

    // Standard Ktor cookie session (for non-OAuth flows)
    cookie<AdminSession>("admin_session") {
        cookie.httpOnly = true
        cookie.secure = true
    }
}
```

Both session types use `call.sessions.get<T>()` / `call.sessions.set<T>()` - the transport is determined by how they're registered.

### application.conf

```hocon
oauth {
    server {
        routePrefix = ""
        tokenExpiration = "PT2160H"  # 90 days (ISO-8601 duration)
        authCodeStorage = "memory"

        jwt {
            issuer = "my-server"
            secretFile = ${user.home}"/.ktor-oauth/jwt.secret"
        }

        endpoints {
            register = "/register"
            authorize = "/authorize"
            token = "/token"
            provision = "/provision"
        }
    }

    sessions {
        type = "file"  # or "memory"
        dataPath = ${user.home}"/.ktor-oauth/sessions"

        cleanup {
            interval = "PT1H"  # ISO-8601 duration, or omit to disable
        }
    }
}
```

## Interactive Resource Setup (Provision)

The `provision` route is where Interactive Resource Setup happens - users provide credentials, API keys, or configuration through forms during the OAuth flow. Data is stored in bearer-bound sessions for use by protected routes.

```kotlin
routing {
    provision {
        // Render the setup form
        get {
            call.respondText("""
                <form method="post">
                    <input name="api_key" placeholder="API Key">
                    <button type="submit">Connect</button>
                </form>
            """, ContentType.Text.Html)
        }

        // Handle form submission
        post {
            val apiKey = call.receiveParameters()["api_key"]

            if (validateApiKey(apiKey)) {
                // Store in bearer-bound session
                call.sessions.set(MySession(apiKey = apiKey))

                // Complete with claims embedded in JWT
                call.provision.complete {
                    withClaim("validated", "true")
                }
            } else {
                call.respondText("Invalid API key")
            }
        }
    }

    authenticate {
        // Protected routes...
    }
}
```

### Provision Context

Access provision context via `call.provision`:

| Property | Description |
|----------|-------------|
| `call.provision.client` | The client identity (clientId and optionally clientName) |
| `call.provision.complete {}` | Complete provision with optional claims builder |

The claims builder supports:
- `withClaim(key, value)` - Plain claims in JWT
- `withEncryptedClaim(key, value)` - Encrypted claims (use `payload.decryptClaim()` to read)

## Multiple Providers

Support multiple OAuth providers for different resources:

```kotlin
install(Authentication) {
    oauthJwt()           // Default provider
    oauthJwt("calendar") // Named provider
}

// Standard Ktor routing with provision and authenticate
routing {
    // Provision routes
    provision { /* default provider */ }
    provision("calendar") {
        post {
            call.provision.complete {
                withClaim("scope", "calendar")
            }
        }
    }

    // Protected routes
    authenticate {
        get("/api/data") { /* ... */ }
    }

    authenticate("calendar") {
        get("/calendar/events") { /* ... */ }
    }
}
```

The plugin automatically discovers which routes are protected by which provider by introspecting Ktor's route tree for `AuthenticationRouteSelector`. This powers RFC 9728 protected resource metadata without manual registration.

## OAuth Flow

```
┌──────────┐                              ┌──────────┐
│  Client  │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │  POST /register                         │
     │  { redirect_uris: [...] }               │
     │ ───────────────────────────────────────>│
     │                                         │
     │  { client_id }  (public client)         │
     │ <───────────────────────────────────────│
     │                                         │
     │  GET /authorize?client_id=...           │
     │      &redirect_uri=...                  │
     │      &code_challenge=...                │
     │ ───────────────────────────────────────>│
     │                                         │
     │  302 → /provision                       │
     │ <───────────────────────────────────────│
     │                                         │
     │  GET /provision                         │
     │ ───────────────────────────────────────>│
     │                                         │
     │  <html>Setup form</html>                │
     │ <───────────────────────────────────────│
     │                                         │
     │  POST /provision                        │
     │  { api_key: "..." }                     │
     │ ───────────────────────────────────────>│
     │                                         │
     │  302 → redirect_uri?code=...            │
     │ <───────────────────────────────────────│
     │                                         │
     │  POST /token                            │
     │  { code, code_verifier }                │
     │ ───────────────────────────────────────>│
     │                                         │
     │  { access_token }                       │
     │ <───────────────────────────────────────│
     │                                         │
     │  GET /api/data                          │
     │  Authorization: Bearer <token>          │
     │ ───────────────────────────────────────>│
     │                                         │
```

## License

Apache 2.0
