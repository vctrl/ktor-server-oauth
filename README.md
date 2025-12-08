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
    implementation("com.vcontrol:ktor-server-oauth:0.4.5")
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
        authorizationServer(LocalAuthServer) {
            openRegistration = true
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
                complete(claims = mapOf("username" to params["username"]))
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

## Configuration

### Plugin Configuration

```kotlin
install(OAuth) {
    authorizationServer(LocalAuthServer) {
        // Enable/disable dynamic client registration
        openRegistration = true

        // Token lifetime
        tokenExpiration = 90.days

        // Global client blocklist
        client { clientId -> clientId !in blockedClients }

        // Client credentials grant validation
        clientCredentials { id, secret -> validateCredentials(id, secret) }

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
        dataDir = "/var/lib/myapp/sessions"
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

Cleanup is disabled by default. The job runs on the configured interval and properly
shuts down when the application stops.

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
        dataDir = ${user.home}"/.ktor-oauth/sessions"

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
                complete(claims = mapOf("validated" to "true"))
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

Handlers receive `ProvisionRoutingContext` with:

| Property | Description |
|----------|-------------|
| `call` | The Ktor `ApplicationCall` (use `call.sessions` for session access) |
| `clientId` | The OAuth client ID |
| `complete()` | Complete provision and continue OAuth flow |

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
        handle { complete(claims = mapOf("scope" to "calendar")) }
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
     │  { client_id, client_secret }           │
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
