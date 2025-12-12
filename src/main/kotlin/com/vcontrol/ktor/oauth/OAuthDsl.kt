package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.model.TokenRequest
import io.ktor.http.Headers
import io.ktor.http.RequestConnectionPoint
import io.ktor.server.plugins.origin
import io.ktor.server.request.ApplicationRequest
import io.ktor.server.routing.Route
import io.ktor.server.sessions.CookieConfiguration

// ============================================================================
// Request Context for Client Validation
// ============================================================================

/**
 * Context for client validation providing request and resource information.
 *
 * Used as receiver for [RegistrationValidator] and [CredentialsValidator].
 *
 * Provides access to:
 * - [request] - The full [ApplicationRequest] for IP, headers, etc.
 * - [resource] - The auth provider/resource name (null for default)
 * - [origin] - Convenience accessor for request origin (remote host, port, etc.)
 * - [headers] - Convenience accessor for request headers
 *
 * Example:
 * ```kotlin
 * server {
 *     clients {
 *         registration { clientId, clientName ->
 *             origin.remoteHost in allowedIps
 *         }
 *         credentials { clientId, secret ->
 *             origin.remoteHost !in blockedIps && db.check(clientId, secret)
 *         }
 *     }
 * }
 * ```
 */
class RequestContext(
    val request: ApplicationRequest,
    val resource: String?
) {
    /** Request origin (remote host, port, etc.) */
    val origin: RequestConnectionPoint get() = request.origin

    /** Request headers */
    val headers: Headers get() = request.headers
}

// ============================================================================
// Type Aliases for Validation
// ============================================================================

/**
 * Type alias for registration validation function.
 * Called during dynamic client registration (RFC 7591).
 *
 * Dynamic registration always produces **public clients** (no client_secret).
 * Public clients authenticate via PKCE at /token.
 *
 * Receives clientName (from request) with [RequestContext] as receiver.
 * Return true to allow, false to reject.
 */
typealias RegistrationValidator = suspend RequestContext.(clientName: String?) -> Boolean

/**
 * Type alias for credentials validation function.
 * Called at /token to validate **confidential clients** (RFC 6749 Section 2.3).
 *
 * Used for pre-configured clients with shared secrets. These clients skip
 * dynamic registration - they already have client_id and client_secret.
 *
 * Receives clientId, secret as parameters with [RequestContext] as receiver.
 * Return true to allow, false to reject.
 *
 * Example:
 * ```kotlin
 * credentials { clientId, secret ->
 *     clientId == "my-app" && secret == "my-secret"
 * }
 * ```
 */
typealias CredentialsValidator = suspend RequestContext.(clientId: String, secret: String?) -> Boolean

/**
 * Type alias for JWT ID (jti) generation function.
 * Called during token issuance to generate a unique token ID.
 * Receives the full [TokenRequest] for context-aware jti generation.
 *
 * Example:
 * ```kotlin
 * jwtId { request ->
 *     when (request) {
 *         is TokenRequest.AuthorizationCodeGrant -> UUID.randomUUID().toString()
 *         is TokenRequest.RefreshTokenGrant -> UUID.randomUUID().toString()
 *     }
 * }
 * ```
 */
typealias JwtIdProvider = (request: TokenRequest) -> String

/**
 * Type alias for auth provider validation function (like Ktor's validate {}).
 * Called after JWT signature verification and global client check.
 * Return a Principal to allow access, or null to reject.
 */
typealias AuthProviderValidator = suspend io.ktor.server.auth.jwt.JWTCredential.() -> Any

/**
 * Type alias for provision route setup.
 * Uses native Ktor [Route] DSL with access to provision context via [ApplicationCall.provision].
 *
 * Access provision context in handlers via `call.provision`:
 * - [ProvisionContext.client] - The client identity (clientId and optionally clientName)
 * - [ProvisionContext.complete] - Complete provision with optional claims
 *
 * Example:
 * ```kotlin
 * provision {
 *     get { call.respondText(formHtml, ContentType.Text.Html) }
 *     post {
 *         val params = call.receiveParameters()
 *         call.sessions.set(MySession(apiKey = params["api_key"]))
 *         call.provision.complete {
 *             withClaim("username", params["username"])
 *         }
 *     }
 * }
 * ```
 */
typealias ProvisionRouteSetup = Route.() -> Unit

// ============================================================================
// Internal Provider Configuration
// ============================================================================

/**
 * Configuration for an OAuth provider.
 *
 * Holds configuration for JWT authentication providers created via `oauth()`:
 * - realm: JWT realm for WWW-Authenticate header
 * - provisionConfig: Provision flow configuration
 * - validateFn: Custom validation function
 *
 * Created automatically when using `oauth { provision { } }` routing extension
 * or `install(Authentication) { oauth("name") { } }`.
 */
class ProviderConfig internal constructor(val name: String?) {
    /** JWT realm for WWW-Authenticate header (like Ktor's basic/jwt realm) */
    var realm: String = "oauth-server"

    /** Which server to use (null = default/local) */
    var server: String? = null

    /** Provision configuration */
    internal var provisionConfig: ProvisionConfig? = null

    /** Per-provider validation function (like Ktor's validate {}) */
    internal var validateFn: AuthProviderValidator? = null

    /**
     * Configure the provision flow using native Ktor routing DSL.
     *
     * Access provision context via `call.provision`:
     * ```kotlin
     * provision {
     *     get { call.respondText(formHtml, ContentType.Text.Html) }
     *     post {
     *         val params = call.receiveParameters()
     *         call.sessions.set(MySession(apiKey = params["api_key"]))
     *         call.provision.complete {
     *             withClaim("username", params["username"])
     *         }
     *     }
     * }
     * ```
     */
    fun provision(path: String? = null, routeSetup: ProvisionRouteSetup) {
        provisionConfig = ProvisionConfig(path = path, routeSetup = routeSetup)
    }

    /**
     * Validate JWT credentials and return a Principal.
     * Like Ktor's validate {} block - return null to reject, or a Principal to allow.
     *
     * Called after JWT signature is verified and global auth server client check passes.
     *
     * Example:
     * ```kotlin
     * validate { credential ->
     *     val clientId = credential.payload.getClaim("client_id").asString()
     *     if (clientId in allowedClients) {
     *         JWTPrincipal(credential.payload)
     *     } else {
     *         null
     *     }
     * }
     * ```
     */
    fun validate(block: AuthProviderValidator) {
        validateFn = block
    }
}

// ============================================================================
// Provision DSL Builders (Resource Server)
// ============================================================================

/**
 * Configuration for the provision flow (resource server setup).
 *
 * Provision is where the resource server collects credentials, API keys, and
 * other configuration needed to serve the client. This is distinct from
 * RFC authorization consent - provision is resource-specific setup.
 *
 * Uses native Ktor routing DSL. Access provision context via `call.provision`:
 * - [ProvisionContext.client] - The client identity (clientId and optionally clientName)
 * - [ProvisionContext.complete] - Complete provision with optional claims
 *
 * Example:
 * ```kotlin
 * provision {
 *     get {
 *         call.respondText(provisionFormHtml, ContentType.Text.Html)
 *     }
 *     post {
 *         val params = call.receiveParameters()
 *         if (params["password"] == "letmein") {
 *             call.sessions.set(MySession(apiKey = params["api_key"]))
 *             call.provision.complete {
 *                 withClaim("username", params["username"])
 *             }
 *         } else {
 *             call.respondText("Invalid password", ContentType.Text.Html)
 *         }
 *     }
 * }
 * ```
 */
@OAuthDsl
class ProvisionConfig(
    /**
     * The path for the provision endpoint.
     * Default: from oauth.server.endpoints.provision in application.conf
     */
    val path: String? = null,
    internal val routeSetup: ProvisionRouteSetup,
    /**
     * Optional cookie configuration overrides for the provision session cookie.
     */
    internal val cookieConfig: (CookieConfiguration.() -> Unit)? = null
)

// ============================================================================
// Main Plugin Configuration
// ============================================================================

/**
 * Plugin configuration for OAuth.
 *
 * Example:
 * ```kotlin
 * install(OAuth) {
 *     server {
 *         clients {
 *             registration = true
 *             credentials { clientId, secret -> db.check(clientId, secret) }
 *         }
 *         tokenExpiration = 90.days
 *     }
 * }
 *
 * install(OAuthSessions) {
 *     session<MySession>()
 * }
 *
 * install(Authentication) {
 *     oauthJwt { realm = "My API" }
 * }
 *
 * routing {
 *     provision {
 *         get { call.respondText(formHtml, ContentType.Text.Html) }
 *         post {
 *             val params = call.receiveParameters()
 *             call.sessions.set(MySession(apiKey = params["api_key"]))
 *             call.provision.complete { withClaim("username", params["username"]) }
 *         }
 *     }
 *
 *     authenticate {
 *         get("/api/data") { ... }
 *     }
 * }
 * ```
 */
@OAuthDsl
class OAuthPluginConfig {
    internal val authServers = mutableMapOf<String?, AuthServerConfig>()
    internal var oauthCookieConfig: (CookieConfiguration.() -> Unit)? = null

    /**
     * Configure a local authorization server (issues tokens).
     * Only one local server can be configured.
     *
     * Example:
     * ```kotlin
     * server {
     *     clients {
     *         registration = true
     *         credentials { clientId, secret -> db.check(clientId, secret) }
     *     }
     *     tokenExpiration = 90.days
     *     claims(SessionKeyClaimsProvider)
     * }
     * ```
     */
    fun server(block: LocalAuthServerConfig.() -> Unit) {
        server(Local, block)
    }

    /**
     * Configure a server with a specific builder.
     * Use [Local] for local token issuance or [External] for external providers.
     */
    fun <C : AuthServerConfig> server(
        builder: AuthServerBuilder<C>,
        block: C.() -> Unit
    ) {
        val config = builder.createConfig(null)
        config.block()
        require(config !is LocalAuthServerConfig || authServers.values.none { it is LocalAuthServerConfig }) {
            "Only one local server can be configured"
        }
        authServers[config.name] = config
    }

    /**
     * Configure a named server.
     *
     * Note: [External] is not yet implemented - placeholder for future support.
     *
     * Example (future):
     * ```kotlin
     * server("partner", External) {
     *     jwksUri = "https://partner.example/.well-known/jwks.json"
     *     issuer = "https://partner.example"
     * }
     * ```
     */
    fun <C : AuthServerConfig> server(
        name: String,
        builder: AuthServerBuilder<C>,
        block: C.() -> Unit
    ) {
        val config = builder.createConfig(name)
        config.block()
        require(config !is LocalAuthServerConfig || authServers.values.none { it is LocalAuthServerConfig }) {
            "Only one local server can be configured"
        }
        require(name !in authServers) { "Server '$name' already configured" }
        authServers[name] = config
    }

    /**
     * Configure the OAuth auth_request cookie settings.
     * Overrides default cookie configuration.
     *
     * Example:
     * ```kotlin
     * oauthCookie {
     *     secure = true
     *     maxAge = 1.hours
     *     sameSite = SameSite.Strict
     * }
     * ```
     */
    fun oauthCookie(block: CookieConfiguration.() -> Unit) {
        oauthCookieConfig = block
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Get the local authorization server config, if configured.
     */
    internal val localAuthServer: LocalAuthServerConfig?
        get() = authServers.values.filterIsInstance<LocalAuthServerConfig>().firstOrNull()
}

