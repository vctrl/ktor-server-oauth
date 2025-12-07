package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.route.ProvisionRouteBuilder
import io.ktor.server.sessions.CookieConfiguration

// ============================================================================
// Type Aliases for Validation and Principal Factory
// ============================================================================

/**
 * Type alias for client_credentials validation function.
 * Takes clientId and clientSecret, returns true if valid.
 */
typealias CredentialValidator = (clientId: String, clientSecret: String) -> Boolean

/**
 * Type alias for client ID validation function (global blocklist).
 * Called after JWT is validated. Return true to allow, false to reject.
 */
typealias ClientValidator = suspend (clientId: String) -> Boolean

/**
 * Type alias for JWT ID (jti) generation function.
 * Called at the start of each authorization flow to generate a unique token ID.
 * Takes clientId and returns a unique jti string.
 */
typealias JwtIdProvider = (clientId: String) -> String

/**
 * Type alias for auth provider validation function (like Ktor's validate {}).
 * Called after JWT signature verification and global client check.
 * Return a Principal to allow access, or null to reject.
 */
typealias AuthProviderValidator = suspend io.ktor.server.auth.jwt.JWTCredential.() -> Any

/**
 * Type alias for provision route setup.
 * Receives [ProvisionRouteBuilder] for defining handlers with [ProvisionRoutingContext].
 *
 * Handlers have access to:
 * - [ProvisionRoutingContext.call] - The application call (from RoutingContext)
 * - [ProvisionRoutingContext.clientId] - The client ID for this session
 * - [ProvisionRoutingContext.complete] - Complete provision with optional claims
 *
 * Example:
 * ```kotlin
 * provision {
 *     get { call.respondText(formHtml, ContentType.Text.Html) }
 *     post {
 *         val params = call.receiveParameters()
 *         sessions.set(MySession(apiKey = params["api_key"]))
 *         complete(claims = mapOf("username" to params["username"]))
 *     }
 * }
 * ```
 */
typealias ProvisionRouteSetup = ProvisionRouteBuilder.() -> Unit

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

    /** Which authorization server to use (null = default/local) */
    var authorizationServer: String? = null

    /** Provision configuration */
    internal var provisionConfig: ProvisionConfig? = null

    /** Per-provider validation function (like Ktor's validate {}) */
    internal var validateFn: AuthProviderValidator? = null

    /**
     * Configure the provision flow with [ProvisionRoutingContext] handlers.
     *
     * Example:
     * ```kotlin
     * provision {
     *     get { call.respondText(formHtml, ContentType.Text.Html) }
     *     post {
     *         val params = call.receiveParameters()
     *         sessions.set(MySession(apiKey = params["api_key"]))
     *         complete(claims = mapOf("username" to params["username"]))
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
 * Handlers receive [ProvisionRoutingContext] which provides:
 * - [ProvisionRoutingContext.call] - The application call
 * - [ProvisionRoutingContext.clientId] - The client ID for this session
 * - [ProvisionRoutingContext.complete] - Complete provision with optional claims
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
 *             sessions.set(MySession(apiKey = params["api_key"]))
 *             complete(claims = mapOf("username" to params["username"]))
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
 *     authorizationServer(LocalAuthServer) {
 *         openRegistration = true
 *         tokenExpiration = 90.days
 *         clientCredentials { id, secret -> validate(id, secret) }
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
 *             sessions.set(MySession(apiKey = params["api_key"]))
 *             complete(claims = mapOf("username" to params["username"]))
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
     * Only one local auth server can be configured.
     *
     * Example:
     * ```kotlin
     * authorizationServer(LocalAuthServer) {
     *     openRegistration = true
     *     tokenExpiration = 90.days
     *     claims(SessionKeyClaimsProvider)
     * }
     * ```
     */
    fun <C : AuthServerConfig> authorizationServer(
        builder: AuthServerBuilder<C>,
        block: C.() -> Unit
    ) {
        val config = builder.createConfig(null)
        config.block()
        require(config !is LocalAuthServerConfig || authServers.values.none { it is LocalAuthServerConfig }) {
            "Only one local authorization server can be configured"
        }
        authServers[config.name] = config
    }

    /**
     * Configure a named authorization server.
     * Use with ExternalAuthServer for external auth servers.
     *
     * Example:
     * ```kotlin
     * authorizationServer("partner", ExternalAuthServer) {
     *     jwksUri = "https://partner.example/.well-known/jwks.json"
     *     issuer = "https://partner.example"
     * }
     * ```
     */
    fun <C : AuthServerConfig> authorizationServer(
        name: String,
        builder: AuthServerBuilder<C>,
        block: C.() -> Unit
    ) {
        val config = builder.createConfig(name)
        config.block()
        require(config !is LocalAuthServerConfig || authServers.values.none { it is LocalAuthServerConfig }) {
            "Only one local authorization server can be configured"
        }
        require(name !in authServers) { "Authorization server '$name' already configured" }
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

