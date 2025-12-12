package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.model.ClientIdentity
import com.vcontrol.ktor.oauth.token.TokenClaimsProvider
import kotlin.time.Duration

/**
 * Base class for authorization server configurations.
 */
@OAuthDsl
sealed class AuthServerConfig(val name: String?) {
    // TODO: Revisit ClientValidator - may be redundant with sealed ClientIdentity
    // /** Global client validator (blocklist) */
    // internal var clientValidator: ClientValidator? = null
    //
    // /**
    //  * Global client validation (blocklist).
    //  * Called after JWT signature is verified, before resource-level validation.
    //  * Return true to allow, false to reject.
    //  *
    //  * Example:
    //  * ```kotlin
    //  * client { clientId -> clientId !in blockedClients }
    //  * ```
    //  */
    // fun client(validator: ClientValidator) {
    //     clientValidator = validator
    // }
}

/**
 * Configuration for a local authorization server that issues tokens.
 * Only one local auth server can be configured per application.
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
@OAuthDsl
class LocalAuthServerConfig(name: String? = null) : AuthServerConfig(name) {
    /** Token expiration (overrides application.conf) */
    var tokenExpiration: Duration? = null

    /** Grants configuration */
    internal val grantsConfig = GrantsConfig()

    /** Custom JWT ID provider for generating jti claims */
    internal var jwtIdProvider: JwtIdProvider? = null

    /** Custom claims providers for JWT tokens */
    internal val claimsProviders = mutableListOf<TokenClaimsProvider>()

    /** Client validation configuration */
    internal var clientsConfig: ClientsConfig? = null

    /**
     * Configure client validation for registration and authorization.
     *
     * Both validators receive [RequestContext] as receiver with access to:
     * [RequestContext.request], [RequestContext.resource], [RequestContext.origin], [RequestContext.headers].
     *
     * Example:
     * ```kotlin
     * server {
     *     clients {
     *         // Allow dynamic registration (RFC 7591)
     *         registration = true
     *         // Or with condition:
     *         // registration { clientId, clientName -> origin.remoteHost in allowedIps }
     *
     *         // Credential validation at /token (RFC 6749 Section 2.3)
     *         credentials { clientId, secret ->
     *             when {
     *                 secret == null -> true  // Allow open registration (public clients)
     *                 else -> clientId == "my-app" && secret == "my-secret"
     *             }
     *         }
     *         // Or static:
     *         // credentials("app" to "secret", "app2" to "secret2")
     *     }
     * }
     * ```
     */
    fun clients(block: ClientsConfig.() -> Unit) {
        clientsConfig = ClientsConfig().apply(block)
    }

    /**
     * Configure grants (future: refresh token settings, etc.).
     *
     * Example:
     * ```kotlin
     * grants {
     *     // Future: refreshToken { lifetime = 30.days }
     * }
     * ```
     */
    fun grants(block: GrantsConfig.() -> Unit) {
        grantsConfig.apply(block)
    }

    /**
     * Configure custom JWT ID (jti) generation.
     * Default generates UUID if not configured.
     *
     * Note: Currently jti is generated at /authorize time (before TokenRequest exists),
     * so this provider is not called for authorization_code flow. Future use for
     * refresh token flows.
     *
     * The jti is used for:
     * - Token identity in the final JWT
     * - Token revocation tracking
     *
     * Example:
     * ```kotlin
     * jwtId { request ->
     *     UUID.randomUUID().toString()
     * }
     * ```
     */
    fun jwtId(provider: JwtIdProvider) {
        jwtIdProvider = provider
    }

    /**
     * Add custom claims to JWT tokens.
     *
     * Example:
     * ```kotlin
     * claims(SessionKeyClaimsProvider)
     * claims { builder, clientId ->
     *     builder.withClaim("tenant_id", lookupTenant(clientId))
     * }
     * ```
     */
    fun claims(provider: TokenClaimsProvider) {
        claimsProviders.add(provider)
    }
}

/**
 * Configuration for OAuth grants and flows.
 *
 * Currently a placeholder for future grant-specific settings like:
 * - Refresh token configuration (lifetime, rotation)
 * - Authorization code configuration (PKCE requirements)
 */
@OAuthDsl
class GrantsConfig {
    // Future: refresh token settings
    // var refreshTokenLifetime: Duration? = null
    // var rotateRefreshToken: Boolean = true

    // Future: authorization code settings
    // var pkceRequired: Boolean = true
}

/**
 * Configuration for client validation.
 *
 * Two independent concerns:
 *
 * **1. Dynamic Registration (`registration`)** - RFC 7591
 * Controls who can call `/register` to obtain a client_id.
 * Dynamic registration always produces **public clients** (no client_secret).
 * Public clients authenticate via PKCE at `/token`.
 *
 * **2. Pre-configured Credentials (`credentials`)** - RFC 6749 Section 2.3
 * For **confidential clients** with pre-shared secrets.
 * Validates client_secret at `/token` endpoint.
 * These clients skip `/register` - they already have credentials.
 *
 * Both validators receive [RequestContext] as receiver with access to:
 * - [RequestContext.request] - Full request for headers, etc.
 * - [RequestContext.resource] - Auth provider/resource name
 * - [RequestContext.origin] - Remote host, port, etc.
 * - [RequestContext.headers] - Request headers
 *
 * Example:
 * ```kotlin
 * // Public clients via dynamic registration
 * clients {
 *     registration = true
 * }
 *
 * // Confidential clients with pre-configured credentials
 * clients {
 *     credentials { clientId, secret ->
 *         clientId == "my-app" && secret == "my-secret"
 *     }
 * }
 * ```
 */
@OAuthDsl
class ClientsConfig {
    /** Registration validator - null means registration disabled */
    internal var registrationValidator: RegistrationValidator? = null

    /** Credentials validator - null means credentials disabled */
    internal var credentialsValidator: CredentialsValidator? = null

    /**
     * Enable or disable dynamic registration (RFC 7591).
     *
     * When enabled, the /register endpoint accepts client registrations.
     * Dynamic registration always produces **public clients** - no client_secret
     * is issued. Public clients authenticate via PKCE at /token.
     *
     * Example:
     * ```kotlin
     * clients {
     *     registration = true  // Allow all registrations (public clients)
     * }
     * ```
     */
    var registration: Boolean
        get() = registrationValidator != null
        set(value) {
            registrationValidator = if (value) ({ _ -> true }) else null
        }

    /**
     * Enable dynamic registration with a condition.
     *
     * Receives clientName (from request) with [RequestContext] as receiver
     * for access to request, resource, origin, and headers.
     *
     * Example:
     * ```kotlin
     * clients {
     *     registration { clientName ->
     *         origin.remoteHost in allowedIps
     *     }
     * }
     * ```
     */
    fun registration(block: RegistrationValidator) {
        registrationValidator = block
    }

    /**
     * Configure credential validation at /token (RFC 6749 Section 2.3).
     *
     * Called at /token to validate client credentials:
     * - If `secret` is null: client came from open registration (public client, uses PKCE)
     * - If `secret` is non-null: client is using pre-configured credentials (confidential client)
     *
     * Receives clientId and secret (nullable) as parameters, with [RequestContext] as receiver
     * for access to request, resource, origin, and headers.
     *
     * Example:
     * ```kotlin
     * clients {
     *     credentials { clientId, secret ->
     *         when {
     *             secret == null -> true  // Allow open registration (public clients)
     *             else -> clientId == "my-app" && secret == "my-secret"
     *         }
     *     }
     * }
     * ```
     */
    fun credentials(block: CredentialsValidator) {
        credentialsValidator = block
    }

    /**
     * Configure credential validation with static credentials.
     *
     * Example:
     * ```kotlin
     * clients {
     *     credentials("app" to "secret", "app2" to "secret2")
     * }
     * ```
     */
    fun credentials(vararg pairs: Pair<String, String>) {
        val map = pairs.toMap()
        credentialsValidator = { clientId, secret -> map[clientId] == secret }
    }
}

/**
 * Configuration for an external authorization server (validates tokens from elsewhere).
 *
 * **Not yet implemented** - placeholder for future external OAuth provider support.
 *
 * Example (future):
 * ```kotlin
 * server("partner", External) {
 *     jwksUri = "https://partner.example/.well-known/jwks.json"
 *     issuer = "https://partner.example"
 * }
 * ```
 */
@OAuthDsl
class ExternalAuthServerConfig(name: String) : AuthServerConfig(name) {
    /** JWKS URI for fetching public keys to validate tokens */
    lateinit var jwksUri: String

    /** Expected issuer claim in tokens */
    lateinit var issuer: String
}

/**
 * Builder interface for authorization server configurations.
 */
interface AuthServerBuilder<C : AuthServerConfig> {
    fun createConfig(name: String?): C
}

/**
 * Builder for local authorization server.
 * Use with unnamed `server { }` for default,
 * or `server(Local) { }` for explicit builder.
 */
object Local : AuthServerBuilder<LocalAuthServerConfig> {
    override fun createConfig(name: String?) = LocalAuthServerConfig(name)
}

/**
 * Builder for external authorization server.
 * Must be named: `server("partner", External) { }`.
 *
 * **Not yet implemented** - placeholder for future external OAuth provider support.
 */
object External : AuthServerBuilder<ExternalAuthServerConfig> {
    override fun createConfig(name: String?): ExternalAuthServerConfig {
        requireNotNull(name) { "External auth server must have a name" }
        return ExternalAuthServerConfig(name)
    }
}

