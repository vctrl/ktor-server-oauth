package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.token.TokenClaimsProvider
import kotlin.time.Duration

/**
 * Base class for authorization server configurations.
 * Both local and external auth servers can have a global client validator.
 */
@OAuthDsl
sealed class AuthServerConfig(val name: String?) {
    /** Global client validator (blocklist) */
    internal var clientValidator: ClientValidator? = null

    /**
     * Global client validation (blocklist).
     * Called after JWT signature is verified, before resource-level validation.
     * Return true to allow, false to reject.
     *
     * Example:
     * ```kotlin
     * client { clientId -> clientId !in blockedClients }
     * ```
     */
    fun client(validator: ClientValidator) {
        clientValidator = validator
    }
}

/**
 * Configuration for a local authorization server that issues tokens.
 * Only one local auth server can be configured per application.
 *
 * Example:
 * ```kotlin
 * authorizationServer(LocalAuthServer) {
 *     openRegistration = true
 *     tokenExpiration = 90.days
 *     client { clientId -> clientId !in blockedClients }
 *     claims(SessionKeyClaimsProvider)
 *     clientCredentials { id, secret -> validate(id, secret) }
 * }
 * ```
 */
@OAuthDsl
class LocalAuthServerConfig(name: String? = null) : AuthServerConfig(name) {
    /** Enable dynamic client registration */
    var openRegistration: Boolean = true

    /** Token expiration (overrides application.conf) */
    var tokenExpiration: Duration? = null

    /** Client credentials validator for client_credentials grant */
    internal var clientCredentialsValidator: CredentialValidator? = null

    /** Custom claims providers for JWT tokens */
    internal val claimsProviders = mutableListOf<TokenClaimsProvider>()

    /**
     * Configure client_credentials grant validation.
     * Return true to allow, false to reject.
     *
     * Example:
     * ```kotlin
     * clientCredentials { clientId, clientSecret ->
     *     clientId == "my-service" && clientSecret == "secret"
     * }
     * ```
     */
    fun clientCredentials(validator: CredentialValidator) {
        clientCredentialsValidator = validator
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
 * Configuration for an external authorization server (validates tokens from elsewhere).
 * Multiple external auth servers can be configured, each must be named.
 *
 * Example:
 * ```kotlin
 * authorizationServer("partner", ExternalAuthServer) {
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
 * Use with unnamed `authorizationServer(LocalAuthServer) { }` for default,
 * or named `authorizationServer("name", LocalAuthServer) { }`.
 */
object LocalAuthServer : AuthServerBuilder<LocalAuthServerConfig> {
    override fun createConfig(name: String?) = LocalAuthServerConfig(name)
}

/**
 * Builder for external authorization server.
 * Must be named: `authorizationServer("partner", ExternalAuthServer) { }`.
 */
object ExternalAuthServer : AuthServerBuilder<ExternalAuthServerConfig> {
    override fun createConfig(name: String?): ExternalAuthServerConfig {
        requireNotNull(name) { "External auth server must have a name" }
        return ExternalAuthServerConfig(name)
    }
}