package com.vcontrol.ktor.oauth

import com.auth0.jwt.JWT
import com.vcontrol.ktor.oauth.session.BearerSessionKeyAttributeKey
import com.vcontrol.ktor.oauth.session.SessionKeyAttributeKey
import com.vcontrol.ktor.oauth.token.SessionKeyClaimsProvider
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.util.AttributeKey

/**
 * Configure JWT authentication with OAuth defaults.
 * Use inside Ktor's `jwt { }` block for manual configuration with OAuth-issued tokens.
 *
 * For simple cases, use [oauthJwt] instead which includes session integration.
 *
 * Example:
 * ```kotlin
 * install(Authentication) {
 *     jwt {
 *         oauthDefaults()
 *         // Add custom validation if needed:
 *         // validate { credential -> ... }
 *     }
 * }
 * ```
 */
fun JWTAuthenticationProvider.Config.oauthDefaults() {
    val application = OAuthApplicationContext.get()
        ?: error("oauthDefaults() must be called after install(OAuth). Make sure OAuth plugin is installed first.")

    val registry = application.oauthOrNull
        ?: error("OAuth plugin must be installed before using oauthDefaults()")

    verifier(registry.jwtVerifier)
    validate { JWTPrincipal(it.payload) }
}

/**
 * Holds the current application during OAuth plugin configuration.
 * Used to pass application context to oauth() extension in install(Authentication).
 */
internal object OAuthApplicationContext {
    private val current = ThreadLocal<Application>()

    fun set(application: Application) {
        current.set(application)
    }

    fun get(): Application? = current.get()

    fun clear() {
        current.remove()
    }
}

/**
 * OAuth authentication provider configuration.
 * Like Ktor's jwt { } or basic { } provider configuration.
 *
 * Example:
 * ```kotlin
 * install(Authentication) {
 *     oauth {
 *         realm = "My API"
 *         validate { credential ->
 *             JWTPrincipal(credential.payload)
 *         }
 *     }
 *     oauth("calendar") {
 *         realm = "Calendar API"
 *     }
 * }
 * ```
 */
@OAuthDsl
class OAuthProviderConfig(val name: String?) {
    /** JWT realm for WWW-Authenticate header. Defaults to JWT issuer if null. */
    var realm: String? = null

    /** Per-provider validation function */
    internal var validateFn: (suspend JWTCredential.() -> Principal?)? = null

    /**
     * Validate JWT credentials and return a Principal.
     * Like Ktor's validate {} block.
     *
     * Called after JWT signature is verified and global auth server client check passes.
     * Return null to reject, or a Principal to allow.
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
    fun validate(block: suspend JWTCredential.() -> Principal?) {
        validateFn = block
    }
}

/**
 * Configure JWT authentication using OAuth-issued tokens (shorthand).
 * Requires the OAuth plugin to be installed first.
 *
 * This is the recommended approach - includes session key resolution and client validation.
 *
 * For manual configuration, use Ktor's `jwt()` with [oauthDefaults]:
 * ```kotlin
 * install(Authentication) {
 *     jwt { oauthDefaults() }
 * }
 * ```
 *
 * Example:
 * ```kotlin
 * install(Authentication) {
 *     oauthJwt()
 *     oauthJwt("calendar") {
 *         realm = "Calendar API"
 *     }
 * }
 * ```
 */
fun AuthenticationConfig.oauthJwt(
    name: String? = null,
    block: OAuthProviderConfig.() -> Unit = {}
) {
    val providerConfig = OAuthProviderConfig(name).apply(block)

    // Get application from context (set by OAuth plugin during install)
    val application = OAuthApplicationContext.get()
        ?: error("oauth() must be called after install(OAuth). Make sure OAuth plugin is installed first.")

    // Get OAuth registry
    val registry = application.oauthOrNull
        ?: error("OAuth plugin must be installed before configuring oauth() authentication providers")

    val authServer = registry.localAuthServer
        ?: error("OAuth server not configured - use authorizationServer(LocalAuthServer) { } in install(OAuth)")

    val tokenIssuer = registry.getTokenIssuer()
        ?: error("Token issuer not configured")

    val jwtConfig = registry.config.server.jwt

    // Configure JWT authentication provider
    val jwtProviderConfig: JWTAuthenticationProvider.Config.() -> Unit = {
        realm = providerConfig.realm ?: jwtConfig.issuer
        verifier(
            JWT.require(tokenIssuer.algorithm)
                .withIssuer(jwtConfig.issuer)
                .build()
        )

        validate { credential ->
            val clientId = credential.payload.getClaim("client_id").asString()
                ?: return@validate null

            // 1. Global auth server client blocklist
            authServer.clientValidator?.let { validator ->
                if (!validator(clientId)) return@validate null
            }

            // Resolve session key using configured resolver or default to client_id
            val sessionKeyResolver = application.attributes.getOrNull(SessionKeyResolverKey)
            val sessionKey = sessionKeyResolver?.invoke(credential.payload) ?: clientId

            // Set call attributes for session resolution
            request.call.attributes.put(BearerSessionKeyAttributeKey, sessionKey)
            credential.payload.getClaim(SessionKeyClaimsProvider.SESSION_KEY_CLAIM).asString()?.let { key ->
                request.call.attributes.put(SessionKeyAttributeKey, key)
            }

            // 2. Provider-level validate {} (like Ktor's validate { })
            providerConfig.validateFn?.invoke(credential)
                ?: JWTPrincipal(credential.payload)
        }
    }

    // Register as default or named provider
    if (name == null) {
        jwt(configure = jwtProviderConfig)
    } else {
        jwt(name, configure = jwtProviderConfig)
    }
}
