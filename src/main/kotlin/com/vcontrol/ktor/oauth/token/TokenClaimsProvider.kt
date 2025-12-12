package com.vcontrol.ktor.oauth.token

import com.auth0.jwt.JWTCreator
import com.vcontrol.ktor.sessions.AesGcmEncryption

/**
 * Provider for custom JWT claims during token creation.
 *
 * Implementations add claims when tokens are issued. Claims are accessed
 * directly from the JWT payload via `call.jwtPrincipal.payload.getClaim()`.
 *
 * Example:
 * ```kotlin
 * object TenantClaimsProvider : TokenClaimsProvider {
 *     override fun addClaims(builder: JWTCreator.Builder, clientId: String) {
 *         builder.withClaim("tenant_id", lookupTenant(clientId))
 *     }
 * }
 *
 * // Access in routes:
 * val tenantId = call.jwtPrincipal?.payload?.getClaim("tenant_id")?.asString()
 * ```
 */
fun interface TokenClaimsProvider {
    /**
     * Add custom claims to the JWT builder during token creation.
     *
     * @param builder The JWT builder to add claims to
     * @param clientId The client ID for which the token is being created
     */
    fun addClaims(builder: JWTCreator.Builder, clientId: String)
}

/**
 * Built-in provider for session encryption key.
 *
 * When added to an OAuth provider, generates a unique AES-256 encryption key
 * per client and embeds it in their JWT. This key is used to encrypt session
 * data at rest, ensuring only the token holder can decrypt their session.
 *
 * Usage:
 * ```kotlin
 * oauth {
 *     claims(SessionKeyClaimsProvider)
 * }
 * ```
 *
 * The key is accessible via `call.sessionKey` after authentication.
 */
object SessionKeyClaimsProvider : TokenClaimsProvider {
    internal const val SESSION_KEY_CLAIM = "session_key"

    override fun addClaims(builder: JWTCreator.Builder, clientId: String) {
        builder.withClaim(SESSION_KEY_CLAIM, AesGcmEncryption.generateKey())
    }
}
