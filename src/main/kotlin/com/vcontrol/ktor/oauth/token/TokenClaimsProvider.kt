package com.vcontrol.ktor.oauth.token

import com.auth0.jwt.JWTCreator
import com.vcontrol.ktor.oauth.crypto
import com.vcontrol.ktor.oauth.session.SessionEncryption
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import java.util.*

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
        builder.withClaim(SESSION_KEY_CLAIM, SessionEncryption.generateKey())
    }
}

// ============================================================================
// Encrypted Claims Access Extensions
// ============================================================================

/**
 * Decrypt a claim that was set via `call.tokenClaims.encrypted["key"]` during provision.
 *
 * Returns null if:
 * - No JWT principal is present
 * - The claim doesn't exist
 * - Decryption fails
 *
 * Example:
 * ```kotlin
 * authenticate {
 *     get("/api/external") {
 *         val apiToken = call.decryptedClaim("api_token")
 *             ?: return@get call.respond(HttpStatusCode.Unauthorized)
 *         // Use apiToken to call external API
 *     }
 * }
 * ```
 */
fun ApplicationCall.decryptedClaim(name: String): String? {
    val principal = principal<JWTPrincipal>() ?: return null
    val encryptedValue = principal.payload.getClaim(name)?.asString() ?: return null

    val crypto = application.crypto
    val encryptionKey = Base64.getUrlEncoder().withoutPadding().encodeToString(crypto.claimEncryptKey)

    return try {
        SessionEncryption.decrypt(encryptedValue, encryptionKey)
    } catch (e: Exception) {
        null
    }
}

/**
 * Access decrypted claims via property accessor.
 *
 * Example:
 * ```kotlin
 * authenticate {
 *     get("/api/external") {
 *         val apiToken = call.decryptedClaims["api_token"]
 *         val refreshToken = call.decryptedClaims["refresh_token"]
 *     }
 * }
 * ```
 */
val ApplicationCall.decryptedClaims: DecryptedClaimsAccessor
    get() = DecryptedClaimsAccessor(this)

/**
 * Accessor for reading encrypted claims from JWT.
 * Provides map-like syntax for decrypting claims.
 */
class DecryptedClaimsAccessor(private val call: ApplicationCall) {
    operator fun get(name: String): String? = call.decryptedClaim(name)
}
