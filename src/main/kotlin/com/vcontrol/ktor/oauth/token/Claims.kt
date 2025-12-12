package com.vcontrol.ktor.oauth.token

import com.auth0.jwt.interfaces.Payload
import com.vcontrol.ktor.oauth.CryptoContext
import com.vcontrol.ktor.oauth.OAuthDsl
import com.vcontrol.ktor.sessions.AesGcmEncryption
import kotlinx.serialization.Serializable
import java.util.Base64

/**
 * Builder for JWT claims during provision flow.
 *
 * Provides a clean API for setting both plain and encrypted claims:
 * ```kotlin
 * complete {
 *     withClaim("username", "paul")
 *     withEncryptedClaim("api_key", "secret-123")
 * }
 * ```
 */
@OAuthDsl
class ClaimsBuilder {
    private val plainClaims = mutableMapOf<String, Any?>()
    private val encryptedClaims = mutableMapOf<String, String>()

    /**
     * Add a plain claim to the token.
     */
    fun withClaim(name: String, value: String): ClaimsBuilder {
        plainClaims[name] = value
        return this
    }

    fun withClaim(name: String, value: Int): ClaimsBuilder {
        plainClaims[name] = value
        return this
    }

    fun withClaim(name: String, value: Long): ClaimsBuilder {
        plainClaims[name] = value
        return this
    }

    fun withClaim(name: String, value: Double): ClaimsBuilder {
        plainClaims[name] = value
        return this
    }

    fun withClaim(name: String, value: Boolean): ClaimsBuilder {
        plainClaims[name] = value
        return this
    }

    /**
     * Add an encrypted claim to the token.
     * The value will be encrypted with the server key at token creation time.
     * Use [Payload.decryptClaim] to read it back.
     */
    fun withEncryptedClaim(name: String, value: String): ClaimsBuilder {
        encryptedClaims[name] = value
        return this
    }

    /**
     * Build the provision claims for storage.
     */
    internal fun build(): ProvisionClaims = ProvisionClaims(
        plain = plainClaims.mapValues { (_, v) -> v?.toString() ?: "" }.filterValues { it.isNotEmpty() },
        encrypted = encryptedClaims.toMap()
    )
}

/**
 * Serializable storage for provision claims.
 */
@Serializable
data class ProvisionClaims(
    val plain: Map<String, String> = emptyMap(),
    val encrypted: Map<String, String> = emptyMap()
) {
    fun isEmpty(): Boolean = plain.isEmpty() && encrypted.isEmpty()
}

// =============================================================================
// Extension functions for reading encrypted claims from JWT
// =============================================================================

/**
 * Decrypt an encrypted claim from the JWT payload.
 *
 * @param name The claim name
 * @param crypto The crypto context for decryption
 * @return The decrypted value, or null if claim doesn't exist
 */
fun Payload.decryptClaim(name: String, crypto: CryptoContext): String? {
    val encrypted = getClaim(name)?.asString() ?: return null
    val encryptionKey = Base64.getUrlEncoder().withoutPadding().encodeToString(crypto.claimEncryptKey)
    return AesGcmEncryption.decode(encrypted, encryptionKey)
}
