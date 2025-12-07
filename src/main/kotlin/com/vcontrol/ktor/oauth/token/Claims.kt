package com.vcontrol.ktor.oauth.token

import com.auth0.jwt.interfaces.Payload
import com.vcontrol.ktor.oauth.CryptoContext
import com.vcontrol.ktor.oauth.OAuthDsl
import com.vcontrol.ktor.oauth.session.SessionEncryption
import kotlinx.serialization.Serializable
import java.util.Base64

/**
 * Marker for encrypted claim values in storage.
 * Values prefixed with this are encrypted and need decryption when reading.
 */
private const val ENCRYPTED_PREFIX = "enc:"

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
 *
 * Encrypted claims are stored with a marker prefix and encrypted at token creation time.
 */
@OAuthDsl
class ClaimsBuilder {
    private val claims = mutableMapOf<String, Any?>()

    /**
     * Add a plain claim to the token.
     */
    fun withClaim(name: String, value: String): ClaimsBuilder {
        claims[name] = value
        return this
    }

    fun withClaim(name: String, value: Int): ClaimsBuilder {
        claims[name] = value
        return this
    }

    fun withClaim(name: String, value: Long): ClaimsBuilder {
        claims[name] = value
        return this
    }

    fun withClaim(name: String, value: Double): ClaimsBuilder {
        claims[name] = value
        return this
    }

    fun withClaim(name: String, value: Boolean): ClaimsBuilder {
        claims[name] = value
        return this
    }

    /**
     * Add an encrypted claim to the token.
     * The value will be encrypted with the server key at token creation time.
     * Use [Payload.decryptClaim] to read it back.
     */
    fun withEncryptedClaim(name: String, value: String): ClaimsBuilder {
        // Mark as encrypted - will be encrypted at token creation
        claims[name] = "$ENCRYPTED_PREFIX$value"
        return this
    }

    /**
     * Build the claims map for storage.
     */
    internal fun build(): Map<String, Any?> = claims.toMap()
}

/**
 * Serializable storage for provision claims.
 * Encrypted claims are marked with a prefix and encrypted at token creation.
 */
@Serializable
data class ProvisionClaims(
    val values: Map<String, String> = emptyMap()
) {
    companion object {
        fun from(claims: Map<String, Any?>): ProvisionClaims {
            val stringified = claims.mapValues { (_, v) -> v?.toString() ?: "" }
                .filterValues { it.isNotEmpty() }
            return ProvisionClaims(stringified)
        }
    }

    fun isEmpty(): Boolean = values.isEmpty()
}

/**
 * Process claims for JWT creation.
 * Encrypts values marked with the encrypted prefix.
 *
 * @return Pair of (plainClaims, encryptedClaims) maps
 */
internal fun ProvisionClaims.processForToken(crypto: CryptoContext): Pair<Map<String, Any?>, Map<String, String>> {
    val plain = mutableMapOf<String, Any?>()
    val encrypted = mutableMapOf<String, String>()

    for ((key, value) in values) {
        if (value.startsWith(ENCRYPTED_PREFIX)) {
            // Strip prefix and add to encrypted claims
            encrypted[key] = value.removePrefix(ENCRYPTED_PREFIX)
        } else {
            plain[key] = value
        }
    }

    return plain to encrypted
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
    return SessionEncryption.decrypt(encrypted, encryptionKey)
}
