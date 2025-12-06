package com.vcontrol.ktor.oauth

import io.ktor.server.application.Application
import io.ktor.util.AttributeKey
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

private val CryptoContextKey = AttributeKey<CryptoContext>("CryptoContext")

/**
 * Access the CryptoContext for this application.
 * Lazily initialized on first access using oauth.server.jwt.secretFile from config.
 */
val Application.crypto: CryptoContext
    get() = attributes.getOrNull(CryptoContextKey) ?: run {
        val secretFile = oauth.config.server.jwt.secretFile
        val ctx = CryptoContext(secretFile)
        attributes.put(CryptoContextKey, ctx)
        ctx
    }

/**
 * Cryptographic context for the OAuth server.
 * Provides JWT signing secret and derived session encryption/signing keys.
 *
 * Keys are persisted to disk so tokens remain valid across server restarts.
 */
class CryptoContext(secretFile: String) {
    private val secretPath: Path = Path.of(secretFile)
        .also { it.parent?.let { p -> Files.createDirectories(p) } }

    /** JWT signing secret - persisted for token validation across restarts */
    val jwtSecret: String = loadOrGenerateSecret(secretPath, 64)

    /** Session encryption key (AES-128) derived from JWT secret */
    val sessionEncryptKey: ByteArray = deriveKey(jwtSecret, "session-encrypt", 16)

    /** Session signing key (HMAC-SHA256) derived from JWT secret */
    val sessionSignKey: ByteArray = deriveKey(jwtSecret, "session-sign", 32)

    /** Claim encryption key (AES-256) for encrypting JWT claims */
    val claimEncryptKey: ByteArray = deriveKey(jwtSecret, "claim-encrypt", 32)

    /**
     * Derive a key from the JWT secret using SHA-256 with a purpose string.
     * This provides domain separation so different keys are derived for different uses.
     */
    private fun deriveKey(secret: String, purpose: String, size: Int): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(secret.toByteArray())
        digest.update(purpose.toByteArray())
        return digest.digest().copyOf(size)
    }

    private fun loadOrGenerateSecret(path: Path, size: Int): String {
        return if (Files.exists(path)) {
            Files.readString(path).trim()
        } else {
            val bytes = ByteArray(size)
            SecureRandom().nextBytes(bytes)
            val secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
            Files.writeString(path, secret)
            secret
        }
    }
}
