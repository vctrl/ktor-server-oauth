package com.vcontrol.ktor.oauth.session

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM encryption utilities for session data.
 *
 * Key format: Base64 URL-safe encoded 32-byte (256-bit) key for JWT storage
 * Ciphertext format: [12-byte IV][ciphertext][16-byte auth tag]
 */
object SessionEncryption {
    private const val ALGORITHM = "AES/GCM/NoPadding"
    private const val KEY_SIZE_BITS = 256
    private const val IV_SIZE_BYTES = 12
    private const val TAG_SIZE_BITS = 128

    /**
     * Generate a new AES-256 key for session encryption.
     *
     * @return Base64 URL-safe encoded 32-byte key suitable for JWT storage
     */
    fun generateKey(): String {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(KEY_SIZE_BITS, SecureRandom())
        val key = keyGen.generateKey()
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key.encoded)
    }

    /**
     * Encrypt plaintext using the provided base64-encoded key.
     *
     * @param plaintext The text to encrypt
     * @param keyBase64 Base64 URL-safe encoded AES-256 key
     * @return Base64 URL-safe encoded ciphertext (IV + encrypted data + auth tag)
     */
    fun encrypt(plaintext: String, keyBase64: String): String {
        val key = decodeKey(keyBase64)
        val iv = ByteArray(IV_SIZE_BYTES).also { SecureRandom().nextBytes(it) }

        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_SIZE_BITS, iv))

        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

        // Combine: IV || ciphertext (includes auth tag)
        val combined = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(ciphertext, 0, combined, iv.size, ciphertext.size)

        return Base64.getUrlEncoder().withoutPadding().encodeToString(combined)
    }

    /**
     * Decrypt ciphertext using the provided base64-encoded key.
     *
     * @param ciphertextBase64 Base64 URL-safe encoded ciphertext
     * @param keyBase64 Base64 URL-safe encoded AES-256 key
     * @return Decrypted plaintext
     * @throws DecryptionException if decryption fails (wrong key, tampered data, etc.)
     */
    fun decrypt(ciphertextBase64: String, keyBase64: String): String {
        try {
            val key = decodeKey(keyBase64)
            val combined = Base64.getUrlDecoder().decode(ciphertextBase64)

            require(combined.size > IV_SIZE_BYTES) { "Ciphertext too short" }

            val iv = combined.copyOfRange(0, IV_SIZE_BYTES)
            val ciphertext = combined.copyOfRange(IV_SIZE_BYTES, combined.size)

            val cipher = Cipher.getInstance(ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_SIZE_BITS, iv))

            val plaintext = cipher.doFinal(ciphertext)
            return String(plaintext, Charsets.UTF_8)
        } catch (e: Exception) {
            throw DecryptionException("Failed to decrypt session data", e)
        }
    }

    private fun decodeKey(keyBase64: String): SecretKey {
        val keyBytes = Base64.getUrlDecoder().decode(keyBase64)
        require(keyBytes.size == KEY_SIZE_BITS / 8) {
            "Invalid key size: expected ${KEY_SIZE_BITS / 8} bytes, got ${keyBytes.size}"
        }
        return SecretKeySpec(keyBytes, "AES")
    }
}

/**
 * Exception thrown when session decryption fails.
 */
class DecryptionException(message: String, cause: Throwable? = null) : Exception(message, cause)
