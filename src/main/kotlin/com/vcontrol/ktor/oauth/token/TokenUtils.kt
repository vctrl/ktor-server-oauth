package com.vcontrol.ktor.oauth.token

import java.security.SecureRandom
import java.util.*

/**
 * OAuth client credential generation utilities.
 */
object TokenUtils {

    /**
     * Generate a random client ID (16 bytes, URL-safe base64).
     */
    fun generateClientId(): String {
        val random = SecureRandom()
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * Generate a random client secret (32 bytes, URL-safe base64).
     */
    fun generateClientSecret(): String {
        val random = SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}
