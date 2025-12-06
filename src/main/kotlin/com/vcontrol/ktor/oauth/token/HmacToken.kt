package com.vcontrol.ktor.oauth.token

import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Generates and validates short-lived HMAC-based tokens.
 *
 * Token format: base64(subject:expiryTimestamp:hmac)
 * The HMAC covers subject + expiryTimestamp to prevent tampering.
 *
 * Used for time-limited authentication tokens (e.g., provision URLs, password resets).
 */
object HmacToken {
    private const val ALGORITHM = "HmacSHA256"

    /**
     * Default validity period for tokens.
     */
    val DEFAULT_VALIDITY: Duration = 15.minutes

    /**
     * Generate a token for the given subject.
     *
     * @param subject The subject to generate a token for (e.g., client ID, user ID)
     * @param secret The HMAC secret
     * @param validity How long the token should be valid
     * @return Base64-encoded token string
     */
    fun generate(
        subject: String,
        secret: String,
        validity: Duration = DEFAULT_VALIDITY
    ): String {
        val expiry = System.currentTimeMillis() + validity.inWholeMilliseconds
        val data = "$subject:$expiry"
        val hmac = hmac(data, secret)
        return Base64.getUrlEncoder().withoutPadding().encodeToString("$data:$hmac".toByteArray())
    }

    /**
     * Validate a token and extract the subject.
     *
     * @param token The token to validate
     * @param secret The HMAC secret
     * @return The subject if valid and not expired, null otherwise
     */
    fun validate(token: String, secret: String): String? {
        return try {
            val decoded = String(Base64.getUrlDecoder().decode(token))
            val parts = decoded.split(":")
            if (parts.size != 3) return null

            val (subject, expiryStr, providedHmac) = parts
            val expiry = expiryStr.toLongOrNull() ?: return null

            // Check expiry
            if (System.currentTimeMillis() > expiry) return null

            // Verify HMAC
            val expectedHmac = hmac("$subject:$expiryStr", secret)
            if (!constantTimeEquals(providedHmac, expectedHmac)) return null

            subject
        } catch (e: Exception) {
            null
        }
    }

    private fun hmac(data: String, secret: String): String {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(secret.toByteArray(), ALGORITHM))
        val hash = mac.doFinal(data.toByteArray())
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }

    /**
     * Constant-time string comparison to prevent timing attacks.
     */
    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].code xor b[i].code)
        }
        return result == 0
    }
}
