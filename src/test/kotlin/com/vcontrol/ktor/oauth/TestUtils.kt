package com.vcontrol.ktor.oauth

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*

/**
 * PKCE Test Utilities
 * RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
 */

/**
 * Generate a cryptographically random code verifier.
 * RFC 7636 requires 43-128 characters from the unreserved character set.
 */
fun generateCodeVerifier(): String {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

/**
 * Generate S256 code challenge from verifier.
 * challenge = BASE64URL(SHA256(verifier))
 */
fun generateCodeChallenge(codeVerifier: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(codeVerifier.toByteArray(Charsets.US_ASCII))
    return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
}

/**
 * Extract authorization code from redirect URL.
 * Example: http://localhost/callback?code=abc123 -> abc123
 */
fun extractCodeFromRedirectUrl(url: String): String? {
    val regex = Regex("[?&]code=([^&]+)")
    return regex.find(url)?.groupValues?.get(1)
}
