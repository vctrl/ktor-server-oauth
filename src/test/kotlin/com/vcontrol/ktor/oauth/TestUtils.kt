package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.config.OAuthConfig
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*

/**
 * Helper class providing OAuth endpoint paths for tests.
 * Loads configuration from application.conf to ensure tests use correct paths.
 */
class OAuthEndpoints(config: OAuthConfig = OAuthConfig.load()) {
    private val server = config.server

    val register: String get() = server.endpoint(server.endpoints.register)
    val authorize: String get() = server.endpoint(server.endpoints.authorize)
    val token: String get() = server.endpoint(server.endpoints.token)
    val provision: String get() = server.endpoint(server.endpoints.provision)

    /** Get provision endpoint for a named provider */
    fun provision(providerName: String): String = "${provision}/$providerName"

    /** Well-known endpoints (not prefixed) */
    val authServerMetadata: String = "/.well-known/oauth-authorization-server"
    val protectedResourceMetadata: String = "/.well-known/oauth-protected-resource"
}

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
