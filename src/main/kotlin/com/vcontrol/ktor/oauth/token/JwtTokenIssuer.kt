package com.vcontrol.ktor.oauth.token

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.vcontrol.ktor.oauth.CryptoContext
import com.vcontrol.ktor.oauth.session.SessionEncryption
import java.util.*
import kotlin.time.Duration

/**
 * JWT-based token issuer for access token creation.
 * Uses HS256 signed JWTs.
 *
 * Token validation is handled by Ktor's jwt {} authentication provider.
 * This class only handles token creation.
 *
 * Supports extensible claims via [TokenClaimsProvider] implementations.
 */
class JwtTokenIssuer(
    val jwtIssuer: String = "ktor-oauth",
    val crypto: CryptoContext,
    private val claimsProviders: List<TokenClaimsProvider> = emptyList()
) {
    /** Algorithm for JWT signing/verification */
    val algorithm: Algorithm = Algorithm.HMAC256(crypto.jwtSecret)

    companion object {
        val DEFAULT_EXPIRATION: Duration = Duration.parse("90d")
    }

    fun createAccessToken(
        clientId: String,
        jti: String,
        clientName: String?,
        expiration: Duration,
        claims: ProvisionClaims = ProvisionClaims()
    ): String {
        val now = System.currentTimeMillis()

        val builder = JWT.create()
            .withIssuer(jwtIssuer)
            .withJWTId(jti)
            .withClaim("client_id", clientId)
            .withClaim("client_name", clientName)
            .withIssuedAt(Date(now))

        // ZERO = never expires (omit exp claim)
        if (expiration.isPositive()) {
            val expiresAt = Date(now + expiration.inWholeMilliseconds)
            builder.withExpiresAt(expiresAt)
        }

        // Process claims - split into plain and encrypted
        if (!claims.isEmpty()) {
            val (plainClaims, encryptedClaims) = claims.processForToken(crypto)

            // Add plain claims
            if (plainClaims.isNotEmpty()) {
                builder.withPayload(plainClaims)
            }

            // Add encrypted claims (encrypt with server key)
            if (encryptedClaims.isNotEmpty()) {
                val encryptionKey = Base64.getUrlEncoder().withoutPadding().encodeToString(crypto.claimEncryptKey)
                for ((key, value) in encryptedClaims) {
                    builder.withClaim(key, SessionEncryption.encrypt(value, encryptionKey))
                }
            }
        }

        // Apply claims providers AFTER (can override provision claims)
        // This ensures session_key from SessionKeyClaimsProvider can't be tampered
        claimsProviders.forEach { provider ->
            provider.addClaims(builder, clientId)
        }

        return builder.sign(algorithm)
    }
}
