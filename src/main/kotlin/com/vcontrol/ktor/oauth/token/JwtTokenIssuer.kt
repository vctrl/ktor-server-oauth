package com.vcontrol.ktor.oauth.token

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.vcontrol.ktor.oauth.CryptoContext
import com.vcontrol.ktor.oauth.model.AuthorizationIdentity
import com.vcontrol.ktor.oauth.model.ClientIdentity
import com.vcontrol.ktor.sessions.AesGcmEncryption
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

    /**
     * Create an access token from the authorization identity.
     *
     * @param identity The authorization identity containing client info and jti
     * @param expiration Token expiration duration (Duration.ZERO = never expires)
     * @param claims Additional claims from provision flow
     */
    fun createAccessToken(
        identity: AuthorizationIdentity,
        expiration: Duration,
        claims: ProvisionClaims = ProvisionClaims()
    ): String {
        val now = System.currentTimeMillis()

        val builder = JWT.create()
            .withIssuer(jwtIssuer)
            .withJWTId(identity.jti)
            .withClaim("client_id", identity.client.clientId)
            .withIssuedAt(Date(now))

        // Only add client_name if present (Dynamic clients only)
        if (identity.client is ClientIdentity.Dynamic) builder.withClaim("client_name", identity.client.clientName)

        // ZERO = never expires (omit exp claim)
        if (expiration.isPositive()) {
            val expiresAt = Date(now + expiration.inWholeMilliseconds)
            builder.withExpiresAt(expiresAt)
        }

        // Add provision claims
        if (!claims.isEmpty()) {
            if (claims.plain.isNotEmpty()) {
                builder.withPayload(claims.plain)
            }
            if (claims.encrypted.isNotEmpty()) {
                val encryptionKey = Base64.getUrlEncoder().withoutPadding().encodeToString(crypto.claimEncryptKey)
                for ((key, value) in claims.encrypted) {
                    builder.withClaim(key, AesGcmEncryption.encode(value, encryptionKey))
                }
            }
        }

        // Apply claims providers AFTER (can override provision claims)
        // This ensures session_key from SessionKeyClaimsProvider can't be tampered
        claimsProviders.forEach { provider ->
            provider.addClaims(builder, identity.client.clientId)
        }

        return builder.sign(algorithm)
    }
}
