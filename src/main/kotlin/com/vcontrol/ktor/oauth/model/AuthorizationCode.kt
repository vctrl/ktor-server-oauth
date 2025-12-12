package com.vcontrol.ktor.oauth.model

import com.vcontrol.ktor.oauth.token.ProvisionClaims

/**
 * Authorization code storage (for authorization code flow with PKCE).
 * Embeds the full [AuthorizationIdentity] for token exchange.
 */
data class AuthorizationCode(
    val code: String,
    /** Full authorization identity including client info */
    val identity: AuthorizationIdentity,
    val redirectUri: String,
    val codeChallenge: String,
    val codeChallengeMethod: CodeChallengeMethod,
    val state: String?,
    val scope: String?,
    val createdAt: Long,
    val expiresAt: Long = createdAt + 600, // 10 minutes
    /**
     * Claims from provision flow to embed in the JWT token.
     * Encrypted claims are marked and processed at token creation time.
     */
    val claims: ProvisionClaims = ProvisionClaims()
)
