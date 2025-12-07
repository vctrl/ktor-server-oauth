package com.vcontrol.ktor.oauth.model

import com.vcontrol.ktor.oauth.token.ProvisionClaims

/**
 * Authorization code storage (for authorization code flow with PKCE).
 * Includes provider context for token exchange.
 */
data class AuthorizationCode(
    val code: String,
    val clientId: String,
    /**
     * JWT ID generated at start of authorization flow.
     * Passed through to token issuance for session key continuity.
     */
    val jti: String,
    val redirectUri: String,
    val codeChallenge: String,
    val codeChallengeMethod: CodeChallengeMethod,
    val state: String?,
    val scope: String?,
    val createdAt: Long,
    val expiresAt: Long = createdAt + 600, // 10 minutes
    /**
     * OAuth provider name that issued this code.
     * Used during token exchange to look up provider-specific config.
     */
    val providerName: String? = null,
    /**
     * Claims from provision flow to embed in the JWT token.
     * Encrypted claims are marked and processed at token creation time.
     */
    val claims: ProvisionClaims = ProvisionClaims()
)
