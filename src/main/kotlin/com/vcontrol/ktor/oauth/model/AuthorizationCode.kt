package com.vcontrol.ktor.oauth.model

/**
 * Authorization code storage (for authorization code flow with PKCE).
 * Includes provider context for token exchange.
 */
data class AuthorizationCode(
    val code: String,
    val clientId: String,
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
     * Custom claims from provision flow to embed in the JWT token.
     * Supports any JSON-compatible value (String, Number, Boolean, List, Map).
     */
    val claims: Map<String, Any?> = emptyMap(),
    /**
     * Encrypted claims from provision flow.
     * Values are plaintext here; encrypted with server key during token creation.
     */
    val encryptedClaims: Map<String, String> = emptyMap()
)
