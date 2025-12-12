package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OAuth 2.0 Token Request - sealed class hierarchy for type-safe grant handling.
 *
 * Supports:
 * - [AuthorizationCodeGrant]: Authorization code flow with PKCE (RFC 7636)
 * - [RefreshTokenGrant]: Refresh token flow (RFC 6749 Section 6)
 */
@Serializable
sealed class TokenRequest {
    /** Optional scope for the token */
    abstract val scope: String?

    /**
     * Authorization code grant (RFC 6749 Section 4.1, RFC 7636 for PKCE)
     * Client is authenticated via PKCE code_verifier.
     */
    @Serializable
    @SerialName("authorization_code")
    data class AuthorizationCodeGrant(
        val code: String,
        val redirectUri: String,
        val codeVerifier: String,
        /** Optional - if provided, must match stored auth code */
        val clientId: String? = null,
        /** Optional - for confidential clients (RFC 6749 Section 2.3) */
        val clientSecret: String? = null,
        override val scope: String? = null
    ) : TokenRequest()

    /**
     * Refresh token grant (RFC 6749 Section 6)
     */
    @Serializable
    @SerialName("refresh_token")
    data class RefreshTokenGrant(
        val refreshToken: String,
        override val scope: String? = null
    ) : TokenRequest()
}
