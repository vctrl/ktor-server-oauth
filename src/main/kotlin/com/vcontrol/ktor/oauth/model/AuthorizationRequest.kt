package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable

/**
 * OAuth authorization request parameters.
 * Immutable representation of the OAuth params from the initial /authorize request.
 * Stored in session cookie to preserve state through the registration flow.
 */
@Serializable
data class AuthorizationRequest(
    val responseType: ResponseType,
    val clientId: String,
    val redirectUri: String,
    val codeChallenge: String,
    val codeChallengeMethod: CodeChallengeMethod,
    val state: String? = null,
    val scope: String? = null,
    /**
     * OAuth provider name for this authorization.
     * Determines which provider's registration handler and token config to use.
     */
    val providerName: String? = null
)
