package com.vcontrol.ktor.oauth.model

/**
 * Result of OAuth authorization processing.
 *
 * Simplified to pure OAuth results - registration handled by RegistrationResult.
 */
sealed class AuthorizationResult {
    /**
     * Redirect user back to client with authorization code
     */
    data class RedirectWithCode(
        val redirectUri: String,
        val code: String,
        val state: String?
    ) : AuthorizationResult()

    /**
     * Redirect user back to client with error
     */
    data class RedirectWithError(
        val redirectUri: String,
        val error: OAuthError,
        val state: String?
    ) : AuthorizationResult()

    /**
     * Return bad request error (cannot redirect)
     */
    data class BadRequest(
        val error: OAuthError
    ) : AuthorizationResult()
}
