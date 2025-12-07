package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.token.TokenUtils
import com.vcontrol.ktor.oauth.model.AuthorizationCode
import com.vcontrol.ktor.oauth.model.AuthorizationIdentity
import com.vcontrol.ktor.oauth.model.AuthorizationRequest
import com.vcontrol.ktor.oauth.model.AuthorizationResult
import com.vcontrol.ktor.oauth.model.CodeChallengeMethod
import com.vcontrol.ktor.oauth.model.OAuthError
import com.vcontrol.ktor.oauth.model.ResponseType

/**
 * Handles pure OAuth authorization flow.
 *
 * This service validates OAuth parameters and generates authorization codes.
 * Registration stages are handled separately by RegistrationPipeline.
 *
 * Security is ensured by PKCE:
 * - AuthorizationCode stores clientId, redirectUri, codeChallenge
 * - Token exchange validates all these match the original request
 * - No client pre-registration needed
 *
 * Flow:
 * 1. /authorize checks if registration is required (via RegistrationPipeline.isRegistrationRequired())
 * 2. If registration needed → redirect to registration path
 * 3. Registration completes pipeline and redirects back
 * 4. /authorize validates OAuth params and generates code
 */
class AuthorizationProvider(
    private val authCodeStorage: AuthCodeStorage
) {
    /**
     * Process authorization request - validate and generate code.
     *
     * Assumes setup is already complete (session config exists).
     *
     * @param request OAuth authorization request parameters
     * @param identity Authorization identity (clientId, jti, providerName)
     * @param provisionClaims Claims set during provision flow via call.tokenClaims
     * @param encryptedClaims Claims set via call.tokenClaims.encrypted (encrypted at token creation)
     * @return AuthorizationResult indicating next action
     */
    fun processAuthorization(
        request: AuthorizationRequest,
        identity: AuthorizationIdentity,
        provisionClaims: Map<String, Any?> = emptyMap(),
        encryptedClaims: Map<String, String> = emptyMap()
    ): AuthorizationResult {
        // Validate OAuth parameters
        val validationResult = validateAuthorizationRequest(request)
        if (validationResult != null) {
            return validationResult
        }

        // Generate authorization code with identity and provision claims
        return generateAuthorizationCode(request, identity, provisionClaims, encryptedClaims)
    }

    /**
     * Validate OAuth authorization request parameters.
     *
     * Note: We don't validate that the client exists. Security is provided by PKCE:
     * the authorization code stores the code_challenge, and only the original
     * requestor (who has the code_verifier) can exchange it for a token.
     *
     * @return AuthorizationResult error if validation fails, null if valid
     */
    private fun validateAuthorizationRequest(request: AuthorizationRequest): AuthorizationResult? {
        // Validate response_type
        if (request.responseType != ResponseType.Code) {
            return AuthorizationResult.RedirectWithError(
                redirectUri = request.redirectUri,
                error = OAuthError(
                    error = "unsupported_response_type",
                    errorDescription = "Only 'code' response type is supported"
                ),
                state = request.state
            )
        }

        // Validate required parameters
        if (request.clientId.isBlank()) {
            return AuthorizationResult.BadRequest(
                error = OAuthError(
                    error = OAuthError.INVALID_REQUEST,
                    errorDescription = "client_id is required"
                )
            )
        }

        if (request.redirectUri.isBlank()) {
            return AuthorizationResult.BadRequest(
                error = OAuthError(
                    error = OAuthError.INVALID_REQUEST,
                    errorDescription = "redirect_uri is required"
                )
            )
        }

        // Validate PKCE parameters (required by OAuth spec)
        if (request.codeChallenge.isBlank()) {
            return AuthorizationResult.RedirectWithError(
                redirectUri = request.redirectUri,
                error = OAuthError(
                    error = OAuthError.INVALID_REQUEST,
                    errorDescription = "code_challenge is required (PKCE)"
                ),
                state = request.state
            )
        }

        if (request.codeChallengeMethod != CodeChallengeMethod.S256) {
            return AuthorizationResult.RedirectWithError(
                redirectUri = request.redirectUri,
                error = OAuthError(
                    error = OAuthError.INVALID_REQUEST,
                    errorDescription = "Only S256 code_challenge_method is supported"
                ),
                state = request.state
            )
        }

        return null // Validation passed
    }

    /**
     * Generate authorization code and prepare redirect response.
     * Includes identity and provision claims for token exchange.
     */
    private fun generateAuthorizationCode(
        request: AuthorizationRequest,
        identity: AuthorizationIdentity,
        provisionClaims: Map<String, Any?>,
        encryptedClaims: Map<String, String>
    ): AuthorizationResult {
        val authCode = TokenUtils.generateClientSecret()
        val now = System.currentTimeMillis() / 1000

        val authorization = AuthorizationCode(
            code = authCode,
            clientId = identity.clientId,
            jti = identity.jti,
            redirectUri = request.redirectUri,
            codeChallenge = request.codeChallenge,
            codeChallengeMethod = request.codeChallengeMethod,
            state = request.state,
            scope = request.scope,
            createdAt = now,
            providerName = identity.providerName,
            claims = provisionClaims,
            encryptedClaims = encryptedClaims
        )

        authCodeStorage.store(authorization)

        return AuthorizationResult.RedirectWithCode(
            redirectUri = request.redirectUri,
            code = authCode,
            state = request.state
        )
    }
}
