package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.oauth
import com.vcontrol.ktor.oauth.AuthCodeStorage
import com.vcontrol.ktor.oauth.RequestContext
import com.vcontrol.ktor.oauth.config.ServerConfig
import com.vcontrol.ktor.oauth.model.CodeChallengeMethod
import com.vcontrol.ktor.oauth.model.AuthorizationIdentity
import com.vcontrol.ktor.oauth.model.OAuthError
import com.vcontrol.ktor.oauth.model.TokenRequest
import com.vcontrol.ktor.oauth.model.TokenResponse
import com.vcontrol.ktor.oauth.token.JwtTokenIssuer
import com.vcontrol.ktor.oauth.token.ProvisionClaims
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.security.MessageDigest
import java.util.*
import kotlin.time.Duration

/**
 * Configure OAuth Token endpoint
 * Supports authorization_code grant type with PKCE
 * RFC 6749: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 * RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
 */
fun Routing.configureTokenRoutes() {
    val oauthConfig = application.oauth.config
    val serverConfig = oauthConfig.server
    val authCodeStorage = application.oauth.authCodeStorage

    // Token Endpoint (Authorization Code Grant)
    post(serverConfig.endpoint(serverConfig.endpoints.token)) {
        try {
            val request = call.receiveTokenRequest()

            // Route to appropriate grant type handler using sealed class dispatch
            when (request) {
                is TokenRequest.AuthorizationCodeGrant -> handleAuthorizationCodeGrant(request, serverConfig, authCodeStorage)
                is TokenRequest.RefreshTokenGrant -> {
                    val error = OAuthError(
                        error = OAuthError.UNSUPPORTED_GRANT_TYPE,
                        errorDescription = "refresh_token grant not yet supported"
                    )
                    call.respond(HttpStatusCode.BadRequest, error)
                }
            }

        } catch (e: Exception) {
            val error = OAuthError(
                error = OAuthError.INVALID_REQUEST,
                errorDescription = "Invalid token request: ${e.message}"
            )
            call.respond(HttpStatusCode.BadRequest, error)
        }
    }
}

/**
 * Receive token request from form-urlencoded body and parse into sealed type.
 */
private suspend fun ApplicationCall.receiveTokenRequest(): TokenRequest {
    val params = receiveParameters()
    val grantType = params["grant_type"]
        ?: throw IllegalArgumentException("grant_type is required")

    return when (grantType) {
        "authorization_code" -> TokenRequest.AuthorizationCodeGrant(
            code = params["code"] ?: throw IllegalArgumentException("code is required"),
            redirectUri = params["redirect_uri"] ?: throw IllegalArgumentException("redirect_uri is required"),
            codeVerifier = params["code_verifier"] ?: throw IllegalArgumentException("code_verifier is required"),
            clientId = params["client_id"],  // Optional with PKCE
            clientSecret = params["client_secret"],  // For confidential clients (RFC 6749 Section 2.3)
            scope = params["scope"]
        )
        "refresh_token" -> TokenRequest.RefreshTokenGrant(
            refreshToken = params["refresh_token"] ?: throw IllegalArgumentException("refresh_token is required"),
            scope = params["scope"]
        )
        else -> throw IllegalArgumentException("Unsupported grant_type: $grantType")
    }
}

private suspend fun RoutingContext.issueTokenResponse(
    tokenIssuer: JwtTokenIssuer,
    identity: AuthorizationIdentity,
    scope: String?,
    expiration: Duration = JwtTokenIssuer.DEFAULT_EXPIRATION,
    claims: ProvisionClaims = ProvisionClaims()
) {
    val accessToken = tokenIssuer.createAccessToken(identity, expiration, claims)
    // expiresIn: 0 means never expires (per OAuth spec, omit if infinite)
    val expiresIn = if (expiration.isPositive()) expiration.inWholeSeconds else null

    val response = TokenResponse(
        accessToken = accessToken,
        tokenType = "Bearer",
        expiresIn = expiresIn,
        scope = scope
    )

    call.respond(HttpStatusCode.OK, response)
}

/**
 * Handle authorization_code grant type with PKCE.
 * Uses provider context from the stored auth code for token configuration.
 *
 * Note: client_id is optional when PKCE is used. Per RFC 7636, the code_verifier
 * proves the caller is the same party that initiated the authorization request.
 */
private suspend fun RoutingContext.handleAuthorizationCodeGrant(
    request: TokenRequest.AuthorizationCodeGrant,
    serverConfig: ServerConfig,
    authCodeStorage: AuthCodeStorage
) {
    // Consume and validate authorization code
    val authCode = authCodeStorage.consume(request.code)
    if (authCode == null) {
        val error = OAuthError(
            error = OAuthError.INVALID_GRANT,
            errorDescription = "Invalid or expired authorization code"
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Verify redirect_uri matches
    if (authCode.redirectUri != request.redirectUri) {
        val error = OAuthError(
            error = OAuthError.INVALID_GRANT,
            errorDescription = "redirect_uri does not match authorization request"
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Verify PKCE code_verifier (this proves the caller is legitimate)
    if (!verifyPkce(request.codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
        val error = OAuthError(
            error = OAuthError.INVALID_GRANT,
            errorDescription = "PKCE verification failed"
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Get token configuration from local auth server
    val registry = call.application.oauth
    val localAuthServer = registry.localAuthServer

    // Validate client credentials if configured (RFC 6749 Section 2.3)
    // For confidential clients, client_secret is required at /token
    // For public clients (open registration), client_secret is null and allowed
    val credentialsValidator = localAuthServer?.clientsConfig?.credentialsValidator
    if (credentialsValidator != null) {
        val clientId = request.clientId ?: authCode.identity.client.clientId
        val context = RequestContext(call.request, authCode.identity.providerName)
        if (!context.credentialsValidator(clientId, request.clientSecret)) {
            val error = OAuthError(
                error = OAuthError.INVALID_CLIENT,
                errorDescription = "Client authentication failed"
            )
            call.respond(HttpStatusCode.Unauthorized, error)
            return
        }
    }
    val expiration = localAuthServer?.tokenExpiration ?: serverConfig.tokenExpiration

    // Get token issuer
    val tokenIssuer = registry.getTokenIssuer()
        ?: error("Token issuer not configured")

    // Use the full identity from stored auth code (includes clientId, clientName, jti)
    issueTokenResponse(tokenIssuer, authCode.identity, authCode.scope, expiration, authCode.claims)
}

/**
 * Verify PKCE code verifier against code challenge
 * RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
 * @param codeVerifier The code verifier sent in the token request
 * @param codeChallenge The code challenge stored from the authorization request
 * @param codeChallengeMethod The method used (only S256 supported)
 * @return true if verification succeeds, false otherwise
 */
private fun verifyPkce(
    codeVerifier: String,
    codeChallenge: String,
    codeChallengeMethod: CodeChallengeMethod
): Boolean {
    if (codeChallengeMethod != CodeChallengeMethod.S256) {
        return false
    }

    try {
        // Compute SHA256(code_verifier)
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(codeVerifier.toByteArray(Charsets.US_ASCII))

        // Base64URL encode the hash
        val computedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash)

        // Compare with stored challenge
        return computedChallenge == codeChallenge
    } catch (e: Exception) {
        return false
    }
}
