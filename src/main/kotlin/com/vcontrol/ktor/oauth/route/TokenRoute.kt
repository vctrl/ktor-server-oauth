package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.oauth
import com.vcontrol.ktor.oauth.AuthCodeStorage
import com.vcontrol.ktor.oauth.config.OAuthConfig
import com.vcontrol.ktor.oauth.config.ServerConfig
import com.vcontrol.ktor.oauth.model.CodeChallengeMethod
import com.vcontrol.ktor.oauth.model.GrantType
import com.vcontrol.ktor.oauth.model.OAuthError
import com.vcontrol.ktor.oauth.model.TokenRequest
import com.vcontrol.ktor.oauth.model.TokenResponse
import com.vcontrol.ktor.oauth.token.JwtTokenIssuer
import com.vcontrol.ktor.oauth.baseUrl
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
 * Supports client_credentials and authorization_code grant types
 * RFC 6749: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 */
fun Routing.configureTokenRoutes() {
    val oauthConfig = application.oauth.config
    val serverConfig = oauthConfig.server
    val authCodeStorage = application.oauth.authCodeStorage

    // Token Endpoint (Client Credentials Grant & Authorization Code Grant)
    post(serverConfig.endpoint(serverConfig.endpoints.token)) {
        try {
            val request = call.receiveTokenRequest()

            // Route to appropriate grant type handler
            when (request.grantType) {
                GrantType.ClientCredentials -> handleClientCredentialsGrant(request, serverConfig)
                GrantType.AuthorizationCode -> handleAuthorizationCodeGrant(request, serverConfig, authCodeStorage)
                GrantType.RefreshToken -> {
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
 * Receive token request from either form-urlencoded or JSON body
 */
private suspend fun ApplicationCall.receiveTokenRequest(): TokenRequest {
    return try {
        // Try form-urlencoded first (OAuth spec default)
        val params = receiveParameters()
        val grantTypeStr = params["grant_type"]
            ?: throw IllegalArgumentException("grant_type is required")
        TokenRequest(
            grantType = parseGrantType(grantTypeStr),
            clientId = params["client_id"],
            clientName = params["client_name"],
            clientSecret = params["client_secret"],
            scope = params["scope"],
            code = params["code"],
            redirectUri = params["redirect_uri"],
            codeVerifier = params["code_verifier"]
        )
    } catch (e: Exception) {
        // Fall back to JSON body
        receive<TokenRequest>()
    }
}

/**
 * Parse grant_type string to GrantType enum
 */
private fun parseGrantType(value: String): GrantType = when (value) {
    "authorization_code" -> GrantType.AuthorizationCode
    "client_credentials" -> GrantType.ClientCredentials
    "refresh_token" -> GrantType.RefreshToken
    else -> throw IllegalArgumentException("Unsupported grant_type: $value")
}

private suspend fun RoutingContext.issueTokenResponse(
    tokenIssuer: JwtTokenIssuer,
    clientId: String,
    clientName: String?,
    scope: String?,
    expiration: Duration = JwtTokenIssuer.DEFAULT_EXPIRATION,
    additionalClaims: Map<String, Any?> = emptyMap(),
    encryptedClaims: Map<String, String> = emptyMap()
) {
    val accessToken = tokenIssuer.createAccessToken(clientId, clientName, expiration, additionalClaims, encryptedClaims)
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
 * Handle client_credentials grant type.
 * Uses the DSL-configured validator.
 * Supports provider-specific validators via ?resource= query param (RFC 8707).
 */
private suspend fun RoutingContext.handleClientCredentialsGrant(
    request: TokenRequest,
    serverConfig: ServerConfig
) {
    val clientId = request.clientId
    val clientSecret = request.clientSecret

    // Validate client credentials
    if (clientId == null || clientSecret == null) {
        val error = OAuthError(
            error = OAuthError.INVALID_REQUEST,
            errorDescription = "client_id and client_secret are required"
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Get provider from ?resource= query param (RFC 8707)
    val providerName = call.request.queryParameters["resource"]
    val registry = call.application.oauth

    // Validate provider exists if specified
    if (providerName != null && !registry.authProviders.containsKey(providerName)) {
        val error = OAuthError(
            error = OAuthError.INVALID_REQUEST,
            errorDescription = "Unknown resource: $providerName"
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Get validator from local auth server configuration
    val localAuthServer = registry.localAuthServer
    val validator = localAuthServer?.clientCredentialsValidator
    if (validator == null) {
        val error = OAuthError(
            error = OAuthError.UNSUPPORTED_GRANT_TYPE,
            errorDescription = "client_credentials grant not configured. Use clientCredentials { } in authorizationServer { } DSL."
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Check credentials using DSL-configured validator
    if (!validator(clientId, clientSecret)) {
        val error = OAuthError(
            error = OAuthError.INVALID_CLIENT,
            errorDescription = "Invalid client credentials"
        )
        call.response.header("WWW-Authenticate", "Bearer realm=\"${call.baseUrl}\"")
        call.respond(HttpStatusCode.Unauthorized, error)
        return
    }

    // Get token issuer
    val tokenIssuer = registry.getTokenIssuer()
        ?: error("Token issuer not configured")

    // Use auth server's token expiration if configured, else default from config
    val expiration = localAuthServer.tokenExpiration ?: serverConfig.tokenExpiration
    issueTokenResponse(tokenIssuer, clientId, request.clientName, request.scope, expiration)
}

/**
 * Handle authorization_code grant type with PKCE.
 * Uses provider context from the stored auth code for token configuration.
 */
private suspend fun RoutingContext.handleAuthorizationCodeGrant(
    request: TokenRequest,
    serverConfig: ServerConfig,
    authCodeStorage: AuthCodeStorage
) {
    val code = request.code
    val clientId = request.clientId
    val redirectUri = request.redirectUri
    val codeVerifier = request.codeVerifier

    // Validate required parameters
    if (code == null || clientId == null || redirectUri == null || codeVerifier == null) {
        val error = OAuthError(
            error = OAuthError.INVALID_REQUEST,
            errorDescription = "code, client_id, redirect_uri, and code_verifier are required"
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Consume and validate authorization code
    val authCode = authCodeStorage.consume(code)
    if (authCode == null) {
        val error = OAuthError(
            error = OAuthError.INVALID_GRANT,
            errorDescription = "Invalid or expired authorization code"
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Verify client_id matches
    if (authCode.clientId != clientId) {
        val error = OAuthError(
            error = OAuthError.INVALID_GRANT,
            errorDescription = "client_id does not match authorization code"
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Verify redirect_uri matches
    if (authCode.redirectUri != redirectUri) {
        val error = OAuthError(
            error = OAuthError.INVALID_GRANT,
            errorDescription = "redirect_uri does not match authorization request"
        )
        call.respond(HttpStatusCode.BadRequest, error)
        return
    }

    // Verify PKCE code_verifier
    if (!verifyPkce(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
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
    val expiration = localAuthServer?.tokenExpiration ?: serverConfig.tokenExpiration

    // Get token issuer
    val tokenIssuer = registry.getTokenIssuer()
        ?: error("Token issuer not configured")

    // Pass provision claims from auth code to be embedded in the JWT
    issueTokenResponse(tokenIssuer, clientId, request.clientName, authCode.scope, expiration, authCode.claims, authCode.encryptedClaims)
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
