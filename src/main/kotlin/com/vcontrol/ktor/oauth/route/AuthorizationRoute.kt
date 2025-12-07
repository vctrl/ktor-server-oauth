package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.oauth
import com.vcontrol.ktor.oauth.model.AuthorizationIdentity
import com.vcontrol.ktor.oauth.model.AuthorizationRequest
import com.vcontrol.ktor.oauth.model.AuthorizationResult
import com.vcontrol.ktor.oauth.model.CodeChallengeMethod
import com.vcontrol.ktor.oauth.model.OAuthError
import com.vcontrol.ktor.oauth.model.ResponseType
import com.vcontrol.ktor.oauth.AuthorizationProvider
import com.vcontrol.ktor.oauth.model.ProvisionSession
import com.vcontrol.ktor.oauth.token.ProvisionClaims
import java.util.UUID
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*

private val logger = KotlinLogging.logger {}

/**
 * Configure OAuth Authorization endpoint
 * Authorization Code Flow with PKCE
 * RFC 6749: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 * RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
 * RFC 8707: https://datatracker.ietf.org/doc/html/rfc8707 (Resource Indicators)
 *
 * Supports multiple resources via the resource query parameter (RFC 8707).
 * The resource parameter maps to internal resource names for provision/token configuration.
 * Resource context is preserved in session through the provision flow.
 *
 * Flow:
 * 1. New request: store OAuth params (including resource) in session, redirect to /provision if provision configured
 * 2. /provision completes and redirects back to /authorize (no params, but AuthorizationRequest cookie exists)
 * 3. Resume from session, validate OAuth params, generate code with resource context
 */
fun Routing.configureAuthorizationRoutes() {
    val oauthConfig = application.oauth.config
    val serverConfig = oauthConfig.server
    val authProvider = application.oauth.authorizationProvider

    get(serverConfig.endpoint(serverConfig.endpoints.authorize)) {
        try {
            val params = call.request.queryParameters
            val savedRequest = call.sessions.get<AuthorizationRequest>()
            val registry = application.oauth

            // Determine if this is a new request or returning from /provision
            val isReturningFromProvision = savedRequest != null && params["client_id"] == null

            val request: AuthorizationRequest
            val identity: AuthorizationIdentity
            val claims: ProvisionClaims

            if (isReturningFromProvision) {
                // Returning from /provision - use saved request (includes provider) and clear it
                call.sessions.clear<AuthorizationRequest>()
                request = savedRequest!!

                // Read identity, claims from provision session and clear it
                val provisionSession = call.sessions.get<ProvisionSession>()
                    ?: error("ProvisionSession missing after provision flow")
                identity = provisionSession.identity
                claims = provisionSession.claims
                call.sessions.clear<ProvisionSession>()
            } else {
                // New authorization request - get resource from resource param (RFC 8707)
                val providerName = params["resource"]

                // Validate resource exists if specified
                if (providerName != null && !registry.authProviders.containsKey(providerName)) {
                    call.respond(HttpStatusCode.BadRequest, OAuthError(
                        error = OAuthError.INVALID_REQUEST,
                        errorDescription = "Unknown resource: $providerName"
                    ))
                    return@get
                }

                request = AuthorizationRequest(
                    responseType = parseResponseType(params["response_type"]),
                    clientId = params["client_id"] ?: "",
                    redirectUri = params["redirect_uri"] ?: "",
                    codeChallenge = params["code_challenge"] ?: "",
                    codeChallengeMethod = parseCodeChallengeMethod(params["code_challenge_method"]),
                    state = params["state"],
                    scope = params["scope"],
                    providerName = providerName
                )

                // Generate jti upfront using configured provider or UUID default
                val jwtIdProvider = registry.localAuthServer?.jwtIdProvider
                val jti = jwtIdProvider?.invoke(request.clientId) ?: UUID.randomUUID().toString()

                // Create immutable identity context for this authorization flow
                identity = AuthorizationIdentity(
                    clientId = request.clientId,
                    jti = jti,
                    providerName = providerName
                )

                claims = ProvisionClaims()
            }

            // Only redirect to provision if:
            // 1. Provision is configured for this provider
            // 2. This is NOT a return from /provision (we just completed provision)
            if (!isReturningFromProvision && registry.hasProvision(identity.providerName)) {
                // Save OAuth request and create ProvisionSession with identity before redirecting
                call.sessions.set(request)
                call.sessions.set(ProvisionSession(
                    identity = identity,
                    nextUrl = serverConfig.endpoint(serverConfig.endpoints.authorize)
                ))
                // Named providers have provision at /provision/{providerName}
                val provisionEndpoint = serverConfig.endpoint(serverConfig.endpoints.provision)
                val provisionPath = when (identity.providerName) {
                    null -> provisionEndpoint
                    else -> "$provisionEndpoint/${identity.providerName}"
                }
                call.respondRedirect(provisionPath)
                return@get
            }

            // Provision complete (or not required) - process authorization directly
            // Pass identity and claims for auth code storage
            handleAuthorizationResult(
                authProvider.processAuthorization(request, identity, claims),
                identity.clientId
            )

        } catch (e: Exception) {
            logger.error(e) { "Authorization error" }
            e.printStackTrace()
            call.respond(HttpStatusCode.InternalServerError, mapOf(
                "error" to "server_error",
                "error_description" to "Internal server error: ${e.message}"
            ))
        }
    }
}

/**
 * Handle authorization result
 */
private suspend fun RoutingContext.handleAuthorizationResult(
    result: AuthorizationResult,
    clientId: String
) {
    when (result) {
        is AuthorizationResult.RedirectWithCode -> {
            logger.trace { "Authorization successful for client '$clientId'" }
            val redirectUrl = buildRedirectUrl(
                redirectUri = result.redirectUri,
                code = result.code,
                state = result.state
            )
            call.respondRedirect(redirectUrl)
        }

        is AuthorizationResult.RedirectWithError -> {
            val redirectUrl = buildErrorRedirectUrl(
                redirectUri = result.redirectUri,
                error = result.error,
                state = result.state
            )
            call.respondRedirect(redirectUrl)
        }

        is AuthorizationResult.BadRequest -> {
            call.respond(HttpStatusCode.BadRequest, result.error)
        }
    }
}

/**
 * Build redirect URL with authorization code
 */
private fun buildRedirectUrl(redirectUri: String, code: String, state: String?): String {
    return buildString {
        append(redirectUri)
        append("?code=")
        append(code)
        if (state != null) {
            append("&state=")
            append(state)
        }
    }
}

/**
 * Build redirect URL with error
 */
private fun buildErrorRedirectUrl(
    redirectUri: String,
    error: OAuthError,
    state: String?
): String {
    return buildString {
        append(redirectUri)
        append("?error=")
        append(error.error)
        error.errorDescription?.let {
            append("&error_description=")
            append(it)
        }
        if (state != null) {
            append("&state=")
            append(state)
        }
    }
}

private fun parseResponseType(value: String?): ResponseType = when (value) {
    "code" -> ResponseType.Code
    "token" -> ResponseType.Token
    null -> throw IllegalArgumentException("response_type is required")
    else -> throw IllegalArgumentException("Unsupported response_type: $value")
}

private fun parseCodeChallengeMethod(value: String?): CodeChallengeMethod = when (value) {
    "S256" -> CodeChallengeMethod.S256
    "plain" -> CodeChallengeMethod.Plain
    null -> throw IllegalArgumentException("code_challenge_method is required")
    else -> throw IllegalArgumentException("Unsupported code_challenge_method: $value")
}
