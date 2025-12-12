package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.oauth
import com.vcontrol.ktor.oauth.RequestContext
import com.vcontrol.ktor.oauth.model.*
import com.vcontrol.ktor.oauth.token.TokenUtils
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

private val logger = KotlinLogging.logger {}

/**
 * Configure OAuth Dynamic Client Registration endpoint
 * RFC 7591: https://datatracker.ietf.org/doc/html/rfc7591
 *
 * Controlled by server { clients { registration = true } } in OAuth DSL.
 * Default: No configuration = reject all registrations (secure by default).
 *
 * Returns clientId only (public client) unless token_endpoint_auth_method
 * requests a secret (confidential client).
 */
fun Routing.configureClientRegistrationRoutes() {
    val serverConfig = application.oauth.config.server
    val localAuthServer = application.oauth.localAuthServer
    val clientsConfig = localAuthServer?.clientsConfig
    val registrationValidator = clientsConfig?.registrationValidator

    // No registration configured = registration not enabled (secure by default)
    if (registrationValidator == null) {
        logger.info { "Dynamic OAuth registration disabled (no clients { registration = true } configured)" }
        return
    }

    // Dynamic Client Registration
    post(serverConfig.endpoint(serverConfig.endpoints.register)) {
        try {
            val request = call.receive<ClientRegistrationRequest>()

            // Generate client ID
            val clientId = TokenUtils.generateClientId()

            // Get resource from query param (RFC 8707)
            val resource = call.request.queryParameters["resource"]

            // Validate registration using the configured validator with request context
            val context = RequestContext(call.request, resource)
            if (!context.registrationValidator(request.clientName)) {
                val error = OAuthError(
                    error = OAuthError.UNAUTHORIZED_CLIENT,
                    errorDescription = "Registration not allowed"
                )
                call.respond(HttpStatusCode.Forbidden, error)
                return@post
            }

            val issuedAt = System.currentTimeMillis() / 1000

            // Stateless mode: dynamic registration always produces public clients
            // Confidential clients must use pre-configured credentials via credentials { }
            val authMethod = TokenEndpointAuthMethod.None
            val clientSecret: String? = null

            val response = ClientRegistrationResponse(
                clientId = clientId,
                clientSecret = clientSecret,
                clientIdIssuedAt = issuedAt,
                clientSecretExpiresAt = if (clientSecret != null) 0 else null,
                clientName = request.clientName,
                clientUri = request.clientUri,
                redirectUris = request.redirectUris,
                grantTypes = request.grantTypes ?: listOf(GrantType.AuthorizationCode),
                responseTypes = request.responseTypes ?: listOf(ResponseType.Code),
                tokenEndpointAuthMethod = authMethod
            )

            logger.trace { "Generated OAuth client: ${clientId.take(8)}... (public=${clientSecret == null})" }

            call.respond(HttpStatusCode.Created, response)

        } catch (e: Exception) {
            logger.error(e) { "Client registration failed: ${e.message}" }
            val error = OAuthError(
                error = OAuthError.INVALID_REQUEST,
                errorDescription = "Invalid registration request: ${e.message}"
            )
            call.respond(HttpStatusCode.BadRequest, error)
        }
    }
}
