package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.baseUrl
import com.vcontrol.ktor.oauth.oauth
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
 * RFC 8707: https://datatracker.ietf.org/doc/html/rfc8707 (Resource Indicators)
 *
 * Controlled by authorizationServer { openRegistration = false } in OAuth DSL (default: true)
 *
 * Accepts optional ?resource= query parameter to specify which resource
 * to use for this client.
 *
 * Note: Credentials are ephemeral - returned to client but not persisted.
 * Security is ensured by PKCE during the authorization flow.
 */
fun Routing.configureClientRegistrationRoutes() {
    val serverConfig = application.oauth.config.server
    // Get openRegistration from local auth server config
    val localAuthServer = application.oauth.localAuthServer
    val openRegistration = localAuthServer?.openRegistration ?: true

    if (!openRegistration) {
        logger.info { "Dynamic OAuth registration disabled (openRegistration=false)" }
        return
    }

    // Dynamic Client Registration
    post(serverConfig.endpoint(serverConfig.endpoints.register)) {
        try {
            val request = call.receive<ClientRegistrationRequest>()

            // Get provider from ?resource= query param (RFC 8707)
            val resourceParam = call.request.queryParameters["resource"]

            // Resolve provider: if resource is a URL, strip base URL to get path
            val providerName = when {
                resourceParam == null -> null
                resourceParam.contains("://") -> {
                    val path = resourceParam.removePrefix(call.baseUrl)
                    application.findAuthProviderForPath(path)
                }
                application.oauth.authProviders.containsKey(resourceParam) -> resourceParam
                else -> null  // Unknown resource name, fall back to default
            }

            // Generate client credentials (ephemeral - not persisted)
            val clientId = TokenUtils.generateClientId()
            val clientSecret = TokenUtils.generateClientSecret()
            val issuedAt = System.currentTimeMillis() / 1000

            // Return registration response
            // Note: Client credentials are ephemeral. The client uses these for
            // the OAuth authorization flow, but PKCE ensures security.
            val response = ClientRegistrationResponse(
                clientId = clientId,
                clientSecret = clientSecret,
                clientIdIssuedAt = issuedAt,
                clientSecretExpiresAt = 0, // No expiration
                clientName = request.clientName,
                clientUri = request.clientUri,
                redirectUris = request.redirectUris,
                grantTypes = request.grantTypes ?: listOf(GrantType.AuthorizationCode),
                responseTypes = request.responseTypes ?: listOf(ResponseType.Code),
                tokenEndpointAuthMethod = request.tokenEndpointAuthMethod ?: TokenEndpointAuthMethod.None
            )

            logger.trace { "Generated ephemeral OAuth client: ${clientId.take(8)}... (provider: ${providerName ?: "default"})" }

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
