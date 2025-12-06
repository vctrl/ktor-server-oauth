package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.oauth
import com.vcontrol.ktor.oauth.model.*
import com.vcontrol.ktor.oauth.baseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.*
import io.ktor.server.auth.AuthenticationRouteSelector
import io.ktor.server.response.respond
import io.ktor.server.routing.*

/**
 * Configure all OAuth 2.0 endpoints
 * Implements RFC 8414, RFC 7591, RFC 6749, and RFC 7636
 *
 * Delegates to specialized route files:
 * - OAuthMetadataRoutes.kt: Authorization server metadata
 * - OAuthAuthorizationRoutes.kt: Authorization code flow
 * - OAuthRegistrationRoutes.kt: Dynamic client registration
 * - OAuthTokenRoutes.kt: Token issuance
 */
fun Application.configureOAuthRoutes() {
    val serverConfig = oauth.config.server
    // Get openRegistration from local auth server config
    val localAuthServer = oauth.localAuthServer
    val openRegistration = localAuthServer?.openRegistration ?: true

    routing {
        // OAuth Authorization Server Metadata (RFC 8414)
        // Supports both base endpoint and path suffix (e.g., /.well-known/oauth-authorization-server/r/calendar)
        // For path-based issuers, returns endpoints with ?resource= baked in for automatic flow
        get("/.well-known/oauth-authorization-server/{path...}") {
            val baseUrl = call.baseUrl
            val pathSegments = call.parameters.getAll("path") ?: emptyList()

            // Extract resource from path (e.g., "/r/calendar" -> "calendar")
            val resource = if (pathSegments.size >= 2 && pathSegments[0] == "r") {
                pathSegments.drop(1).joinToString("/")
            } else {
                null
            }

            // Build endpoint URLs with resource param baked in (empty for default)
            val resourceParam = resource?.let { "?resource=$it" } ?: ""
            val issuerPath = if (pathSegments.isEmpty()) "" else "/" + pathSegments.joinToString("/")

            val metadata = AuthorizationServerMetadata(
                issuer = "$baseUrl$issuerPath",
                authorizationEndpoint = "$baseUrl${serverConfig.endpoint(serverConfig.endpoints.authorize)}$resourceParam",
                tokenEndpoint = "$baseUrl${serverConfig.endpoint(serverConfig.endpoints.token)}$resourceParam",
                registrationEndpoint = if (openRegistration) "$baseUrl${serverConfig.endpoint(serverConfig.endpoints.register)}$resourceParam" else null,
                grantTypesSupported = listOf(GrantType.AuthorizationCode, GrantType.ClientCredentials),
                responseTypesSupported = listOf(ResponseType.Code, ResponseType.Token),
                tokenEndpointAuthMethodsSupported = listOf(
                    TokenEndpointAuthMethod.ClientSecretPost,
                    TokenEndpointAuthMethod.ClientSecretBasic
                ),
                codeChallengeMethodsSupported = listOf(CodeChallengeMethod.S256)
            )
            call.respond(HttpStatusCode.OK, metadata)
        }

        // OAuth Protected Resource Metadata (RFC 9728)
        // Dynamically discovers which routes are protected by which auth provider
        // by introspecting Ktor's route tree for AuthenticationRouteSelector
        get("/.well-known/oauth-protected-resource/{path...}") {
            val baseUrl = call.baseUrl
            val pathSegments = call.parameters.getAll("path") ?: emptyList()
            val resourcePath = if (pathSegments.isEmpty()) "" else "/" + pathSegments.joinToString("/")

            // Dynamically find the auth provider for this path by introspecting routes
            val providerName = if (resourcePath.isNotEmpty()) {
                application.findAuthProviderForPath(resourcePath)
            } else {
                null
            }

            // Return issuer with path for specific providers, base URL for default
            val authServer = if (providerName != null) "$baseUrl/r/$providerName" else baseUrl
            call.respond(HttpStatusCode.OK, ProtectedResourceMetadata(
                resource = "$baseUrl$resourcePath",
                authorizationServers = listOf(authServer)
            ))
        }

        configureAuthorizationRoutes()
        configureClientRegistrationRoutes()
        configureTokenRoutes()
    }
}

/**
 * Find the auth provider name for a given path by introspecting the route tree.
 * Traverses all routes and looks for AuthenticationRouteSelector in the parent chain.
 */
private fun Application.findAuthProviderForPath(path: String): String? {
    // Get the root routing node
    val rootRoute = this.routing {}

    // Collect all routes recursively
    fun collectRoutes(route: Route): List<Route> {
        val routes = mutableListOf(route)
        val node = route as? RoutingNode
        node?.children?.forEach { child ->
            routes.addAll(collectRoutes(child))
        }
        return routes
    }

    val allRoutes = collectRoutes(rootRoute)

    // Find routes that match this path
    for (route in allRoutes) {
        val routePath = route.toString()
        if (routePath == path || path.startsWith("$routePath/") || routePath.startsWith("$path/")) {
            // Traverse up looking for AuthenticationRouteSelector
            val provider = route.findAuthProvider()
            if (provider != null) {
                return provider
            }
        }
    }
    return null
}

/**
 * Find the auth provider name by traversing up the route hierarchy
 * looking for AuthenticationRouteSelector.
 */
private fun Route.findAuthProvider(): String? {
    var current: Route? = this
    while (current != null) {
        val node = current as? RoutingNode
        val selector = node?.selector
        if (selector is AuthenticationRouteSelector) {
            // Return the first provider name (null for default)
            return selector.names.firstOrNull()
        }
        current = node?.parent
    }
    return null
}
