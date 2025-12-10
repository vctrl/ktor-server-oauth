package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.baseUrl
import com.vcontrol.ktor.oauth.model.*
import com.vcontrol.ktor.oauth.oauth
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
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
    val registry = oauth
    // Get config from local auth server
    val localAuthServer = registry.localAuthServer
    val openRegistration = localAuthServer?.openRegistration ?: true

    routing {
        // OAuth Authorization Server Metadata (RFC 8414)
        // Supports both base endpoint and path suffix (e.g., /.well-known/oauth-authorization-server/r/calendar)
        // For path-based issuers, returns endpoints with ?resource= baked in for automatic flow
        get("/.well-known/oauth-authorization-server/{path...}") {
            val baseUrl = call.baseUrl
            val pathSegments = call.parameters.getAll("path") ?: emptyList()

            // Extract resource/provider from path (e.g., "/r/calendar" -> "calendar")
            val providerName = if (pathSegments.size >= 2 && pathSegments[0] == "r") {
                pathSegments.drop(1).joinToString("/")
            } else {
                null
            }

            // Look up per-provider serviceDocumentation
            val serviceDocumentation = providerName?.let { registry.getJwtProviderConfig(it)?.serviceDocumentation }

            // Build endpoint URLs with resource param baked in (empty for default)
            val resourceParam = providerName?.let { "?resource=$it" } ?: ""
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
                serviceDocumentation = serviceDocumentation,
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
 * Used by protected resource metadata endpoint and resource URL resolution.
 *
 * Note: RFC 8707 resource indicators are URLs without HTTP method info, so if only
 * some methods are authenticated on a path (e.g., POST but not GET), this will still
 * return the provider for that path. This is a limitation of the resource indicator spec.
 */
internal fun Application.findAuthProviderForPath(path: String): String? {
    val rootRoute = this.routing {}
    val targetSegments = path.trim('/').split('/').filter { it.isNotEmpty() }

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

    // Find routes whose path segments match or are a prefix of the target
    // Sort by segment count descending to find most specific match first
    for (route in allRoutes.sortedByDescending { it.pathSegments().size }) {
        val routeSegments = route.pathSegments()
        if (routeSegments.isEmpty()) continue

        // Check if route path matches or is a prefix of target path
        val isMatch = routeSegments == targetSegments ||
            (routeSegments.size <= targetSegments.size &&
             targetSegments.subList(0, routeSegments.size) == routeSegments)

        if (isMatch) {
            val provider = route.findAuthProvider()
            if (provider != null) {
                return provider
            }
        }
    }
    return null
}

/**
 * Collect path segments from a route by walking up and checking PathSegmentConstantRouteSelector.value
 */
private fun Route.pathSegments(): List<String> {
    val segments = mutableListOf<String>()
    var current: Route? = this
    while (current != null) {
        val node = current as? RoutingNode
        val selector = node?.selector
        if (selector is PathSegmentConstantRouteSelector) {
            segments.add(0, selector.value)
        }
        current = node?.parent
    }
    return segments
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
