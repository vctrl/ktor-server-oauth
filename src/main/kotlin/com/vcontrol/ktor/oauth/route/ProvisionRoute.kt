package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.*
import com.vcontrol.ktor.oauth.model.ProvisionSession
import com.vcontrol.ktor.oauth.session.BearerSessionKeyAttributeKey
import com.vcontrol.ktor.oauth.token.HmacToken
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*

private val logger = KotlinLogging.logger {}

/** Marker nextUrl for standalone provision (not from OAuth flow) */
private const val STANDALONE_MARKER = "standalone://complete"

/**
 * Define provision routes for an OAuth provider.
 *
 * Use inside `routing { }` to configure the provision endpoint where clients
 * provide credentials, API keys, or other configuration during the OAuth flow.
 *
 * Handlers receive [ProvisionRoutingContext] which provides:
 * - [ProvisionRoutingContext.call] - The application call
 * - [ProvisionRoutingContext.clientId] - The client ID for this session
 * - [ProvisionRoutingContext.sessions] - Session accessor for get/set
 * - [ProvisionRoutingContext.complete] - Complete provision with claims
 *
 * Example:
 * ```kotlin
 * routing {
 *     provision {
 *         get { call.respondText(formHtml, ContentType.Text.Html) }
 *         post {
 *             sessions.set(MySession(apiKey = params["api_key"]))
 *             complete(claims = mapOf("username" to params["username"]))
 *         }
 *     }
 *
 *     provision("calendar") {
 *         handle { complete(claims = mapOf("scope" to "calendar")) }
 *     }
 *
 *     authenticate {
 *         get("/api/data") { ... }
 *     }
 * }
 * ```
 *
 * @param providerName The OAuth provider name (null for default provider)
 * @param block Route builder for defining GET/POST/handle handlers
 */
fun Route.provision(providerName: String? = null, block: ProvisionRouteBuilder.() -> Unit) {
    val app = application
    val registry = app.oauthOrNull
        ?: error("OAuth plugin must be installed before configuring provision routes")

    // Determine the provision endpoint path
    val oauthConfig = registry.config
    val provisionEndpoint = oauthConfig.server.endpoint(oauthConfig.server.endpoints.provision)
    val path = when (providerName) {
        null -> provisionEndpoint
        else -> "$provisionEndpoint/$providerName"
    }

    // Register provision config in registry
    val routeSetup: ProvisionRouteSetup = block
    val newProvisionConfig = ProvisionConfig(routeSetup = routeSetup)

    val existingProvider = registry.getProvider(providerName)
    val newProvider = ProviderConfig(providerName).apply {
        if (existingProvider != null) {
            realm = existingProvider.realm
            authorizationServer = existingProvider.authorizationServer
            validateFn = existingProvider.validateFn
        }
        provisionConfig = newProvisionConfig
    }

    // Register the provider
    if (providerName == null) {
        registry.setDefaultProvider(newProvider)
    } else if (existingProvider == null) {
        registry.registerProvider(providerName, newProvider)
    }

    // Store provision config for session cookie configuration
    val existingConfigs = app.attributes.getOrNull(ProvisionConfigsKey)?.toMutableMap() ?: mutableMapOf()
    existingConfigs[providerName] = newProvisionConfig
    app.attributes.put(ProvisionConfigsKey, existingConfigs)

    // Create the provision route
    val cryptoCtx = app.crypto

    route(path) {
        // Install intercept to validate session before user handlers run
        install(createRouteScopedPlugin("ProvisionSessionPlugin") {
            onCall { call ->
                try {
                    val params = call.request.queryParameters
                    var session = call.sessions.get<ProvisionSession>()

                    // Check for standalone auth token (from CLI tools)
                    val clientIdParam = params["client_id"]
                    val authToken = params["auth_token"]

                    if (session == null && clientIdParam != null && authToken != null) {
                        // Validate HMAC token
                        val validatedClientId = HmacToken.validate(authToken, cryptoCtx.jwtSecret)
                        if (validatedClientId == null || validatedClientId != clientIdParam) {
                            call.respond(HttpStatusCode.Unauthorized, mapOf(
                                "error" to "invalid_token",
                                "error_description" to "Invalid or expired provision token."
                            ))
                            return@onCall
                        }

                        // Create standalone session
                        session = ProvisionSession(
                            clientId = clientIdParam,
                            nextUrl = STANDALONE_MARKER
                        )
                        call.sessions.set(session)
                        logger.info { "Created standalone provision session for client: ${clientIdParam.take(8)}..." }
                    }

                    // No session = invalid access
                    if (session == null) {
                        call.respond(HttpStatusCode.BadRequest, mapOf(
                            "error" to "invalid_request",
                            "error_description" to "Provision requires an active authorization session or valid provision token."
                        ))
                        return@onCall
                    }

                    // Store session in attributes for handlers to access
                    call.attributes.put(ProvisionSessionKey, session)

                    // Set session key attribute so bearer sessions can resolve it during provision
                    call.attributes.put(BearerSessionKeyAttributeKey, session.clientId)

                } catch (e: Exception) {
                    logger.error(e) { "Provision error" }
                    call.respond(HttpStatusCode.InternalServerError, mapOf(
                        "error" to "server_error",
                        "error_description" to "Internal server error: ${e.message}"
                    ))
                }
            }
        })

        // Apply user's route setup using ProvisionRouteBuilder
        val builder = ProvisionRouteBuilder(this)
        block(builder)
    }
}

/**
 * Define provision routes for the default OAuth provider.
 *
 * Shorthand for `provision(null) { ... }`.
 *
 * @see provision
 */
fun Route.provision(block: ProvisionRouteBuilder.() -> Unit) = provision(null, block)
