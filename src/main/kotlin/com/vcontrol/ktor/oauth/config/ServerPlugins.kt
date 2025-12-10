package com.vcontrol.ktor.oauth.config

import com.vcontrol.ktor.oauth.*
import com.vcontrol.ktor.oauth.model.AuthorizationRequest
import com.vcontrol.ktor.oauth.session.SessionRecordStorage
import com.vcontrol.ktor.oauth.session.bearerSession
import com.vcontrol.ktor.oauth.session.configureProvisionSession
import com.vcontrol.ktor.oauth.baseUrl
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.forwardedheaders.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.response.*
import io.ktor.server.sessions.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNamingStrategy
import kotlin.reflect.KClass
import kotlin.time.Duration.Companion.minutes

private val logger = KotlinLogging.logger {}

/**
 * Configure server plugins: ContentNegotiation and StatusPages.
 * Called by OAuth plugin during installation.
 */
fun Application.configureServerPlugins() {

    // Install XForwardedHeaders to handle X-Forwarded-* headers from reverse proxies
    // This allows retrieving original client information when behind a proxy
    install(XForwardedHeaders) {
        // Use the first proxy in X-Forwarded-For chain (represents original client)
        // This prevents header spoofing when requests pass through multiple proxies
        useFirstProxy()
    }

    // Enable deferred session loading so transport.receive() is called when sessions.get() is called
    // rather than eagerly at request start. This allows authentication to run first and set the
    // principal/clientId before session resolution attempts to read it.
    System.setProperty("io.ktor.server.sessions.deferred", "true")

    // Install content negotiation for JSON serialization
    install(ContentNegotiation) {
        json(Json {
            prettyPrint = true
            ignoreUnknownKeys = true
            encodeDefaults = true  // Ensure all OAuth metadata fields are included
            explicitNulls = false  // Omit null fields (good practice)
            namingStrategy = JsonNamingStrategy.SnakeCase
        })
    }

    // Install status pages for exception handling
    install(StatusPages) {
        exception<IllegalStateException> { call, cause ->
            // Handle validation failures (missing credentials, revoked clients, etc.)
            // Resolve context lazily from DI
            logger.debug (cause) { "Validation error: ${cause.message}" }
            call.response.header(
                "WWW-Authenticate",
                "Bearer realm=\"${call.baseUrl}\", error=\"invalid_token\", error_description=\"${cause.message}\""
            )
            call.respond(
                HttpStatusCode.Unauthorized,
                mapOf("error" to (cause.message ?: "Unauthorized"))
            )
        }

        exception<IllegalArgumentException> { call, cause ->
            // Handle invalid requests
            logger.debug { "Invalid request: ${cause.message}" }
            call.respond(
                HttpStatusCode.BadRequest,
                mapOf("error" to "invalid_request", "error_description" to (cause.message ?: "Bad Request"))
            )
        }

        exception<Throwable> { call, cause ->
            // Handle unexpected errors
            logger.error(cause) { "Unexpected error: ${cause.message}" }
            cause.printStackTrace()
            call.respond(
                HttpStatusCode.InternalServerError,
                mapOf("error" to "Internal server error", "message" to (cause.message ?: "Unknown error"))
            )
        }
    }
}

/**
 * Configure OAuth sessions.
 * Called by OAuthSessions plugin during installation.
 *
 * Installs Ktor Sessions with:
 * - Internal OAuth cookies (auth_request, provision_session)
 * - ClientId-based session transport for user-defined session types
 */
fun Application.configureOAuthSessions() {
    // Get sessions blocks and build storage instances
    val sessionsBlocks = oauthSessionsBlocks

    // Build storage instance for each block and collect session type mappings
    data class SessionTypeMapping(
        val type: KClass<*>,
        val storage: SessionRecordStorage,
        val ttl: kotlin.time.Duration
    )
    val sessionTypeMappings = mutableListOf<SessionTypeMapping>()

    // Get config from registry for TTL fallback
    val serverConfig = oauth.config.server
    val defaultTtl = serverConfig.tokenExpiration  // Default: session TTL = token expiration

    for (block in sessionsBlocks) {
        @Suppress("UNCHECKED_CAST")
        val storage = (block.builder as SessionStorageBuilder<SessionsConfigBase>).build(
            config = block.config,
            application = this@configureOAuthSessions
        )

        // Map each session type to its storage with resolved TTL
        for ((sessionType, typeConfig) in block.sessionTypes) {
            // TTL resolution order: per-type > storage-level > token expiration
            val resolvedTtl = typeConfig.ttl
                ?: block.storageLevelTtl
                ?: defaultTtl

            sessionTypeMappings.add(SessionTypeMapping(sessionType, storage, resolvedTtl))
        }
    }

    // Get config from registry and application attributes
    val pluginConfig = oauthPluginConfig
    val crypto = this@configureOAuthSessions.crypto

    // Install Sessions for OAuth and setup flow state
    install(Sessions) {
        // 1. Configure OAuth internal cookies

        // auth_request cookie for OAuth flow state
        cookie<AuthorizationRequest>("auth_request") {
            // Apply defaults - path scoped to OAuth routes (or "/" if no routePrefix)
            cookie.path = serverConfig.routePrefix.ifEmpty { "/" }
            cookie.httpOnly = true
            cookie.maxAge = 10.minutes
            cookie.extensions["SameSite"] = "Lax"

            // Apply user overrides if provided
            pluginConfig?.oauthCookieConfig?.invoke(cookie)

            // Always apply encryption (after user config so they can't disable it)
            transform(SessionTransportTransformerEncrypt(crypto.sessionEncryptKey, crypto.sessionSignKey))
        }

        // provision_session cookie - always configure since provisions can be added
        // via oauth { provision { } } after plugin installation
        configureProvisionSession(this@configureOAuthSessions)

        // 2. Register bearer token-bound session types
        for (mapping in sessionTypeMappings) {
            bearerSession(mapping.type, mapping.storage, mapping.ttl)
        }

        // 3. Apply user's Ktor session configs (cookie<T>(), header<T>() from sessions { } block)
        for (block in sessionsBlocks) {
            block.ktorSessionConfigs.forEach { it.invoke(this) }
        }
    }
}
