package com.vcontrol.ktor.oauth

import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.util.AttributeKey

// ============================================================================
// Attribute Keys
// ============================================================================

internal val ProvisionConfigsKey = AttributeKey<Map<String?, ProvisionConfig>>("OAuthProvisionConfigs")
internal val OAuthPluginConfigKey = AttributeKey<OAuthPluginConfig>("OAuthPluginConfig")
internal val OAuthKey = AttributeKey<OAuthRegistry>("OAuth")
internal val SessionsBlocksKey = AttributeKey<List<SessionsBlockConfig>>("OAuthSessionsBlocks")

// ============================================================================
// Application Extension Properties
// ============================================================================

/**
 * Get all provision configs from all providers.
 * Key is provider name (null for default provider).
 */
internal val Application.oauthProvisionConfigs: Map<String?, ProvisionConfig>
    get() = attributes.getOrNull(ProvisionConfigsKey) ?: emptyMap()

/**
 * Get the OAuth plugin configuration.
 * Returns null if OAuth plugin is not installed.
 */
internal val Application.oauthPluginConfig: OAuthPluginConfig?
    get() = attributes.getOrNull(OAuthPluginConfigKey)

/**
 * Access the OAuth registry. Requires OAuth plugin to be installed.
 */
val Application.oauth: OAuthRegistry
    get() = attributes.getOrNull(OAuthKey)
        ?: error("OAuth plugin not installed - call install(OAuth) { } first")

/**
 * Access the OAuth registry, or null if not installed.
 * Use this in extension functions that need to check if OAuth is available.
 */
val Application.oauthOrNull: OAuthRegistry?
    get() = attributes.getOrNull(OAuthKey)

/**
 * Get the sessions blocks configured with the OAuthSessions plugin.
 * Each block has its own builder, config, and session types.
 */
internal val Application.oauthSessionsBlocks: List<SessionsBlockConfig>
    get() = attributes.getOrNull(SessionsBlocksKey) ?: emptyList()

/**
 * Get the base URL from the request, using X-Forwarded-* headers if present.
 * Requires XForwardedHeaders plugin to be installed.
 *
 * Example: "https://oauth.example.com" or "http://localhost:8080"
 */
val ApplicationCall.baseUrl: String
    get() = "${request.origin.scheme}://${request.origin.serverHost}"
