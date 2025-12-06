package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * Session state for the OAuth provision flow.
 *
 * Created by /authorize when provision is required, stores nextUrl
 * to redirect back after provision completes.
 *
 * clientId is set upfront for session binding during provision.
 * providerName tracks which OAuth provider's handlers to use.
 *
 * Provision is where the resource server collects credentials, API keys, and
 * other configuration needed to serve the client. This is distinct from
 * RFC authorization consent - provision is resource-specific setup.
 */
@Serializable
data class ProvisionSession(
    val clientId: String,
    val nextUrl: String,
    /**
     * OAuth provider name for this provision flow.
     * Used to look up the correct provision handler.
     */
    val providerName: String? = null,
    /**
     * Custom claims to embed in the JWT token.
     * Set during provision via `call.tokenClaims["key"] = value`.
     * Stored as JsonElement for serialization; use TokenClaimsMap wrapper for type-safe access.
     */
    val claims: MutableMap<String, JsonElement> = mutableMapOf(),
    /**
     * Encrypted claims to embed in the JWT token.
     * Set during provision via `call.tokenClaims.encrypted["key"] = value`.
     * Values are encrypted with the server key before being added to the JWT.
     */
    val encryptedClaims: MutableMap<String, String> = mutableMapOf()
)
