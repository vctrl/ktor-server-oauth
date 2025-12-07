package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * Session state for the OAuth provision flow.
 *
 * Created by /authorize when provision is required, stores nextUrl
 * to redirect back after provision completes.
 *
 * Contains [identity] which holds the immutable authorization context
 * (clientId, jti, providerName) that flows through to the final JWT.
 *
 * Provision is where the resource server collects credentials, API keys, and
 * other configuration needed to serve the client. This is distinct from
 * RFC authorization consent - provision is resource-specific setup.
 */
@Serializable
data class ProvisionSession(
    /** Immutable identity context for this authorization flow */
    val identity: AuthorizationIdentity,
    /** URL to redirect back to after provision completes */
    val nextUrl: String,
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
) {
    /** Client identifier - delegated from identity */
    val clientId: String get() = identity.clientId
    /** JWT ID - delegated from identity */
    val jti: String get() = identity.jti
    /** Provider name - delegated from identity */
    val providerName: String? get() = identity.providerName
}
