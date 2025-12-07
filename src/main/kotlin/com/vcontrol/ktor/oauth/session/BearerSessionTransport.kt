package com.vcontrol.ktor.oauth.session

import com.vcontrol.ktor.oauth.SessionKeyResolverKey
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.application.ApplicationCall
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.principal
import io.ktor.server.sessions.SessionTransport
import io.ktor.util.AttributeKey

private val logger = KotlinLogging.logger {}

/**
 * Attribute key for passing session key through call attributes.
 * Used during provision flow where the session key is known but JWT is not yet issued.
 */
internal val BearerSessionKeyAttributeKey = AttributeKey<String>("BearerSessionKey")

/**
 * Session transport that derives session keys from bearer token claims.
 *
 * By default uses "jti" (JWT ID), but can be configured via [OAuthSessionsPluginConfig.sessionKeyClaim]
 * or [OAuthSessionsPluginConfig.sessionKeyResolver].
 *
 * Resolves session key from multiple sources (in priority order):
 * 1. JWT principal (JWTPrincipal) - for authenticated routes
 * 2. Call attribute (BearerSessionKeyAttributeKey) - for provision flow
 *
 * This transport doesn't actually send/receive data to/from the client -
 * instead it provides the session key as the "transport string" which the
 * [BearerSessionTracker] uses to key session storage.
 */
class BearerSessionTransport : SessionTransport {

    /**
     * Receive the session key from available context.
     *
     * Priority:
     * 1. JWT principal (authenticated routes) - uses configured claim/resolver
     * 2. Call attribute (set during provision flow)
     *
     * Note: We cannot access other session types here (like ProvisionSession)
     * because this method is called DURING session resolution, which would
     * cause a recursive call and "Sessions are not yet ready" error.
     */
    override fun receive(call: ApplicationCall): String? {
        // First try JWT principal (available in authenticated routes)
        val principal = call.principal<JWTPrincipal>()
        if (principal != null) {
            // Use configured resolver if available, otherwise default to jti
            val resolver = call.application.attributes.getOrNull(SessionKeyResolverKey)
            return if (resolver != null) {
                resolver(principal.payload)
            } else {
                // Default fallback to jti (JWT ID)
                principal.payload.getClaim("jti").asString()
            }
        }

        // Fall back to attribute (set during provision flow)
        return call.attributes.getOrNull(BearerSessionKeyAttributeKey)
    }

    /**
     * No-op for bearer session transport - we don't send anything to the client.
     * The session key is derived from auth context, not stored in response.
     */
    override fun send(call: ApplicationCall, value: String) {
        // No-op: session key comes from auth context, not sent to client
    }

    /**
     * No-op for bearer session transport - clearing is handled at storage level.
     */
    override fun clear(call: ApplicationCall) {
        // No-op: session clearing is handled by the tracker
    }
}
