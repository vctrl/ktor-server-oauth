package com.vcontrol.ktor.oauth.model

import com.vcontrol.ktor.oauth.token.ProvisionClaims
import kotlinx.serialization.Serializable

/**
 * Session state for the OAuth provision flow.
 *
 * Created by /authorize when provision is required, stores nextUrl
 * to redirect back after provision completes.
 *
 * Contains [identity] which holds the immutable authorization context
 * (jti, providerName, client) that flows through to the final JWT.
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
     * Claims to embed in the JWT token.
     * Set during provision via complete { withClaim(...); withEncryptedClaim(...) }
     * Encrypted claims are marked and encrypted at token creation time.
     */
    val claims: ProvisionClaims = ProvisionClaims()
) {
    /** JWT ID - delegated from identity */
    val jti: String get() = identity.jti
}
