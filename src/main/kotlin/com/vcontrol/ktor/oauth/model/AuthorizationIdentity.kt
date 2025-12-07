package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable

/**
 * Immutable identity context for an OAuth authorization flow.
 *
 * Created at the start of /authorize and passed through the entire flow:
 * - Stored in ProvisionSession during provision
 * - Passed to AuthorizationCode for token exchange
 * - jti ends up in the final JWT
 *
 * The jti is generated upfront (via configured provider or UUID default)
 * so sessions created during provision use the same key that will be
 * in the token - safer than client_id which can be manipulated.
 */
@Serializable
data class AuthorizationIdentity(
    /** Client identifier from the authorization request */
    val clientId: String,
    /** JWT ID - generated at flow start, used for session keying and token */
    val jti: String,
    /** OAuth provider name (null for default provider) */
    val providerName: String? = null
)
