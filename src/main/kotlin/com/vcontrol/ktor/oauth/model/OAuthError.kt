package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable

/**
 * OAuth 2.0 Error Response
 * RFC 6749: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
@Serializable
data class OAuthError(
    val error: String,
    val errorDescription: String? = null,
    val errorUri: String? = null
) {
    companion object {
        const val INVALID_REQUEST = "invalid_request"
        const val INVALID_CLIENT = "invalid_client"
        const val INVALID_GRANT = "invalid_grant"
        const val UNAUTHORIZED_CLIENT = "unauthorized_client"
        const val UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
        const val INVALID_SCOPE = "invalid_scope"
    }
}
