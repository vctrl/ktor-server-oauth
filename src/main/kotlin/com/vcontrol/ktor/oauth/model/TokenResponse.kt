package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable

/**
 * OAuth 2.0 Token Response
 * RFC 6749: https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 */
@Serializable
data class TokenResponse(
    val accessToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long? = null,  // null = never expires (omitted from JSON)
    val scope: String? = null,
    val refreshToken: String? = null
)
