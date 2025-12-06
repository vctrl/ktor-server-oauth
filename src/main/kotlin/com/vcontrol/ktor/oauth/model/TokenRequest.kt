package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable

/**
 * OAuth 2.0 Token Request
 * Supports client_credentials and authorization_code grant types
 * RFC 6749: https://datatracker.ietf.org/doc/html/rfc6749
 */
@Serializable
data class TokenRequest(
    // OAuth 2.0 standard fields
    val grantType: GrantType,
    val clientId: String? = null,
    val clientSecret: String? = null,
    val scope: String? = null,

    // Extension: Display name embedded in JWT claims (see JwtTokenIssuer)
    val clientName: String? = null,

    // Authorization code grant fields
    val code: String? = null,
    val redirectUri: String? = null,
    val codeVerifier: String? = null
)
