package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable

/**
 * Dynamic Client Registration Response
 * RFC 7591: https://datatracker.ietf.org/doc/html/rfc7591
 */
@Serializable
data class ClientRegistrationResponse(
    val clientId: String,
    val clientSecret: String,
    val clientIdIssuedAt: Long,
    val clientSecretExpiresAt: Long = 0, // 0 means no expiration
    val clientName: String? = null,
    val clientUri: String? = null,
    val redirectUris: List<String>? = null,
    val grantTypes: List<GrantType> = listOf(GrantType.ClientCredentials),
    val responseTypes: List<ResponseType> = listOf(ResponseType.Token),
    val tokenEndpointAuthMethod: TokenEndpointAuthMethod = TokenEndpointAuthMethod.ClientSecretPost
)
