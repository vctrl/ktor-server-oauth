package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable

/**
 * Dynamic Client Registration Request
 * RFC 7591: https://datatracker.ietf.org/doc/html/rfc7591
 */
@Serializable
data class ClientRegistrationRequest(
    val clientName: String? = null,
    val clientUri: String? = null,
    val redirectUris: List<String>? = null,
    val grantTypes: List<GrantType>? = listOf(GrantType.ClientCredentials),
    val responseTypes: List<ResponseType>? = listOf(ResponseType.Token),
    val tokenEndpointAuthMethod: TokenEndpointAuthMethod? = TokenEndpointAuthMethod.ClientSecretPost
)
