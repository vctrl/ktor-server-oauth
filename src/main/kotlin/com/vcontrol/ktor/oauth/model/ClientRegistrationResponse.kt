package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable

/**
 * Dynamic Client Registration Response
 * RFC 7591: https://datatracker.ietf.org/doc/html/rfc7591
 *
 * For public clients (open registration), clientSecret is null and
 * tokenEndpointAuthMethod is None.
 */
@Serializable
data class ClientRegistrationResponse(
    val clientId: String,
    val clientSecret: String? = null,
    val clientIdIssuedAt: Long,
    val clientSecretExpiresAt: Long? = null, // Only present if clientSecret is set
    val clientName: String? = null,
    val clientUri: String? = null,
    val redirectUris: List<String>? = null,
    val grantTypes: List<GrantType> = listOf(GrantType.AuthorizationCode),
    val responseTypes: List<ResponseType> = listOf(ResponseType.Code),
    val tokenEndpointAuthMethod: TokenEndpointAuthMethod = TokenEndpointAuthMethod.None
)
