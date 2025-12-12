package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.Serializable

/**
 * Dynamic Client Registration Request
 * RFC 7591: https://datatracker.ietf.org/doc/html/rfc7591
 *
 * Note: This server operates in stateless mode - dynamic registration always
 * produces public clients (tokenEndpointAuthMethod = None, no client_secret).
 * The tokenEndpointAuthMethod field is accepted but ignored.
 *
 * For confidential clients, use pre-configured credentials via the
 * `credentials { }` DSL instead of dynamic registration.
 */
@Serializable
data class ClientRegistrationRequest(
    val clientName: String? = null,
    val clientUri: String? = null,
    val redirectUris: List<String>? = null,
    val grantTypes: List<GrantType>? = listOf(GrantType.AuthorizationCode),
    val responseTypes: List<ResponseType>? = listOf(ResponseType.Code),
    val tokenEndpointAuthMethod: TokenEndpointAuthMethod? = null  // Ignored in stateless mode
)
