package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OAuth 2.0 Response Types (RFC 6749)
 */
@Serializable
enum class ResponseType {
    @SerialName("code") Code,
    @SerialName("token") Token
}

/**
 * OAuth 2.0 Grant Types (RFC 6749)
 */
@Serializable
enum class GrantType {
    @SerialName("authorization_code") AuthorizationCode,
    @SerialName("client_credentials") ClientCredentials,
    @SerialName("refresh_token") RefreshToken
}

/**
 * OAuth 2.0 Token Endpoint Authentication Methods (RFC 7591)
 */
@Serializable
enum class TokenEndpointAuthMethod {
    @SerialName("client_secret_post") ClientSecretPost,
    @SerialName("client_secret_basic") ClientSecretBasic,
    @SerialName("none") None
}

/**
 * PKCE Code Challenge Methods (RFC 7636)
 */
@Serializable
enum class CodeChallengeMethod {
    @SerialName("S256") S256,
    @SerialName("plain") Plain
}

/**
 * OAuth 2.0 Protected Resource Metadata
 * RFC 9728: https://datatracker.ietf.org/doc/html/rfc9728
 *
 * The authorizationServers field contains issuer identifiers. For resource-specific
 * providers, the issuer includes a path component (e.g., "https://auth.example/r/calendar").
 * Clients fetch metadata from /.well-known/oauth-authorization-server/{path} per RFC 8414.
 */
@Serializable
data class ProtectedResourceMetadata(
    val resource: String,
    val authorizationServers: List<String>
)

/**
 * OAuth 2.0 Authorization Server Metadata
 * RFC 8414: https://datatracker.ietf.org/doc/html/rfc8414
 */
@Serializable
data class AuthorizationServerMetadata(
    val issuer: String,
    val authorizationEndpoint: String? = null,
    val tokenEndpoint: String,
    val registrationEndpoint: String? = null,
    val jwksUri: String? = null,
    val responseTypesSupported: List<ResponseType> = listOf(ResponseType.Token),
    val grantTypesSupported: List<GrantType> = listOf(GrantType.ClientCredentials),
    val tokenEndpointAuthMethodsSupported: List<TokenEndpointAuthMethod> = listOf(
        TokenEndpointAuthMethod.ClientSecretPost,
        TokenEndpointAuthMethod.ClientSecretBasic
    ),
    val serviceDocumentation: String? = null,
    val codeChallengeMethodsSupported: List<CodeChallengeMethod>? = listOf(CodeChallengeMethod.S256)
)
