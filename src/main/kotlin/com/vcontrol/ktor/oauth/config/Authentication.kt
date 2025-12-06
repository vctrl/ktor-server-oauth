package com.vcontrol.ktor.oauth.config

import com.vcontrol.ktor.oauth.crypto
import com.vcontrol.ktor.oauth.oauth
import com.vcontrol.ktor.oauth.oauthPluginConfig
import com.vcontrol.ktor.oauth.token.JwtTokenIssuer
import com.vcontrol.ktor.oauth.token.SessionKeyClaimsProvider
import io.ktor.server.application.*
import io.ktor.server.auth.jwt.JWTPrincipal

/**
 * Configure the JWT token issuer for the OAuth authorization server.
 *
 * This creates the token issuer used by the token endpoint to issue JWTs.
 * Authentication providers are created separately via `install(Authentication) { oauth() }`.
 *
 * Called automatically during OAuth plugin installation.
 */
fun Application.configureAuthentication() {
    val config = oauthPluginConfig ?: return
    val localAuthServer = config.localAuthServer ?: return

    val registry = oauth
    val jwtConfig = registry.config.server.jwt

    // Create token issuer for token creation (used by TokenRoute)
    val tokenIssuer = JwtTokenIssuer(
        jwtIssuer = jwtConfig.issuer,
        crypto = crypto,
        claimsProviders = localAuthServer.claimsProviders.toList()
    )
    registry.registerTokenIssuer(tokenIssuer)

    // Authentication providers are created via install(Authentication) { oauth() }
}

// ============================================================================
// JWTPrincipal Extensions
// ============================================================================

/**
 * The client_id claim from the JWT token.
 */
val JWTPrincipal.clientId: String?
    get() = payload.getClaim("client_id").asString()

/**
 * The client_name claim from the JWT token (optional).
 */
val JWTPrincipal.clientName: String?
    get() = payload.getClaim("client_name").asString()

/**
 * The session encryption key from the JWT token (internal use).
 */
internal val JWTPrincipal.sessionKey: String?
    get() = payload.getClaim(SessionKeyClaimsProvider.SESSION_KEY_CLAIM).asString()
