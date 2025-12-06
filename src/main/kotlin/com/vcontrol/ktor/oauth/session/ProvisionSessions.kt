package com.vcontrol.ktor.oauth.session

import com.vcontrol.ktor.oauth.crypto
import com.vcontrol.ktor.oauth.oauth
import com.vcontrol.ktor.oauth.model.ProvisionSession
import io.ktor.server.application.*
import io.ktor.server.sessions.*
import kotlin.time.Duration.Companion.minutes

/**
 * Configure the provision session cookie.
 * Called from ServerPlugins during OAuth plugin installation.
 *
 * Always configured regardless of whether provisions are defined upfront,
 * since provisions can be added later via oauth { provision { } }.
 */
fun SessionsConfig.configureProvisionSession(application: Application) {
    val crypto = application.crypto
    val serverConfig = application.oauth.config.server

    cookie<ProvisionSession>("provision_session") {
        // Apply defaults - path must be broad enough for both /provision/* and /authorize
        cookie.path = serverConfig.routePrefix.ifEmpty { "/" }
        cookie.httpOnly = true
        cookie.maxAge = 10.minutes
        cookie.extensions["SameSite"] = "Lax"

        // Always apply encryption
        transform(SessionTransportTransformerEncrypt(crypto.sessionEncryptKey, crypto.sessionSignKey))
    }
}
