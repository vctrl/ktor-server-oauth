package com.vcontrol.ktor.oauth.cli

import com.vcontrol.ktor.oauth.CryptoContext
import com.vcontrol.ktor.oauth.token.JwtTokenIssuer
import com.vcontrol.ktor.oauth.token.HmacToken
import com.vcontrol.ktor.oauth.token.TokenUtils
import com.typesafe.config.ConfigFactory
import io.ktor.server.config.*
import java.util.UUID
import kotlin.time.Duration

/**
 * CLI tool for generating bearer tokens for clients that don't support OAuth
 * (e.g., LM Studio which only accepts a static bearer token).
 *
 * Outputs:
 * - Bearer token for API authentication
 * - Provision URL to complete setup (set session data)
 *
 * Usage:
 *   ./gradlew :server:generateToken --args="[options]"
 *
 * Options:
 *   --name <name>         Client name to embed in token (default: "cli-client")
 *   --expiration <dur>    ISO 8601 duration for token (default: PT0S = never expires)
 *   --base-url <url>      Server base URL (default: from config or http://localhost:8080)
 *   --help, -h            Show help
 */
fun main(args: Array<String>) {
    // Load from application.conf
    val appConfig = HoconApplicationConfig(ConfigFactory.load())

    val secretFile = appConfig.property("oauth.server.jwt.secretFile").getString()
    val routePrefix = appConfig.propertyOrNull("oauth.server.routePrefix")?.getString() ?: ""
    val defaultPort = appConfig.propertyOrNull("ktor.deployment.port")?.getString() ?: "8080"
    val defaultHost = appConfig.propertyOrNull("ktor.deployment.host")?.getString() ?: "localhost"
    val provisionEndpoint = routePrefix + (appConfig.propertyOrNull("oauth.server.endpoints.provision")?.getString() ?: "/provision")

    var clientName = "cli-client"
    var clientId: String? = null
    var expiration = Duration.ZERO
    // 0.0.0.0 means "all interfaces" - use localhost for URLs
    val displayHost = if (defaultHost == "0.0.0.0") "localhost" else defaultHost
    var baseUrl = "http://$displayHost:$defaultPort"

    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--name" -> {
                i++
                if (i < args.size) clientName = args[i]
            }
            "--client-id" -> {
                i++
                if (i < args.size) clientId = args[i]
            }
            "--expiration" -> {
                i++
                if (i < args.size) expiration = Duration.parseIsoString(args[i])
            }
            "--base-url" -> {
                i++
                if (i < args.size) baseUrl = args[i].trimEnd('/')
            }
            "--help", "-h" -> {
                printUsage()
                return
            }
        }
        i++
    }

    val crypto = CryptoContext(secretFile)
    val tokenIssuer = JwtTokenIssuer(crypto = crypto)
    val finalClientId = clientId ?: TokenUtils.generateClientId()
    val jti = UUID.randomUUID().toString()
    val token = tokenIssuer.createAccessToken(finalClientId, jti, clientName, expiration)
    val provisionToken = HmacToken.generate(finalClientId, crypto.jwtSecret)

    println("""
        Client ID: $finalClientId
        Token: $token

        Provision URL (expires in 15 minutes):
        $baseUrl$provisionEndpoint?client_id=$finalClientId&auth_token=$provisionToken

        Instructions:
        1. Open the provision URL in a browser to complete setup
        2. Configure your client with the bearer token above
    """.trimIndent())
}

private fun printUsage() {
    println("""
        Generate Bearer Token for OAuth Server

        Creates a bearer token and a one-time provision URL. Use the provision URL to
        complete setup (e.g., enter credentials), then use the token
        for API authentication.

        Usage: ./gradlew :server:generateToken --args="[options]"

        Options:
          --name <name>         Client name to embed in token (default: "cli-client")
          --client-id <id>      Use specific client ID (default: auto-generated)
          --expiration <dur>    ISO 8601 duration for token (default: PT0S = never expires)
          --base-url <url>      Server base URL (default: http://localhost:8080)
          --help, -h            Show this help message

        Examples:
          # Basic usage (defaults: auto-generated client ID, never expires)
          ./gradlew :server:generateToken

          # With client name
          ./gradlew :server:generateToken --args="--name 'LM Studio'"

          # With specific client ID
          ./gradlew :server:generateToken --args="--client-id my-lm-studio"

          # Token expires in 90 days
          ./gradlew :server:generateToken --args="--expiration PT2160H"

        ISO 8601 Duration format:
          PT0S     = never expires (zero seconds)
          PT24H    = 24 hours
          PT168H   = 1 week
          PT2160H  = 90 days
    """.trimIndent())
}
