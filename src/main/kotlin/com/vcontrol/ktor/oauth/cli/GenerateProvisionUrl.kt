package com.vcontrol.ktor.oauth.cli

import com.vcontrol.ktor.oauth.CryptoContext
import com.vcontrol.ktor.oauth.token.HmacToken
import com.typesafe.config.ConfigFactory
import io.ktor.server.config.*

/**
 * CLI tool for generating provision URLs for existing clients.
 *
 * Use this when a client already has a client_id but needs to complete
 * provision to set up session data.
 *
 * Usage:
 *   ./gradlew :server:generateSetupUrl --args="--client-id <id>"
 */
fun main(args: Array<String>) {
    val appConfig = HoconApplicationConfig(ConfigFactory.load())

    val secretFile = appConfig.property("oauth.server.jwt.secretFile").getString()
    val routePrefix = appConfig.propertyOrNull("oauth.server.routePrefix")?.getString() ?: ""
    val defaultPort = appConfig.propertyOrNull("ktor.deployment.port")?.getString() ?: "8080"
    val defaultHost = appConfig.propertyOrNull("ktor.deployment.host")?.getString() ?: "localhost"
    val provisionEndpoint = routePrefix + (appConfig.propertyOrNull("oauth.server.endpoints.provision")?.getString() ?: "/provision")

    var clientId: String? = null
    // 0.0.0.0 means "all interfaces" - use localhost for URLs
    val displayHost = if (defaultHost == "0.0.0.0") "localhost" else defaultHost
    var baseUrl = "http://$displayHost:$defaultPort"

    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--client-id" -> {
                i++
                if (i < args.size) clientId = args[i]
            }
            "--base-url" -> {
                i++
                if (i < args.size) baseUrl = args[i].trimEnd('/')
            }
            "--help", "-h" -> {
                printSetupUrlUsage()
                return
            }
        }
        i++
    }

    if (clientId == null) {
        System.err.println("Error: --client-id is required")
        System.err.println()
        printSetupUrlUsage()
        return
    }

    val crypto = CryptoContext(secretFile)
    val provisionToken = HmacToken.generate(clientId, crypto.jwtSecret)

    println("""
        Provision URL (expires in 15 minutes):
        $baseUrl$provisionEndpoint?client_id=$clientId&auth_token=$provisionToken

        Open this URL in a browser to complete provision for client: $clientId
    """.trimIndent())
}

private fun printSetupUrlUsage() {
    println("""
        Generate Provision URL for OAuth Server

        Creates a one-time provision URL for an existing client ID. Use this when
        a client already has credentials (e.g., via OAuth) but needs to complete
        provision to set up session data.

        Usage: ./gradlew :server:generateSetupUrl --args="--client-id <id>"

        Options:
          --client-id <id>      Client ID to generate provision URL for (required)
          --base-url <url>      Server base URL (default: http://localhost:8080)
          --help, -h            Show this help message

        Examples:
          # Generate provision URL for a specific client
          ./gradlew :server:generateSetupUrl --args="--client-id abc123"

          # With custom server URL
          ./gradlew :server:generateSetupUrl --args="--client-id abc123 --base-url https://oauth.example.com"
    """.trimIndent())
}
