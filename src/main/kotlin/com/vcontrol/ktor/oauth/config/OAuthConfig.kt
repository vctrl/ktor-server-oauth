package com.vcontrol.ktor.oauth.config

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toKotlinDuration

/**
 * Root OAuth configuration loaded from oauth.* in application.conf.
 *
 * Example config:
 * ```hocon
 * oauth {
 *     server {
 *         routePrefix = "/.oauth"
 *         tokenExpiration = 90d
 *         authCodeStorage = "memory"
 *
 *         jwt {
 *             issuer = "my-server"
 *             secretFile = ${user.home}"/.ktor-oauth/jwt.secret"
 *         }
 *
 *         endpoints {
 *             register = "/register"
 *             authorize = "/authorize"
 *             token = "/token"
 *             provision = "/provision"
 *         }
 *     }
 *
 *     sessions {
 *         storage = "directory"
 *         dataPath = ${user.home}"/.ktor-oauth/sessions"
 *         ttl = 90d
 *         cleanup {
 *             enabled = false
 *             interval = 1h
 *             initialDelay = 5m
 *         }
 *     }
 * }
 * ```
 */
data class OAuthConfig(
    val server: ServerConfig = ServerConfig(),
    val sessions: SessionsConfig = SessionsConfig()
) {
    companion object {
        /**
         * Load configuration from application.conf using ConfigFactory.
         * Merges all application.conf files from classpath (plugin defaults + app overrides).
         */
        fun load(): OAuthConfig {
            val config = ConfigFactory.load()
            return if (config.hasPath("oauth")) {
                config.getConfig("oauth").toOAuthConfig()
            } else {
                OAuthConfig() // Pure Kotlin defaults
            }
        }
    }
}

/**
 * Authorization server configuration.
 */
data class ServerConfig(
    /** Route prefix for all OAuth endpoints (e.g., "/.oauth") */
    val routePrefix: String = "/.oauth",
    /** Default token expiration for issued tokens */
    val tokenExpiration: Duration = 90.days,
    /** Auth code storage: "memory" or fully qualified class name */
    val authCodeStorage: String = "memory",
    /** JWT configuration */
    val jwt: JwtConfig = JwtConfig(),
    /** OAuth endpoint paths */
    val endpoints: EndpointsConfig = EndpointsConfig()
) {
    /** Get full endpoint path with prefix */
    fun endpoint(path: String): String = routePrefix + path
}

/**
 * JWT configuration for token signing.
 */
data class JwtConfig(
    /** JWT issuer claim */
    val issuer: String = "ktor-oauth",
    /** Path to JWT secret file */
    val secretFile: String = System.getProperty("user.home") + "/.ktor-oauth/jwt.secret"
)

/**
 * OAuth endpoint paths (without prefix).
 */
data class EndpointsConfig(
    val register: String = "/register",
    val authorize: String = "/authorize",
    val token: String = "/token",
    val provision: String = "/provision"
)

/**
 * Session storage configuration.
 */
data class SessionsConfig(
    /** Session storage: "directory", "encrypted", or fully qualified class name */
    val storage: String = "directory",
    /** Directory path for session data */
    val dataPath: String = System.getProperty("user.home") + "/.ktor-oauth/sessions",
    /** Maximum session lifetime */
    val ttl: Duration = 90.days,
    /** Background cleanup configuration */
    val cleanup: CleanupConfig = CleanupConfig()
)

/**
 * Cleanup scheduler configuration.
 */
data class CleanupConfig(
    /** Enable background cleanup */
    val enabled: Boolean = false,
    /** Interval between cleanup runs */
    val interval: Duration = 1.hours,
    /** Initial delay before first cleanup run */
    val initialDelay: Duration = 5.minutes
)

// =============================================================================
// Config parsing extensions
// =============================================================================

private fun Config.toOAuthConfig(): OAuthConfig = OAuthConfig(
    server = if (hasPath("server")) getConfig("server").toServerConfig() else ServerConfig(),
    sessions = if (hasPath("sessions")) getConfig("sessions").toSessionsConfig() else SessionsConfig()
)

private fun Config.toServerConfig(): ServerConfig = ServerConfig(
    routePrefix = getStringOrDefault("routePrefix", "/.oauth"),
    tokenExpiration = getDurationOrDefault("tokenExpiration", 90.days),
    authCodeStorage = getStringOrDefault("authCodeStorage", "memory"),
    jwt = if (hasPath("jwt")) getConfig("jwt").toJwtConfig() else JwtConfig(),
    endpoints = if (hasPath("endpoints")) getConfig("endpoints").toEndpointsConfig() else EndpointsConfig()
)

private fun Config.toJwtConfig(): JwtConfig = JwtConfig(
    issuer = getStringOrDefault("issuer", "ktor-oauth"),
    secretFile = getStringOrDefault("secretFile", System.getProperty("user.home") + "/.ktor-oauth/jwt.secret")
)

private fun Config.toEndpointsConfig(): EndpointsConfig = EndpointsConfig(
    register = getStringOrDefault("register", "/register"),
    authorize = getStringOrDefault("authorize", "/authorize"),
    token = getStringOrDefault("token", "/token"),
    provision = getStringOrDefault("provision", "/provision")
)

private fun Config.toSessionsConfig(): SessionsConfig = SessionsConfig(
    storage = getStringOrDefault("storage", "directory"),
    dataPath = getStringOrDefault("dataPath", System.getProperty("user.home") + "/.ktor-oauth/sessions"),
    ttl = getDurationOrDefault("ttl", 90.days),
    cleanup = if (hasPath("cleanup")) getConfig("cleanup").toCleanupConfig() else CleanupConfig()
)

private fun Config.toCleanupConfig(): CleanupConfig = CleanupConfig(
    enabled = getBooleanOrDefault("enabled", false),
    interval = getDurationOrDefault("interval", 1.hours),
    initialDelay = getDurationOrDefault("initialDelay", 5.minutes)
)

// Helper extensions
private fun Config.getStringOrDefault(path: String, default: String): String =
    if (hasPath(path)) getString(path) else default

private fun Config.getBooleanOrDefault(path: String, default: Boolean): Boolean =
    if (hasPath(path)) getBoolean(path) else default

private fun Config.getDurationOrDefault(path: String, default: Duration): Duration =
    if (hasPath(path)) getDuration(path).toKotlinDuration() else default
