package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.config.configureOAuthSessions
import com.vcontrol.ktor.oauth.token.SessionKeyClaimsProvider
import io.ktor.server.application.*
import io.ktor.server.sessions.*
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.reflect.KClass
import kotlin.time.Duration

/**
 * Per-session type configuration.
 */
@OAuthDsl
class SessionTypeConfig {
    /**
     * TTL for this session type. If null, uses the sessions-level or storage default.
     */
    var ttl: Duration? = null
}

/**
 * Base config for session type registration.
 * Provides both OAuth bearerSession-based sessions and standard Ktor session DSL.
 */
@OAuthDsl
abstract class SessionsConfigBase {
    @PublishedApi
    internal val sessionTypes = mutableMapOf<KClass<*>, SessionTypeConfig>()

    @PublishedApi
    internal val ktorSessionConfigs = mutableListOf<SessionsConfig.() -> Unit>()

    /**
     * Default TTL for all session types in this storage.
     * Individual session types can override this with their own ttl.
     * If null, uses the application-level default from config.
     */
    var ttl: Duration? = null

    /**
     * Register a session type to be stored by clientId with default TTL.
     */
    inline fun <reified S : Any> session() {
        sessionTypes[S::class] = SessionTypeConfig()
    }

    /**
     * Register a session type with custom configuration.
     *
     * Example:
     * ```kotlin
     * sessions {
     *     ttl = 30.days  // Default for all session types
     *
     *     session<MySession>()  // Uses 30 days
     *
     *     session<ShortSession> {
     *         ttl = 1.hours  // Override for this type
     *     }
     * }
     * ```
     */
    inline fun <reified S : Any> session(block: SessionTypeConfig.() -> Unit) {
        val config = SessionTypeConfig()
        config.block()
        sessionTypes[S::class] = config
    }

    /**
     * Register a standard Ktor cookie-based session.
     * This delegates to Ktor's native SessionsConfig.cookie() method.
     *
     * Example:
     * ```kotlin
     * sessions {
     *     session<MySession>()  // OAuth bearerSession-based session
     *
     *     cookie<AdminSession>("admin_session") {
     *         cookie.httpOnly = true
     *         cookie.secure = true
     *     }
     * }
     * ```
     */
    inline fun <reified S : Any> cookie(
        name: String,
        noinline block: CookieSessionBuilder<S>.() -> Unit = {}
    ) {
        ktorSessionConfigs += { cookie<S>(name, block) }
    }

    /**
     * Register a standard Ktor header-based session.
     * This delegates to Ktor's native SessionsConfig.header() method.
     *
     * Example:
     * ```kotlin
     * sessions {
     *     header<ApiSession>("X-Api-Session") {
     *         serializer = SessionSerializerReflection(ApiSession::class)
     *     }
     * }
     * ```
     */
    inline fun <reified S : Any> header(
        name: String,
        noinline block: HeaderSessionBuilder<S>.() -> Unit = {}
    ) {
        ktorSessionConfigs += { header<S>(name, block) }
    }
}

/**
 * Builder pattern for session storage.
 * Each storage type defines its own config class.
 */
interface SessionStorageBuilder<C : SessionsConfigBase> {
    /** Create default config for this storage */
    fun createConfig(): C

    /** Build the storage from config */
    fun build(config: C, application: Application): SessionStorage
}

/**
 * Config for DiskSessions.
 * Allows customizing the Json serializer and directory path.
 */
@OAuthDsl
class DiskSessionsConfig : SessionsConfigBase() {
    internal var customJson: Json? = null
    internal var customDataDir: String? = null

    /**
     * Override the session storage directory path.
     * Default: from oauth.sessions.dataDir in application.conf
     *
     * Example:
     * ```kotlin
     * sessions(DiskSessions) {
     *     dataDir = "/var/lib/myapp/sessions"
     *     session<MySession>()
     * }
     * ```
     */
    var dataDir: String?
        get() = customDataDir
        set(value) { customDataDir = value }

    /**
     * Configure a custom Json serializer for session storage.
     * This allows encryption via custom serializers, transformers, etc.
     *
     * Example:
     * ```kotlin
     * sessions(DiskSessions) {
     *     session<MySession>()
     *     json(Json {
     *         ignoreUnknownKeys = true
     *         serializersModule = SerializersModule {
     *             contextual(MyEncryptedSerializer())
     *         }
     *     })
     * }
     * ```
     */
    fun json(json: Json) {
        customJson = json
    }
}

/**
 * Config for InMemorySessionStorage.
 * No additional options - just register session types.
 */
@OAuthDsl
class InMemorySessionsConfig : SessionsConfigBase()

/**
 * Disk session storage builder.
 * Uses Ktor's directorySessionStorage to persist sessions as files.
 *
 * Each session is stored as a separate file, enabling:
 * - File-based cleanup using modification timestamps
 * - Simple backup/restore via file operations
 * - Integration with Ktor's CacheStorage for caching
 */
object DiskSessions : SessionStorageBuilder<DiskSessionsConfig> {
    override fun createConfig() = DiskSessionsConfig()

    override fun build(
        config: DiskSessionsConfig,
        application: Application
    ): SessionStorage {
        val dataDir = config.customDataDir
            ?: application.oauth.config.sessions.dataDir

        return directorySessionStorage(File(dataDir), cached = true)
    }
}

/**
 * In-memory session storage builder.
 * Uses Ktor's SessionStorageMemory for ephemeral sessions.
 *
 * Sessions are lost when the application restarts.
 * Useful for testing or non-persistent session types.
 */
object InMemorySessions : SessionStorageBuilder<InMemorySessionsConfig> {
    override fun createConfig() = InMemorySessionsConfig()

    override fun build(config: InMemorySessionsConfig, application: Application): SessionStorage {
        return SessionStorageMemory()
    }
}

/**
 * Config for EncryptedDiskSessions.
 * Same options as DiskSessionsConfig.
 */
@OAuthDsl
class EncryptedDiskSessionsConfig : SessionsConfigBase() {
    internal var customDataDir: String? = null

    /**
     * Override the session storage directory path.
     * Default: from oauth.sessions.dataDir in application.conf
     */
    var dataDir: String?
        get() = customDataDir
        set(value) { customDataDir = value }
}

/**
 * Encrypted disk session storage builder.
 *
 * Encrypts session data using per-client keys from JWT tokens.
 * Session data is encrypted with AES-256-GCM using a key embedded in each
 * client's JWT token. The server cannot decrypt session data without the
 * client presenting their bearer token.
 *
 * Encryption is handled by the session tracker, not storage.
 * This uses the same directorySessionStorage as DiskSessions - the
 * difference is that EncryptedDiskSessions auto-adds SessionKeyClaimsProvider.
 *
 * Usage:
 * ```kotlin
 * install(OAuth) {
 *     sessions(EncryptedDiskSessions) {
 *         session<MySession>()
 *     }
 *
 *     authorizationServer(LocalAuthServer) {
 *         // SessionKeyClaimsProvider is auto-added when using EncryptedDiskSessions
 *     }
 * }
 * ```
 *
 * Sessions written during provision flow (before JWT exists) are stored
 * unencrypted. They become encrypted on first authenticated access.
 */
object EncryptedDiskSessions : SessionStorageBuilder<EncryptedDiskSessionsConfig> {
    override fun createConfig() = EncryptedDiskSessionsConfig()

    override fun build(config: EncryptedDiskSessionsConfig, application: Application): SessionStorage {
        val dataDir = config.customDataDir
            ?: application.oauth.config.sessions.dataDir

        // Use Ktor's directory storage - encryption is handled by BearerSessionTracker
        return directorySessionStorage(File(dataDir), cached = true)
    }
}

/**
 * Attribute key for storing the session key resolver function.
 * Used by BearerSessionTransport to resolve session keys from JWTs.
 */
internal val SessionKeyResolverKey = io.ktor.util.AttributeKey<(com.auth0.jwt.interfaces.Payload) -> String?>("SessionKeyResolver")

/**
 * Holds a sessions block configuration: builder + config + session types.
 * Multiple of these can exist, each with its own storage instance.
 */
internal data class SessionsBlockConfig(
    val builder: SessionStorageBuilder<*>,
    val config: SessionsConfigBase
) {
    val sessionTypes: Map<KClass<*>, SessionTypeConfig>
        get() = config.sessionTypes

    val storageLevelTtl: Duration?
        get() = config.ttl

    val ktorSessionConfigs: List<SessionsConfig.() -> Unit>
        get() = config.ktorSessionConfigs
}

/**
 * Configuration for OAuth.Sessions sub-plugin.
 *
 * Example:
 * ```kotlin
 * install(OAuth.Sessions) {
 *     session<MySession>()
 * }
 *
 * // Or with custom storage:
 * install(OAuth.Sessions) {
 *     storage(DiskSessions) {
 *         dataDir = "/tmp/sessions"
 *     }
 *     session<MySession>()
 * }
 *
 * // Or with custom session key claim:
 * install(OAuth.Sessions) {
 *     sessionKeyClaim = "tenant_id"  // Use tenant_id instead of client_id
 *     session<MySession>()
 * }
 * ```
 */
@OAuthDsl
class OAuthSessionsPluginConfig {
    internal val sessionsBlocks = mutableListOf<SessionsBlockConfig>()
    internal var currentBuilder: SessionStorageBuilder<*> = DiskSessions
    @PublishedApi internal var currentConfig: SessionsConfigBase = DiskSessions.createConfig()

    /**
     * JWT claim name to use as the session key.
     * Default is "client_id".
     *
     * Use this to key sessions by a different claim, such as:
     * - "tenant_id" for multi-tenant apps
     * - "user_id" or "sub" for user-scoped sessions
     * - Any custom claim from your provision flow
     *
     * Example:
     * ```kotlin
     * install(OAuthSessions) {
     *     sessionKeyClaim = "tenant_id"
     *     session<MySession>()
     * }
     * ```
     */
    var sessionKeyClaim: String = "client_id"

    /**
     * Custom resolver function for deriving the session key from a JWT payload.
     * Takes precedence over [sessionKeyClaim] if set.
     *
     * Use this for complex key derivation logic, such as:
     * - Combining multiple claims
     * - Fallback logic between claims
     * - Transforming claim values
     *
     * Example:
     * ```kotlin
     * install(OAuthSessions) {
     *     sessionKeyResolver { payload ->
     *         payload.getClaim("tenant_id").asString()
     *             ?: payload.getClaim("client_id").asString()
     *             ?: error("No session key claim found")
     *     }
     *     session<MySession>()
     * }
     * ```
     */
    var sessionKeyResolver: ((com.auth0.jwt.interfaces.Payload) -> String)? = null

    /**
     * Resolve the session key from a JWT payload using [sessionKeyResolver] or [sessionKeyClaim].
     */
    internal fun resolveSessionKey(payload: com.auth0.jwt.interfaces.Payload): String? {
        return sessionKeyResolver?.invoke(payload)
            ?: payload.getClaim(sessionKeyClaim).asString()
    }

    /**
     * Configure session storage type.
     * Default is DiskSessions.
     *
     * Example:
     * ```kotlin
     * install(OAuth.Sessions) {
     *     storage(EncryptedDiskSessions) {
     *         dataDir = "/secure/sessions"
     *     }
     *     session<MySession>()
     * }
     * ```
     */
    fun <C : SessionsConfigBase> storage(
        builder: SessionStorageBuilder<C>,
        configure: C.() -> Unit = {}
    ) {
        val config = builder.createConfig().apply(configure)
        currentBuilder = builder
        currentConfig = config
    }

    /**
     * Register a session type that will be stored using clientId-based transport.
     * Sessions are automatically associated with the authenticated client.
     *
     * Example:
     * ```kotlin
     * install(OAuthSessions) {
     *     session<UserPreferences>()
     *     session<ShoppingCart>()
     * }
     * ```
     */
    inline fun <reified T : Any> session() {
        @Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
        currentConfig.sessionTypes[T::class] = SessionTypeConfig()
    }

    internal fun build(): List<SessionsBlockConfig> {
        // If there are session types registered, create a block
        if (currentConfig.sessionTypes.isNotEmpty()) {
            sessionsBlocks.add(SessionsBlockConfig(currentBuilder, currentConfig))
        }
        return sessionsBlocks.toList()
    }
}

/**
 * OAuth.Sessions sub-plugin for configuring client-bound sessions.
 *
 * This plugin extends Ktor's Sessions with OAuth-specific features:
 * - clientId-based session transport (sessions bound to authenticated clients)
 * - Automatic session encryption with per-client keys (when using EncryptedDiskSessions)
 * - Internal OAuth flow cookies (auth_request, provision_session)
 *
 * Must be installed after OAuth plugin.
 *
 * Example:
 * ```kotlin
 * install(OAuth) {
 *     authorizationServer(LocalAuthServer) { openRegistration = true }
 * }
 *
 * install(OAuth.Sessions) {
 *     session<MySession>()
 * }
 *
 * install(Authentication) {
 *     oauth()
 * }
 * ```
 */
val OAuthSessions = createApplicationPlugin(name = "OAuth.Sessions", createConfiguration = ::OAuthSessionsPluginConfig) {
    val config = pluginConfig

    // Verify OAuth is installed
    val registry = application.oauthOrNull
        ?: error("OAuth.Sessions requires OAuth plugin to be installed first. Use install(OAuth) before install(OAuth.Sessions).")

    // Store the session key resolver for BearerSessionTransport to use
    application.attributes.put(SessionKeyResolverKey, config::resolveSessionKey)

    // Build sessions blocks from config
    val sessionsBlocks = config.build()

    // Auto-add SessionKeyClaimsProvider if encrypted sessions are used
    val usesEncryptedSessions = sessionsBlocks.any { it.builder == EncryptedDiskSessions }
    if (usesEncryptedSessions) {
        registry.localAuthServer?.let { authServer ->
            if (SessionKeyClaimsProvider !in authServer.claimsProviders) {
                authServer.claimsProviders.add(0, SessionKeyClaimsProvider)
            }
        }
    }

    // Store sessions blocks for other components to access
    if (sessionsBlocks.isNotEmpty()) {
        application.attributes.put(SessionsBlocksKey, sessionsBlocks)
    }

    // Install sessions
    application.configureOAuthSessions()
}