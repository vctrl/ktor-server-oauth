package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.config.OAuthConfig
import com.vcontrol.ktor.oauth.config.configureAuthentication
import com.vcontrol.ktor.oauth.config.configureServerPlugins
import com.vcontrol.ktor.oauth.route.configureOAuthRoutes
import com.vcontrol.ktor.oauth.token.JwtTokenIssuer
import io.ktor.server.application.*

/**
 * DSL marker to prevent nested scope leaking.
 */
@DslMarker
annotation class OAuthDsl

// ============================================================================
// Registry
// ============================================================================

/**
 * Registry holding OAuth configuration.
 * Access via Application.oauth property after installing the OAuth plugin.
 */
class OAuthRegistry(
    val application: Application,
    val localAuthServer: LocalAuthServerConfig?,
    initialProviders: Map<String?, ProviderConfig>,
    /** Loaded configuration from application.conf */
    val config: OAuthConfig = OAuthConfig.load()
) {
    /**
     * All configured auth providers (mutable to support module extensions).
     * Key is provider name (null for default provider).
     */
    private val _authProviders = initialProviders.toMutableMap()

    val authProviders: Map<String?, ProviderConfig>
        get() = _authProviders

    /**
     * Token issuer for the local auth server.
     * Created during authentication configuration.
     */
    private var _tokenIssuer: JwtTokenIssuer? = null

    /**
     * Get the token issuer.
     * Returns null if not configured yet.
     */
    fun getTokenIssuer(): JwtTokenIssuer? {
        return _tokenIssuer
    }

    /**
     * JWT verifier for validating tokens issued by this server.
     * Use with Ktor's jwt() for manual configuration:
     * ```kotlin
     * install(Authentication) {
     *     jwt {
     *         verifier(oauth.jwtVerifier)
     *         validate { JWTPrincipal(it.payload) }
     *     }
     * }
     * ```
     */
    val jwtVerifier: com.auth0.jwt.interfaces.JWTVerifier by lazy {
        val tokenIssuer = _tokenIssuer
            ?: error("Token issuer not configured. Make sure OAuth plugin is fully initialized.")
        com.auth0.jwt.JWT.require(tokenIssuer.algorithm)
            .withIssuer(tokenIssuer.jwtIssuer)
            .build()
    }

    /**
     * Register the token issuer.
     * Called during authentication configuration.
     */
    internal fun registerTokenIssuer(issuer: JwtTokenIssuer) {
        _tokenIssuer = issuer
    }

    /**
     * Authorization code storage.
     * Created based on oauth.server.authCodeStorage config.
     */
    val authCodeStorage: AuthCodeStorage by lazy {
        val storageConfig = config.server.authCodeStorage
        when (storageConfig) {
            "memory" -> AuthCodeStorageMemory()
            else -> {
                try {
                    val clazz = Class.forName(storageConfig)
                    clazz.getDeclaredConstructor().newInstance() as AuthCodeStorage
                } catch (e: Exception) {
                    throw IllegalArgumentException(
                        "Failed to instantiate AuthCodeStorage: $storageConfig", e
                    )
                }
            }
        }
    }

    /**
     * Authorization provider for the OAuth flow.
     * Uses the configured authCodeStorage.
     */
    val authorizationProvider: AuthorizationProvider by lazy {
        AuthorizationProvider(authCodeStorage)
    }

    /**
     * Check if provision is configured for a provider.
     */
    fun hasProvision(providerName: String?): Boolean {
        return _authProviders[providerName]?.provisionConfig != null
    }

    /**
     * Get the provider config by name.
     */
    fun getProvider(name: String?): ProviderConfig? {
        return _authProviders[name]
    }

    /**
     * Register a new provider (for module extensions).
     * @throws IllegalArgumentException if provider name is empty or already exists
     */
    internal fun registerProvider(name: String, config: ProviderConfig) {
        require(name.isNotEmpty()) { "Module provider requires a non-empty name" }
        require(name !in _authProviders) { "Provider '$name' already registered" }
        _authProviders[name] = config
    }

    /**
     * Set or update the default provider.
     * Used when defining provisions via oauth { provision { } }.
     */
    internal fun setDefaultProvider(config: ProviderConfig) {
        _authProviders[null] = config
    }
}

// ============================================================================
// Plugin Definition
// ============================================================================

val OAuth = createApplicationPlugin(name = "OAuth", createConfiguration = ::OAuthPluginConfig) {
    val config = pluginConfig

    val registry = OAuthRegistry(
        application = application,
        localAuthServer = config.localAuthServer,
        initialProviders = emptyMap()  // Providers are registered via oauth { } extension
    )
    application.attributes.put(OAuthKey, registry)

    // Store config for routes to access
    application.attributes.put(OAuthPluginConfigKey, config)

    // Auto-configure bearer token authentication FIRST
    // This must come before Sessions so that clientId attribute is set before session loading
    application.configureAuthentication()

    // Auto-configure server plugins (ContentNegotiation, StatusPages)
    // Note: Sessions are configured separately via install(OAuthSessions)
    application.configureServerPlugins()

    // Install OAuth routes (only if local auth server is configured)
    if (config.localAuthServer != null) {
        application.configureOAuthRoutes()
    }

    // Provision routes are installed via oauth { provision { } } routing extension

    // Set application context for oauth() extension in install(Authentication) { }
    // This allows oauth() to access the application without explicit parameter
    OAuthApplicationContext.set(application)
}

