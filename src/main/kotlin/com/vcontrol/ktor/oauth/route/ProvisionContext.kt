package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.OAuthDsl
import com.vcontrol.ktor.oauth.model.ProvisionSession
import com.vcontrol.ktor.oauth.token.ClaimsBuilder
import com.vcontrol.ktor.oauth.token.ProvisionClaims
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.*

/** Marker nextUrl for standalone provision (not from OAuth flow) */
private const val STANDALONE_MARKER = "standalone://complete"

/** Key for storing the provision session in call attributes */
internal val ProvisionSessionKey = AttributeKey<ProvisionSession>("ProvisionSession")

/** Key for signaling provision completion */
internal val ProvisionCompletedKey = AttributeKey<Boolean>("ProvisionCompleted")

/**
 * Context for provision route handlers.
 *
 * Provides provision-specific functionality on top of [RoutingContext]:
 * - [call]: The application call (delegated from RoutingContext)
 * - [clientId]: The client ID from the provision session
 * - [complete]: Signal provision completion with optional claims
 *
 * Example:
 * ```kotlin
 * provision {
 *     post {
 *         val params = call.receiveParameters()
 *         if (params["password"] == "letmein") {
 *             sessions.set(MySession(apiKey = params["api_key"]))
 *             complete(claims = mapOf("username" to params["username"]))
 *         } else {
 *             call.respondText("Invalid password")
 *         }
 *     }
 * }
 * ```
 */
class ProvisionRoutingContext(
    private val underlying: RoutingContext,
    internal val session: ProvisionSession
) {
    /** The application call */
    val call: ApplicationCall get() = underlying.call

    /** Access to sessions */
    val sessions: CurrentSession get() = call.sessions

    /**
     * The client ID for this provision session.
     */
    val clientId: String get() = session.clientId

    /**
     * Complete the provision flow and redirect back to authorization.
     *
     * Use the builder to add claims to the access token:
     * ```kotlin
     * complete {
     *     withClaim("username", "paul")
     *     withEncryptedClaim("api_key", "secret-123")
     * }
     * ```
     *
     * Encrypted claims are stored securely and can be read using:
     * ```kotlin
     * val apiKey = call.principal<JWTPrincipal>()?.payload?.decryptClaim("api_key", crypto)
     * ```
     */
    suspend fun complete(builder: ClaimsBuilder.() -> Unit = {}) {
        val claimsBuilder = ClaimsBuilder().apply(builder)
        val newClaims = ProvisionClaims.from(claimsBuilder.build())

        // Merge with existing claims
        val mergedClaims = ProvisionClaims(session.claims.values + newClaims.values)
        val updatedSession = session.copy(claims = mergedClaims)

        // Save session
        call.sessions.set(updatedSession)

        if (updatedSession.nextUrl == STANDALONE_MARKER) {
            // Standalone mode - clear session since there's no authorization route
            call.sessions.clear<ProvisionSession>()
            // Standalone mode - show success page
            call.respondText(
                """
                <!DOCTYPE html>
                <html>
                <head><title>Setup Complete</title></head>
                <body style="font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 20px;">
                    <h1>Setup Complete</h1>
                    <p>Configuration completed successfully. You can close this page and use your client.</p>
                </body>
                </html>
                """.trimIndent(),
                ContentType.Text.Html
            )
        } else {
            // OAuth mode - redirect back to authorization flow
            call.respondRedirect(updatedSession.nextUrl)
        }

        // Mark as completed so the phase doesn't run default handling
        call.attributes.put(ProvisionCompletedKey, true)
    }
}

// ============================================================================
// Provision Route DSL
// ============================================================================

/**
 * Type alias for provision handler with [ProvisionRoutingContext] receiver.
 */
typealias ProvisionHandler = suspend ProvisionRoutingContext.() -> Unit

/**
 * Builder for provision routes with [ProvisionRoutingContext] handlers.
 *
 * Wraps Ktor's Route with provision-aware handlers that provide
 * access to [ProvisionRoutingContext.complete] and [ProvisionRoutingContext.clientId].
 */
@OAuthDsl
class ProvisionRouteBuilder(internal val route: Route) {

    /**
     * Handle GET requests.
     *
     * Example:
     * ```kotlin
     * provision {
     *     get {
     *         call.respondText(formHtml, ContentType.Text.Html)
     *     }
     * }
     * ```
     */
    fun get(handler: ProvisionHandler) {
        route.get { wrapHandler(handler) }
    }

    /**
     * Handle POST requests.
     *
     * Example:
     * ```kotlin
     * provision {
     *     post {
     *         val params = call.receiveParameters()
     *         complete(claims = mapOf("username" to params["username"]))
     *     }
     * }
     * ```
     */
    fun post(handler: ProvisionHandler) {
        route.post { wrapHandler(handler) }
    }

    /**
     * Handle all HTTP methods.
     *
     * Example:
     * ```kotlin
     * provision {
     *     handle {
     *         complete()  // Auto-complete without claims
     *     }
     * }
     * ```
     */
    fun handle(handler: ProvisionHandler) {
        route.handle { wrapHandler(handler) }
    }

    /**
     * Handle PUT requests.
     */
    fun put(handler: ProvisionHandler) {
        route.put { wrapHandler(handler) }
    }

    /**
     * Handle DELETE requests.
     */
    fun delete(handler: ProvisionHandler) {
        route.delete { wrapHandler(handler) }
    }

    /**
     * Handle PATCH requests.
     */
    fun patch(handler: ProvisionHandler) {
        route.patch { wrapHandler(handler) }
    }

    /**
     * Wrap the handler with ProvisionRoutingContext.
     */
    private suspend fun RoutingContext.wrapHandler(handler: ProvisionHandler) {
        val session = call.attributes.getOrNull(ProvisionSessionKey)
            ?: error("Provision handler called without provision session")

        val provisionContext = ProvisionRoutingContext(this, session)
        handler(provisionContext)
    }
}

