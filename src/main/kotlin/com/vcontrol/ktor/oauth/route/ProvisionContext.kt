package com.vcontrol.ktor.oauth.route

import com.vcontrol.ktor.oauth.model.ClientIdentity
import com.vcontrol.ktor.oauth.model.ProvisionSession
import com.vcontrol.ktor.oauth.token.ClaimsBuilder
import com.vcontrol.ktor.oauth.token.ProvisionClaims
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
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
 * Provides provision-specific functionality:
 * - [client]: The client identity (includes clientId and optionally clientName)
 * - [complete]: Signal provision completion with optional claims
 *
 * Access via [ApplicationCall.provision] extension:
 * ```kotlin
 * provision {
 *     post {
 *         val params = call.receiveParameters()
 *         if (params["password"] == "letmein") {
 *             call.sessions.set(MySession(apiKey = params["api_key"]))
 *             call.provision.complete {
 *                 withClaim("username", params["username"])
 *             }
 *         } else {
 *             call.respondText("Invalid password")
 *         }
 *     }
 * }
 * ```
 */
class ProvisionContext(
    private val call: ApplicationCall,
    private val session: ProvisionSession
) {
    /** The full client identity for this provision session */
    val client: ClientIdentity get() = session.identity.client

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
        val newClaims = ClaimsBuilder().apply(builder).build()

        // Merge with existing claims
        val mergedClaims = ProvisionClaims(
            plain = session.claims.plain + newClaims.plain,
            encrypted = session.claims.encrypted + newClaims.encrypted
        )
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
// ApplicationCall Extension
// ============================================================================

/**
 * Access the provision context for this call.
 *
 * Provides access to:
 * - [ProvisionContext.client] - The client identity (clientId and optionally clientName)
 * - [ProvisionContext.complete] - Complete the provision flow with optional claims
 *
 * Example:
 * ```kotlin
 * provision {
 *     get {
 *         val clientId = call.provision.client.clientId
 *         call.respondText(formHtml, ContentType.Text.Html)
 *     }
 *     post {
 *         val params = call.receiveParameters()
 *         call.sessions.set(MySession(apiKey = params["api_key"]))
 *         call.provision.complete {
 *             withClaim("username", params["username"])
 *         }
 *     }
 * }
 * ```
 *
 * @throws IllegalStateException if called outside a provision route
 */
val ApplicationCall.provision: ProvisionContext
    get() {
        val session = attributes.getOrNull(ProvisionSessionKey)
            ?: error("Not in a provision context. This is only available within provision { } routes.")
        return ProvisionContext(this, session)
    }

