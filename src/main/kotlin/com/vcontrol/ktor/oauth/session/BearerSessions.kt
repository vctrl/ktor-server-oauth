package com.vcontrol.ktor.oauth.session

import io.ktor.server.sessions.*
import kotlinx.serialization.json.Json
import kotlin.reflect.KClass
import kotlin.time.Duration

/**
 * Register a bearer token-bound session type.
 *
 * Sessions registered with this method are stored server-side, keyed by a
 * configurable JWT claim (default: jti). This enables session data to
 * persist across connections without relying on cookies.
 *
 * Session encryption is automatic when a session key is present in the JWT.
 * Sessions are wrapped in a [SessionRecord] with TTL-based expiration.
 *
 * Usage:
 * ```kotlin
 * install(Sessions) {
 *     // Cookie-based sessions for registration flow
 *     cookie<RegistrationSession>("registration_session") { ... }
 *
 *     // Bearer token-bound sessions for user data
 *     bearerSession<MySession>(FileSessionRecordStorage(File("sessions")), ttl = 90.days)
 * }
 * ```
 *
 * Then access normally via `call.sessions.get<MySession>()` / `call.sessions.set<MySession>()`.
 *
 * @param S The session data class type (must be @Serializable)
 * @param storage SessionRecordStorage implementation
 * @param ttl Time-to-live for sessions
 * @param json Custom Json instance for serialization
 */
inline fun <reified S : Any> SessionsConfig.bearerSession(
    storage: SessionRecordStorage,
    ttl: Duration,
    json: Json = DefaultSessionJson
) {
    bearerSession(S::class, storage, ttl, json)
}

/**
 * Register a bearer token-bound session type (non-reified version).
 */
fun <S : Any> SessionsConfig.bearerSession(
    type: KClass<S>,
    storage: SessionRecordStorage,
    ttl: Duration,
    json: Json = DefaultSessionJson
) {
    val name = type.qualifiedName
        ?: throw IllegalArgumentException("Session type must have a qualified name: $type")

    val transport = BearerSessionTransport()
    val tracker = BearerSessionTracker(
        type = type,
        storage = storage,
        ttl = ttl,
        json = json
    )

    val provider = SessionProvider(name, type, transport, tracker)
    register(provider)
}
