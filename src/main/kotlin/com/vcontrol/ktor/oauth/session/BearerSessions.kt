package com.vcontrol.ktor.oauth.session

import io.ktor.server.sessions.*
import kotlinx.serialization.json.Json
import kotlin.reflect.KClass

/**
 * Register a bearer token-bound session type.
 *
 * Sessions registered with this method are stored server-side, keyed by a
 * configurable JWT claim (default: client_id). This enables session data to
 * persist across connections without relying on cookies.
 *
 * Uses Ktor's native [SessionStorage] interface. You can use any Ktor storage:
 * - `directorySessionStorage(rootDir)` for file-based storage
 * - `SessionStorageMemory` for in-memory storage
 * - `CacheStorage(backing, timeout)` for cached storage
 *
 * Session encryption is automatic when a session key is present in the JWT.
 *
 * Usage:
 * ```kotlin
 * install(Sessions) {
 *     // Cookie-based sessions for registration flow
 *     cookie<RegistrationSession>("registration_session") { ... }
 *
 *     // Bearer token-bound sessions for user data
 *     bearerSession<MySession>(directorySessionStorage(File("sessions")))
 * }
 * ```
 *
 * Then access normally via `call.sessions.get<MySession>()` / `call.sessions.set<MySession>()`.
 *
 * @param S The session data class type (must be @Serializable)
 * @param storage Any Ktor SessionStorage implementation
 * @param json Custom Json instance for serialization
 */
inline fun <reified S : Any> SessionsConfig.bearerSession(
    storage: SessionStorage,
    json: Json = DefaultSessionJson
) {
    bearerSession(S::class, storage, json)
}

/**
 * Register a bearer token-bound session type (non-reified version).
 */
fun <S : Any> SessionsConfig.bearerSession(
    type: KClass<S>,
    storage: SessionStorage,
    json: Json = DefaultSessionJson
) {
    val name = type.qualifiedName
        ?: throw IllegalArgumentException("Session type must have a qualified name: $type")

    val transport = BearerSessionTransport()
    val tracker = BearerSessionTracker(
        type = type,
        storage = storage,
        json = json
    )

    val provider = SessionProvider(name, type, transport, tracker)
    register(provider)
}
