package com.vcontrol.ktor.oauth.session

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.SessionStorage
import io.ktor.server.sessions.SessionTracker
import io.ktor.util.AttributeKey
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.reflect.KClass

private val logger = KotlinLogging.logger {}

/**
 * Attribute key for passing the session encryption key through the request.
 * Set during authentication when JWT contains a session_key claim.
 */
internal val SessionKeyAttributeKey = AttributeKey<String>("SessionKey")

/**
 * Default Json configuration for session serialization.
 */
val DefaultSessionJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
}

/**
 * Create a composite storage key from session key and session type name.
 */
fun storageKey(sessionKey: String, sessionName: String): String = "$sessionKey:$sessionName"

/**
 * Session tracker that stores sessions keyed by bearer token claims.
 *
 * The [transport] parameter is the session key string received from [BearerSessionTransport].
 *
 * This tracker handles:
 * - Serialization/deserialization of session objects
 * - Encryption/decryption using session key from JWT (implicit: key present = encrypted)
 *
 * Uses Ktor's native [SessionStorage] interface. Session expiration/cleanup can be
 * managed externally using file timestamps (for directorySessionStorage).
 *
 * @param S The session data class type (must be @Serializable)
 * @param type The KClass of the session type
 * @param storage Storage for persisting session data (any Ktor SessionStorage)
 * @param json Json instance for serialization
 */
@OptIn(InternalSerializationApi::class)
class BearerSessionTracker<S : Any>(
    private val type: KClass<S>,
    private val storage: SessionStorage,
    private val json: Json = DefaultSessionJson
) : SessionTracker<S> {

    private val serializer = type.serializer()
    private val sessionName = type.java.name

    /**
     * Load session from storage using the session key.
     *
     * If a session encryption key exists in the request, the stored data is decrypted.
     * If no encryption key, the data is treated as plaintext.
     *
     * @param call The application call (used to get encryption key)
     * @param transport The session key string from [BearerSessionTransport]
     * @return The deserialized session object, or null if not found
     */
    override suspend fun load(call: ApplicationCall, transport: String?): S? {
        val sessionKey = transport ?: return null
        val key = storageKey(sessionKey, sessionName)

        // Read from storage
        val storedData = try {
            storage.read(key)
        } catch (e: NoSuchElementException) {
            return null
        }

        // Check if we have an encryption key - if so, data is encrypted
        val encryptionKey = call.attributes.getOrNull(SessionKeyAttributeKey)

        val sessionJson = if (encryptionKey != null) {
            // Data is encrypted - decrypt it
            try {
                SessionEncryption.decrypt(storedData, encryptionKey)
            } catch (e: Exception) {
                logger.warn { "Failed to decrypt session for $sessionKey: ${e.message}" }
                return null
            }
        } else {
            // No encryption key - data is plaintext
            storedData
        }

        // Deserialize
        return try {
            json.decodeFromString(serializer, sessionJson)
        } catch (e: Exception) {
            logger.error(e) { "Failed to deserialize session for $sessionKey" }
            null
        }
    }

    /**
     * Store session in storage using the session key.
     *
     * If a session encryption key is available from the JWT, the session data
     * is encrypted before storage. Otherwise stored as plaintext.
     *
     * @param call The application call (used to get encryption key)
     * @param value The session object to store
     * @return The session key (passed through from transport)
     */
    override suspend fun store(call: ApplicationCall, value: S): String {
        // Get session key from transport
        val sessionKey = BearerSessionTransport().receive(call)
            ?: throw IllegalStateException("Cannot store session: no session key in context")

        val encryptionKey = call.attributes.getOrNull(SessionKeyAttributeKey)

        // Serialize the session
        val serialized = json.encodeToString(serializer, value)

        // Encrypt if key available, otherwise store plaintext
        val dataToStore = if (encryptionKey != null) {
            SessionEncryption.encrypt(serialized, encryptionKey)
        } else {
            serialized
        }

        val key = storageKey(sessionKey, sessionName)
        storage.write(key, dataToStore)
        return sessionKey
    }

    /**
     * Clear session from storage.
     */
    override suspend fun clear(call: ApplicationCall) {
        val sessionKey = BearerSessionTransport().receive(call) ?: return
        val key = storageKey(sessionKey, sessionName)
        try {
            storage.invalidate(key)
        } catch (_: NoSuchElementException) {
            // Session already cleared or never existed
        }
    }

    /**
     * Validate session - no-op for basic implementation.
     */
    override fun validate(value: S) {
        // No validation required
    }
}
