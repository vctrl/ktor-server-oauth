package com.vcontrol.ktor.oauth.session

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.SessionTracker
import io.ktor.util.AttributeKey
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.reflect.KClass
import kotlin.time.Duration

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
 * - TTL-based expiration via [SessionRecord]
 *
 * Sessions are wrapped in a [SessionRecord] that tracks creation time and expiration.
 * Expiration is set once at creation and not extended on updates.
 *
 * @param S The session data class type (must be @Serializable)
 * @param type The KClass of the session type
 * @param storage Storage for persisting session records
 * @param ttl Time-to-live for sessions (from creation, not extended on update)
 * @param json Json instance for serialization
 */
@OptIn(InternalSerializationApi::class)
class BearerSessionTracker<S : Any>(
    private val type: KClass<S>,
    private val storage: SessionRecordStorage,
    private val ttl: Duration,
    private val json: Json = DefaultSessionJson
) : SessionTracker<S> {

    private val serializer = type.serializer()
    private val sessionName = type.java.name

    /**
     * Load session from storage using the session key.
     *
     * The record is stored as plaintext JSON with metadata (createdAt, expiresAt).
     * Only the inner data field may be encrypted if a session key was present.
     *
     * Sessions are wrapped in a [SessionRecord] that tracks expiration.
     * Returns null if the session has expired.
     *
     * @param call The application call (used to get encryption key)
     * @param transport The session key string from [BearerSessionTransport]
     * @return The deserialized session object, or null if not found or expired
     */
    override suspend fun load(call: ApplicationCall, transport: String?): S? {
        val sessionKey = transport ?: return null
        val key = storageKey(sessionKey, sessionName)

        // Read record from storage
        val record = storage.read(key) ?: return null

        // Check expiration
        if (record.isExpired()) {
            logger.debug { "Session expired for $sessionKey (expired at ${record.expiresAt})" }
            storage.delete(key)
            return null
        }

        // Decrypt data field if encryption key is present
        val encryptionKey = call.attributes.getOrNull(SessionKeyAttributeKey)
        val sessionData = if (encryptionKey != null) {
            try {
                SessionEncryption.decrypt(record.data, encryptionKey)
            } catch (e: Exception) {
                logger.warn { "Failed to decrypt session data for $sessionKey: ${e.message}" }
                return null
            }
        } else {
            record.data
        }

        // Deserialize session data
        return try {
            json.decodeFromString(serializer, sessionData)
        } catch (e: Exception) {
            logger.error(e) { "Failed to deserialize session data for $sessionKey" }
            null
        }
    }

    /**
     * Store session in storage using the session key.
     *
     * If a session encryption key is available from the JWT, the session data
     * is encrypted before storage. The record metadata (createdAt, expiresAt)
     * is always stored as plaintext.
     *
     * On first store, expiration is set based on TTL. On updates, the original
     * expiration is preserved to prevent sessions from outliving their lifetime.
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
        val key = storageKey(sessionKey, sessionName)

        // Serialize the session data
        val serializedData = json.encodeToString(serializer, value)

        // Encrypt data if key available, otherwise plaintext
        val dataToStore = if (encryptionKey != null) {
            SessionEncryption.encrypt(serializedData, encryptionKey)
        } else {
            serializedData
        }

        // Write to storage - storage handles record creation and timestamp preservation
        storage.write(key, dataToStore, ttl)
        return sessionKey
    }

    /**
     * Clear session from storage.
     */
    override suspend fun clear(call: ApplicationCall) {
        val sessionKey = BearerSessionTransport().receive(call) ?: return
        val key = storageKey(sessionKey, sessionName)
        storage.delete(key)
    }

    /**
     * Validate session - no-op for basic implementation.
     */
    override fun validate(value: S) {
        // No validation required
    }
}
