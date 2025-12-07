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
 * - TTL-based expiration via [SessionEnvelope]
 *
 * Sessions are wrapped in a [SessionEnvelope] that tracks creation time and expiration.
 * Expiration is set once at creation and not extended on updates.
 *
 * @param S The session data class type (must be @Serializable)
 * @param type The KClass of the session type
 * @param storage Storage for persisting session data (any Ktor SessionStorage)
 * @param ttl Time-to-live for sessions (from creation, not extended on update)
 * @param json Json instance for serialization
 */
@OptIn(InternalSerializationApi::class)
class BearerSessionTracker<S : Any>(
    private val type: KClass<S>,
    private val storage: SessionStorage,
    private val ttl: Duration,
    private val json: Json = DefaultSessionJson
) : SessionTracker<S> {

    private val serializer = type.serializer()
    private val sessionName = type.java.name
    private val envelopeSerializer = SessionEnvelope.serializer()

    /**
     * Load session from storage using the session key.
     *
     * If a session encryption key exists in the request, the stored data is decrypted.
     * If no encryption key, the data is treated as plaintext.
     *
     * Sessions are wrapped in a [SessionEnvelope] that tracks expiration.
     * Returns null if the session has expired.
     *
     * @param call The application call (used to get encryption key)
     * @param transport The session key string from [BearerSessionTransport]
     * @return The deserialized session object, or null if not found or expired
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

        val envelopeJson = if (encryptionKey != null) {
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

        // Deserialize envelope
        val envelope = try {
            json.decodeFromString(envelopeSerializer, envelopeJson)
        } catch (e: Exception) {
            // Try legacy format (plain session without envelope) for migration
            logger.debug { "Attempting legacy session format for $sessionKey" }
            return try {
                json.decodeFromString(serializer, envelopeJson)
            } catch (e2: Exception) {
                logger.error(e) { "Failed to deserialize session for $sessionKey" }
                null
            }
        }

        // Check expiration
        if (envelope.isExpired()) {
            logger.debug { "Session expired for $sessionKey (expired at ${envelope.expiresAt})" }
            // Optionally clean up expired session
            try {
                storage.invalidate(key)
            } catch (_: NoSuchElementException) {
                // Already gone
            }
            return null
        }

        // Deserialize session data from envelope
        return try {
            json.decodeFromString(serializer, envelope.data)
        } catch (e: Exception) {
            logger.error(e) { "Failed to deserialize session data for $sessionKey" }
            null
        }
    }

    /**
     * Store session in storage using the session key.
     *
     * If a session encryption key is available from the JWT, the session data
     * is encrypted before storage. Otherwise stored as plaintext.
     *
     * Sessions are wrapped in a [SessionEnvelope]. On first store, expiration
     * is set based on TTL. On updates, the original expiration is preserved
     * to prevent sessions from outliving their intended lifetime.
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

        // Check for existing envelope to preserve timestamps
        val existingEnvelope = loadEnvelope(key, encryptionKey)

        // Serialize the session data
        val serializedData = json.encodeToString(serializer, value)

        // Create envelope - preserve expiration if updating existing session
        val now = System.currentTimeMillis()
        val envelope = if (existingEnvelope != null) {
            // Update: preserve original timestamps
            SessionEnvelope(
                data = serializedData,
                createdAt = existingEnvelope.createdAt,
                expiresAt = existingEnvelope.expiresAt
            )
        } else {
            // New session: set expiration based on TTL
            SessionEnvelope(
                data = serializedData,
                createdAt = now,
                expiresAt = now + ttl.inWholeMilliseconds
            )
        }

        // Serialize envelope
        val envelopeJson = json.encodeToString(envelopeSerializer, envelope)

        // Encrypt if key available, otherwise store plaintext
        val dataToStore = if (encryptionKey != null) {
            SessionEncryption.encrypt(envelopeJson, encryptionKey)
        } else {
            envelopeJson
        }

        storage.write(key, dataToStore)
        return sessionKey
    }

    /**
     * Load existing envelope from storage (for preserving timestamps on update).
     */
    private suspend fun loadEnvelope(key: String, encryptionKey: String?): SessionEnvelope? {
        val storedData = try {
            storage.read(key)
        } catch (e: NoSuchElementException) {
            return null
        }

        val envelopeJson = if (encryptionKey != null) {
            try {
                SessionEncryption.decrypt(storedData, encryptionKey)
            } catch (e: Exception) {
                return null
            }
        } else {
            storedData
        }

        return try {
            json.decodeFromString(envelopeSerializer, envelopeJson)
        } catch (e: Exception) {
            null // Legacy format or corrupt data
        }
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
