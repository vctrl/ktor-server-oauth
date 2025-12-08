package com.vcontrol.ktor.oauth.session

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect

/**
 * Interface for session records with expiration metadata.
 *
 * Session records wrap serialized session data with timestamps for:
 * - Creation time tracking (auditing)
 * - Expiration enforcement (TTL-based cleanup)
 *
 * Expiration is set once at creation and not extended on updates,
 * ensuring sessions don't outlive their intended lifetime.
 */
interface SessionRecord {
    /** Serialized session data (may be encrypted) */
    val data: String
    /** Epoch milliseconds when session was created */
    val createdAt: Long
    /** Epoch milliseconds when session expires */
    val expiresAt: Long

    /** Check if this session has expired */
    fun isExpired(nowMillis: Long = System.currentTimeMillis()): Boolean =
        nowMillis >= expiresAt
}

/**
 * Metadata for a session record, used during scanning/cleanup.
 * Contains just enough info to decide whether to delete.
 */
data class SessionRecordMeta(
    val id: String,
    val expiresAt: Long
)

/**
 * Storage interface for session records.
 *
 * Implementations handle:
 * - Record creation and serialization
 * - Timestamp management (preserving expiration on updates)
 * - Scanning for cleanup processes
 *
 * Callers provide raw data and TTL; storage handles record lifecycle.
 */
interface SessionRecordStorage {
    /**
     * Write session data to storage.
     *
     * If a record exists for this id, preserves the original expiration.
     * If new, sets expiration based on TTL from now.
     *
     * @param id Unique session identifier
     * @param data Serialized session data (may be encrypted)
     * @param ttl Time-to-live for new sessions
     */
    suspend fun write(id: String, data: String, ttl: kotlin.time.Duration)

    /**
     * Read a session record from storage.
     * @return The record, or null if not found
     */
    suspend fun read(id: String): SessionRecord?

    /**
     * Delete a session record from storage.
     */
    suspend fun delete(id: String)

    /**
     * Scan all session records for cleanup.
     *
     * Implementation decides ordering strategy:
     * - File storage: may order by mtime (oldest first)
     * - SQL storage: may order by expiresAt
     *
     * @return Flow of session metadata for cleanup processing
     */
    fun scan(): Flow<SessionRecordMeta>

    /**
     * Remove expired sessions from storage.
     *
     * Default implementation uses [scan] + [delete] to iterate and remove.
     * Override for optimized cleanup (e.g., SQL batch delete) or no-op
     * if storage handles expiration natively (e.g., Redis TTL).
     *
     * @return Count of deleted sessions
     */
    suspend fun cleanup(): Int {
        var deleted = 0
        val now = System.currentTimeMillis()
        scan().collect { meta ->
            if (now >= meta.expiresAt) {
                delete(meta.id)
                deleted++
            }
        }
        return deleted
    }
}
