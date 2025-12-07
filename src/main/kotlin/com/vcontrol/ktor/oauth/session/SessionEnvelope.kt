package com.vcontrol.ktor.oauth.session

import kotlinx.serialization.Serializable

/**
 * Envelope wrapping session data with metadata for expiration management.
 *
 * The envelope stores:
 * - The actual session data (serialized, optionally encrypted)
 * - Creation timestamp for auditing
 * - Expiration timestamp for TTL enforcement
 *
 * Expiration is set once at creation and not extended on updates,
 * ensuring sessions don't outlive their intended lifetime.
 */
@Serializable
data class SessionEnvelope(
    /** Serialized session data (may be encrypted) */
    val data: String,
    /** Epoch milliseconds when session was created */
    val createdAt: Long,
    /** Epoch milliseconds when session expires */
    val expiresAt: Long
) {
    /** Check if this session has expired */
    fun isExpired(nowMillis: Long = System.currentTimeMillis()): Boolean =
        nowMillis >= expiresAt
}
