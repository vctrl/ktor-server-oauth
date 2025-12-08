package com.vcontrol.ktor.oauth.session.storage

import com.vcontrol.ktor.oauth.session.SessionRecord
import com.vcontrol.ktor.oauth.session.SessionRecordMeta
import com.vcontrol.ktor.oauth.session.SessionRecordStorage
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration

/**
 * In-memory implementation of [SessionRecordStorage].
 *
 * Stores sessions in a ConcurrentHashMap. Suitable for development
 * and testing, or single-instance deployments.
 *
 * Note: Sessions are lost on application restart.
 */
class InMemorySessionRecordStorage : SessionRecordStorage {

    private val sessions = ConcurrentHashMap<String, InMemoryRecord>()

    private data class InMemoryRecord(
        override val data: String,
        override val createdAt: Long,
        override val expiresAt: Long
    ) : SessionRecord

    override suspend fun write(id: String, data: String, ttl: Duration) {
        val now = System.currentTimeMillis()
        val existing = sessions[id]

        val record = if (existing != null) {
            // Update: preserve original timestamps
            InMemoryRecord(
                data = data,
                createdAt = existing.createdAt,
                expiresAt = existing.expiresAt
            )
        } else {
            // New session: set expiration based on TTL
            InMemoryRecord(
                data = data,
                createdAt = now,
                expiresAt = now + ttl.inWholeMilliseconds
            )
        }

        sessions[id] = record
    }

    override suspend fun read(id: String): SessionRecord? {
        return sessions[id]
    }

    override suspend fun delete(id: String) {
        sessions.remove(id)
    }

    override fun scan(): Flow<SessionRecordMeta> = flow {
        // Sort by creation time (oldest first)
        val entries = sessions.entries.sortedBy { it.value.createdAt }
        for ((id, record) in entries) {
            emit(SessionRecordMeta(id = id, expiresAt = record.expiresAt))
        }
    }
}
