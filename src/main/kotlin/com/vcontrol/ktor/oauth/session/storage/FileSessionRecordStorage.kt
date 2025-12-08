package com.vcontrol.ktor.oauth.session.storage

import com.vcontrol.ktor.oauth.session.SessionRecord
import com.vcontrol.ktor.oauth.session.SessionRecordMeta
import com.vcontrol.ktor.oauth.session.SessionRecordStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.time.Duration

/**
 * File-based implementation of [SessionRecordStorage].
 *
 * Stores each session as a JSON file in the specified directory.
 * File names are sanitized session IDs.
 *
 * @param config Configuration for file storage (directory, json serializer)
 */
class FileSessionRecordStorage(
    private val config: FileStorageConfig
) : SessionRecordStorage {

    private val directory = File(config.dataDir)
    private val json = config.json
    private val recordSerializer = FileSessionRecord.serializer()

    init {
        directory.mkdirs()
    }

    override suspend fun write(id: String, data: String, ttl: Duration) {
        withContext(Dispatchers.IO) {
            val file = fileFor(id)
            val now = System.currentTimeMillis()

            // Check for existing record to preserve timestamps
            val existingRecord = readRecord(file)

            val record = if (existingRecord != null) {
                // Update: preserve original timestamps
                FileSessionRecord(
                    data = data,
                    createdAt = existingRecord.createdAt,
                    expiresAt = existingRecord.expiresAt
                )
            } else {
                // New session: set expiration based on TTL
                FileSessionRecord(
                    data = data,
                    createdAt = now,
                    expiresAt = now + ttl.inWholeMilliseconds
                )
            }

            val recordJson = json.encodeToString(recordSerializer, record)
            file.writeText(recordJson)
        }
    }

    override suspend fun read(id: String): SessionRecord? {
        return withContext(Dispatchers.IO) {
            readRecord(fileFor(id))
        }
    }

    override suspend fun delete(id: String) {
        withContext(Dispatchers.IO) {
            fileFor(id).delete()
        }
    }

    override fun scan(): Flow<SessionRecordMeta> = flow {
        val files = withContext(Dispatchers.IO) {
            directory.listFiles()?.sortedBy { it.lastModified() } ?: emptyList()
        }

        for (file in files) {
            val meta = withContext(Dispatchers.IO) {
                readMeta(file)
            }
            if (meta != null) {
                emit(meta)
            }
        }
    }

    /**
     * Read just the metadata (id + expiresAt) from a file.
     * More efficient than reading full record for cleanup scans.
     */
    private fun readMeta(file: File): SessionRecordMeta? {
        if (!file.exists()) return null
        return try {
            val record = json.decodeFromString(recordSerializer, file.readText())
            SessionRecordMeta(
                id = file.name,
                expiresAt = record.expiresAt
            )
        } catch (e: Exception) {
            null // Corrupt or legacy file
        }
    }

    private fun readRecord(file: File): FileSessionRecord? {
        if (!file.exists()) return null
        return try {
            json.decodeFromString(recordSerializer, file.readText())
        } catch (e: Exception) {
            null // Corrupt or legacy file
        }
    }

    private fun fileFor(id: String): File {
        // Sanitize ID for filesystem safety
        val safeName = id.replace(Regex("[^a-zA-Z0-9_:-]"), "_")
        return File(directory, safeName)
    }
}
