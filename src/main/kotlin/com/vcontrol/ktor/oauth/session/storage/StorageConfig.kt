package com.vcontrol.ktor.oauth.session.storage

import com.vcontrol.ktor.oauth.session.DefaultSessionJson
import com.vcontrol.ktor.oauth.session.SessionRecordStorage
import io.ktor.server.config.*
import kotlinx.serialization.json.Json

/**
 * Base configuration for session record storage.
 * Implementations define storage-specific options.
 */
sealed interface StorageConfig {
    companion object {
        /**
         * Load storage config from HOCON ApplicationConfig.
         *
         * Reads `oauth.sessions.type` to determine storage type:
         * - "file" (default): Uses [FileStorageConfig]
         * - "memory": Uses [InMemoryStorageConfig]
         *
         * Example application.conf:
         * ```hocon
         * oauth {
         *     sessions {
         *         type = "file"  # or "memory"
         *         dataPath = "data/sessions"
         *     }
         * }
         * ```
         */
        fun fromApplicationConfig(config: ApplicationConfig): StorageConfig {
            val type = config.propertyOrNull("oauth.sessions.type")?.getString() ?: "file"
            return when (type) {
                "file" -> FileStorageConfig.fromApplicationConfig(config)
                "memory" -> InMemoryStorageConfig
                else -> error("Unknown session storage type: $type")
            }
        }
    }

    /**
     * Create a SessionRecordStorage instance from this config.
     */
    fun createStorage(): SessionRecordStorage
}

/**
 * Configuration for file-based session storage.
 *
 * @param dataPath Directory path for session files
 * @param json Json serializer configuration
 */
data class FileStorageConfig(
    val dataPath: String,
    val json: Json = DefaultSessionJson
) : StorageConfig {

    override fun createStorage(): SessionRecordStorage =
        FileSessionRecordStorage(this)

    companion object {
        /**
         * Load file storage config from HOCON ApplicationConfig.
         *
         * Reads `oauth.sessions.dataPath` for the directory path.
         */
        fun fromApplicationConfig(config: ApplicationConfig): FileStorageConfig {
            val dataPath = config.propertyOrNull("oauth.sessions.dataPath")?.getString()
                ?: "data/sessions"
            return FileStorageConfig(dataPath = dataPath)
        }
    }
}

/**
 * Configuration for in-memory session storage.
 * No options required - sessions are stored in a ConcurrentHashMap.
 */
data object InMemoryStorageConfig : StorageConfig {
    override fun createStorage(): SessionRecordStorage =
        InMemorySessionRecordStorage()
}
