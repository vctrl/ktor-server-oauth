package com.vcontrol.ktor.oauth.session.storage

import com.vcontrol.ktor.oauth.session.SessionRecord
import kotlinx.serialization.Serializable

/**
 * File-based session record implementation.
 * Serializable for JSON storage on disk.
 */
@Serializable
data class FileSessionRecord(
    override val data: String,
    override val createdAt: Long,
    override val expiresAt: Long
) : SessionRecord
