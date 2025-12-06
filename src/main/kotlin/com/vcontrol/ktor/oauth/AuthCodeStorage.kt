package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.model.AuthorizationCode
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Clock

/**
 * Storage for OAuth authorization codes.
 * Codes are ephemeral and short-lived (10 minutes per OAuth spec).
 */
interface AuthCodeStorage {
    /**
     * Store an authorization code.
     */
    fun store(authCode: AuthorizationCode)

    /**
     * Consume an authorization code (single-use).
     * @return the authorization code if found and not expired, null otherwise
     */
    fun consume(code: String): AuthorizationCode?
}

/**
 * In-memory implementation of AuthCodeStorage.
 * Thread-safe using ConcurrentHashMap.
 * Performs lazy cleanup of expired codes on each consume operation.
 */
class AuthCodeStorageMemory : AuthCodeStorage {
    private val codes = ConcurrentHashMap<String, AuthorizationCode>()

    override fun store(authCode: AuthorizationCode) {
        codes[authCode.code] = authCode
    }

    override fun consume(code: String): AuthorizationCode? {
        val authCode = codes.remove(code) ?: return null

        // Check if code has expired
        val now = Clock.System.now().epochSeconds
        if (now > authCode.expiresAt) {
            return null
        }

        // Lazy cleanup of other expired codes
        cleanupExpired()

        return authCode
    }

    private fun cleanupExpired() {
        val now = Clock.System.now().epochSeconds
        codes.entries.removeIf { it.value.expiresAt < now }
    }
}
