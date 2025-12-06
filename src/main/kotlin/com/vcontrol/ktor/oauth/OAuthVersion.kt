package com.vcontrol.ktor.oauth

import java.util.Properties

/**
 * Provides access to the OAuth plugin version at runtime.
 * Version is read from ktor-oauth-version.properties generated during build.
 */
internal object OAuthVersion {
    val current: String by lazy {
        val props = Properties()
        OAuthVersion::class.java.getResourceAsStream("/ktor-oauth-version.properties")?.use { stream ->
            props.load(stream)
        }
        props.getProperty("version", "unknown")
    }
}
