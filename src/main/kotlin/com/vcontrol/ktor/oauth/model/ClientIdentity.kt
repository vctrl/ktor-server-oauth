package com.vcontrol.ktor.oauth.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Sealed class representing client identity in OAuth flows.
 *
 * Currently only supports:
 * - [Dynamic]: Clients using authorization_code flow (via open registration or pre-configured credentials)
 */
@Serializable
sealed class ClientIdentity {
    /** Client identifier - required by all OAuth RFCs */
    abstract val clientId: String

    /** Display name - optional */
    open val clientName: String? get() = null

    /**
     * Client using authorization_code flow.
     * Can be from open registration (RFC 7591) or pre-configured credentials.
     */
    @Serializable
    @SerialName("dynamic")
    data class Dynamic(
        override val clientId: String,
        override val clientName: String? = null
    ) : ClientIdentity()
}
