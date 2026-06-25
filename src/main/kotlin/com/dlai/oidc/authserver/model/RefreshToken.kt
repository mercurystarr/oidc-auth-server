package com.dlai.oidc.authserver.model

import java.time.Instant

data class RefreshToken(
    val token: String,
    val clientId: String,
    val scopes: Set<String>,
    val subject: String,
    val authTime: Instant,
    val expiresAt: Instant,
    val nonce: String? = null,
    val consumed: Boolean = false
) {
    fun isExpired(): Boolean = Instant.now().isAfter(expiresAt)

    class Builder {
        private var token: String? = null
        private var clientId: String? = null
        private var scopes: Set<String> = emptySet()
        private var subject: String? = null
        private var authTime: Instant? = null
        private var expiresAt: Instant? = null
        private var nonce: String? = null
        private var consumed: Boolean = false

        fun token(token: String) = apply { this.token = token }
        fun clientId(clientId: String) = apply { this.clientId = clientId }
        fun scopes(scopes: Set<String>) = apply { this.scopes = scopes }
        fun scopes(vararg scopes: String) = apply { this.scopes = scopes.toSet() }
        fun subject(subject: String) = apply { this.subject = subject }
        fun authTime(authTime: Instant) = apply { this.authTime = authTime }
        fun expiresAt(expiresAt: Instant) = apply { this.expiresAt = expiresAt }
        fun expiresIn(duration: Long) = apply { this.expiresAt = Instant.now().plusSeconds(duration) }
        fun nonce(nonce: String?) = apply { this.nonce = nonce }
        fun consumed(consumed: Boolean) = apply { this.consumed = consumed }

        fun build(): RefreshToken {
            return RefreshToken(
                token = requireNotNull(token) { "token must not be null" },
                clientId = requireNotNull(clientId) { "clientId must not be null" },
                scopes = scopes,
                subject = requireNotNull(subject) { "subject must not be null" },
                authTime = requireNotNull(authTime) { "authTime must not be null" },
                expiresAt = requireNotNull(expiresAt) { "expiresAt must not be null" },
                nonce = nonce,
                consumed = consumed
            )
        }

        companion object {
            fun builder() = Builder()

            fun refreshToken(init: Builder.() -> Unit): RefreshToken =
                Builder().apply(init).build()
        }
    }
}