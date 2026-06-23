package com.dlai.oidc.authserver.model

import java.time.Duration
import java.time.Instant

/**
 * Represents an issued authorization code, the short-lived artifact exchanged at the
 * token endpoint for the actual access/ID tokens.
 */
data class AuthorizationCode(
    val code: String,
    val clientId: String,
    val redirectUri: String,
    val scopes: Set<String>,
    val subject: String,
    val codeChallenge: String,
    val codeChallengeMethod: String,
    val nonce: String?,
    val authTime: Instant,
    val expiresAt: Instant,
    var consumed: Boolean = false
) {
    fun isExpired(): Boolean = Instant.now().isAfter(expiresAt)

    class Builder {
        private var code: String? = null
        private var clientId: String? = null
        private var redirectUri: String? = null
        private var scopes: Set<String> = emptySet()
        private var subject: String? = null
        private var codeChallenge: String? = null
        private var codeChallengeMethod: String? = null
        private var nonce: String? = null
        private var authTime: Instant? = null
        private var expiresAt: Instant? = null
        private var consumed: Boolean = false

        fun code(code: String) = apply { this.code = code }
        fun clientId(clientId: String) = apply { this.clientId = clientId }
        fun redirectUri(redirectUri: String) = apply { this.redirectUri = redirectUri }
        fun scopes(scopes: Set<String>) = apply { this.scopes = scopes }
        fun scopes(vararg scopes: String) = apply { this.scopes = scopes.toSet() }
        fun subject(subject: String) = apply { this.subject = subject }
        fun codeChallenge(codeChallenge: String) = apply { this.codeChallenge = codeChallenge }
        fun codeChallengeMethod(codeChallengeMethod: String) = apply { this.codeChallengeMethod = codeChallengeMethod }
        fun nonce(nonce: String?) = apply { this.nonce = nonce }
        fun authTime(authTime: Instant) = apply { this.authTime = authTime }
        fun expiresAt(expiresAt: Instant) = apply { this.expiresAt = expiresAt }
        fun expiresIn(duration: Duration) = apply { this.expiresAt = Instant.now().plus(duration) }
        fun consumed(consumed: Boolean) = apply { this.consumed = consumed }

        fun build(): AuthorizationCode {
            return AuthorizationCode(
                code = requireNotNull(code) { "code must not be null" },
                clientId = requireNotNull(clientId) { "clientId must not be null" },
                redirectUri = requireNotNull(redirectUri) { "redirectUri must not be null" },
                scopes = scopes,
                subject = requireNotNull(subject) { "subject must not be null" },
                codeChallenge = requireNotNull(codeChallenge) { "codeChallenge must not be null" },
                codeChallengeMethod = requireNotNull(codeChallengeMethod) { "codeChallengeMethod must not be null" },
                nonce = nonce,
                authTime = requireNotNull(authTime) { "authTime must not be null" },
                expiresAt = requireNotNull(expiresAt) { "expiresAt must not be null" },
                consumed = consumed
            )
        }

        companion object {
            fun builder() = Builder()

            fun authorizationCode(init: Builder.() -> Unit): AuthorizationCode =
                Builder().apply(init).build()
        }
    }
}

