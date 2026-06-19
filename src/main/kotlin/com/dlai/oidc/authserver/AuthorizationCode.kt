package com.dlai.oidc.authserver

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
    val expiresAt: Instant,
    var consumed: Boolean = false
) {
    fun isExpired(): Boolean = Instant.now().isAfter(expiresAt)
}