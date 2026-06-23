package com.dlai.oidc.authserver.model

/**
 * Represents a registered OAuth2 client.
 */
data class RegisteredClient(
    val clientId: String,
    val clientSecret: String?,
    val redirectUris: Set<String>,
    val scopes: Set<String>,
    val requirePkce: Boolean = true
)