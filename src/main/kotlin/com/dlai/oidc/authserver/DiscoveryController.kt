package com.dlai.oidc.authserver

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Implements the two endpoints that let a generic OIDC client (or library, like spring-security-oauth2-client)
 * auto-configure itself against this server without hardcoding endpoint URLs: discovery (OIDC Discovery 1.0) and
 * JWKS (RFC 7517).
 */
@RestController
class DiscoveryController(
    private val keyManager: JwtSigningKeyManager,
    @Value("\${auth.issuer}") private val issuer: String
) {

    @GetMapping("/.well-known/openid-configuration", produces = [MediaType.APPLICATION_JSON_VALUE])
    fun discovery(): Map<String, Any> = mapOf(
        "issuer" to issuer,
        "authorization_endpoint" to "$issuer/authorize",
        "token_endpoint" to "$issuer/token",
        "jwks_uri" to "$issuer/.well-known/jwks.json",
        "response_types_supported" to listOf("code"),
        "subject_types_supported" to listOf("public"),
        "id_token_signing_alg_values_supported" to listOf("RS256"),
        "code_challenge_methods_supported" to listOf("S256"),
        "grant_types_supported" to listOf("authorization_code", "refresh_token"),
        "scopes_supported" to listOf("openid",  "profile",  "email")
    )

    @GetMapping("/.well-known/jwks.json", produces = [MediaType.APPLICATION_JSON_VALUE])
    fun jwks(): String = keyManager.publicJwkSet()
}