package com.dlai.oidc.authserver

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class DiscoveryControllerTest {

    private val keyManager = JwtSigningKeyManager()
    private val issuer = "http://localhost:8080"
    private val discoveryController = DiscoveryController(keyManager, issuer)

    @Test
    fun `discovery endpoint returns expected values`() {
        val discovery = discoveryController.discovery()

        assertEquals(issuer, discovery["issuer"])
        assertEquals("$issuer/authorize", discovery["authorization_endpoint"])
        assertEquals("$issuer/token", discovery["token_endpoint"])
        assertEquals("$issuer/.well-known/jwks.json", discovery["jwks_uri"])
        assertEquals(listOf("code"), discovery["response_types_supported"])
        assertEquals(listOf("public"), discovery["subject_types_supported"])
        assertEquals(listOf("RS256"), discovery["id_token_signing_alg_values_supported"])
        assertEquals(listOf("S256"), discovery["code_challenge_methods_supported"])
        assertEquals(listOf("authorization_code", "refresh_token"), discovery["grant_types_supported"])
        assertEquals(listOf("openid", "profile", "email"), discovery["scopes_supported"])
    }

    @Test
    fun `jwks endpoint returns expected values`() {
        val jwks = discoveryController.jwks()

        assertEquals(keyManager.publicJwkSet(), jwks)
    }
}