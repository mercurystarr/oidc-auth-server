package com.dlai.oidc.authserver.controller

import com.dlai.oidc.authserver.security.JwtSigningKeyManager
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class DiscoveryControllerTest {

    private val keyManager = JwtSigningKeyManager()
    private val issuer = "http://localhost:8080"
    private val discoveryController = DiscoveryController(keyManager, issuer)

    @Test
    fun `discovery endpoint returns expected values`() {
        val discovery = discoveryController.discovery()

        Assertions.assertEquals(issuer, discovery["issuer"])
        Assertions.assertEquals("$issuer/authorize", discovery["authorization_endpoint"])
        Assertions.assertEquals("$issuer/token", discovery["token_endpoint"])
        Assertions.assertEquals("$issuer/.well-known/jwks.json", discovery["jwks_uri"])
        Assertions.assertEquals(listOf("code"), discovery["response_types_supported"])
        Assertions.assertEquals(listOf("public"), discovery["subject_types_supported"])
        Assertions.assertEquals(listOf("RS256"), discovery["id_token_signing_alg_values_supported"])
        Assertions.assertEquals(listOf("S256"), discovery["code_challenge_methods_supported"])
        Assertions.assertEquals(listOf("authorization_code", "refresh_token"), discovery["grant_types_supported"])
        Assertions.assertEquals(listOf("openid", "profile", "email"), discovery["scopes_supported"])
    }

    @Test
    fun `jwks endpoint returns expected values`() {
        val jwks = discoveryController.jwks()

        Assertions.assertEquals(keyManager.publicJwkSet(), jwks)
    }
}