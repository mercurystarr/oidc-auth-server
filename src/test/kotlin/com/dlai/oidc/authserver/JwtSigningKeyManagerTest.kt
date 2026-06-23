package com.dlai.oidc.authserver

import com.nimbusds.jose.jwk.JWKSet
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class JwtSigningKeyManagerTest {

    @Test
    fun `publicJwkSet returns a key set for public use`() {
        val keyManager = JwtSigningKeyManager()
        val jwkSet = keyManager.publicJwkSet()
        // "d" is the RSA private exponent (RFC 7518 §6.3.2), it must never appear in a publicly-published JWKS
        assertFalse(jwkSet.contains("\"d\""))
        val parsedJwkSet = JWKSet.parse(jwkSet)
        assertEquals(keyManager.keyId, parsedJwkSet.keys.first().keyID)
        assertEquals(keyManager.rsaKey.toPublicJWK(), parsedJwkSet.keys.first())
    }
}