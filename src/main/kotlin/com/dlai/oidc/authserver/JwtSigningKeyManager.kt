package com.dlai.oidc.authserver

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import org.springframework.stereotype.Component
import java.util.UUID

/**
 * Holds the RSA keypair used to sign issued JWTs and serves the public half via JWKS.
 *
 * For the sake of simplicity, this is a static keypair that is generated on startup since every restart invalidates all
 * outstanding tokens, and there's no rotation strategy, but in production this would be loaded from a keystore.
 *
 * We use RS256 over HS256 because we need an asymmetric key, where as HS256 is symmetric, and would require the
 * same secret to be shared between the resource and auth server, while RS256 is asymmetric and allows us to share a
 * public key using JWKS.
 */
@Component
class JwtSigningKeyManager {

    val keyId: String = UUID.randomUUID().toString()

    val rsaKey: RSAKey = RSAKeyGenerator(2048)
        .keyID(keyId)
        .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
        .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
        .generate()

    /** Public JWK set, safe to expose at /.well-known/jwks.json */
    fun publicJwkSet(): String = com.nimbusds.jose.jwk.JWKSet(rsaKey.toPublicJWK()).toString()
}
