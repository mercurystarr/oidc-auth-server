package com.dlai.oidc.authserver.service

import com.dlai.oidc.authserver.model.RefreshToken
import com.dlai.oidc.authserver.security.JwtSigningKeyManager
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.UUID

/**
 * Issues RS256-signed access/ID tokens and opaque refresh tokens and verifies signed JWTs
 * (signature + expiry) on redemption.
 */

@Service
class TokenService(
    private val keyManager: JwtSigningKeyManager,
    @Value("\${auth.issuer}") private val issuer: String,
    @Value("\${auth.expiryTime}") private val expiryTime: Long,
    @Value("\${auth.refreshExpiryTime}") private val refreshExpiryTime: Long
) {
    private val secureRandom = SecureRandom()

    fun issueAccessToken(subject: String, clientId: String, scopes: Set<String>): String {
        val now = Instant.now()
        val claimsBuilder = JWTClaimsSet.Builder()
            .subject(subject)
            .issuer(issuer)
            .audience(issuer) // aud can also be a client id
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(expiryTime)))
            .jwtID(UUID.randomUUID().toString())
            .claim("scope", scopes.joinToString(" "))
            .claim("client_id", clientId)
        return sign(claimsBuilder.build())
    }

    fun issueIdToken(subject: String, clientId: String, authTime: Instant, nonce: String?): String {
        val now = Instant.now()
        val claimsBuilder = JWTClaimsSet.Builder()
            .subject(subject)
            .issuer(issuer)
            .audience(clientId) // aud must be the client id
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(expiryTime)))
            .claim("auth_time", Date.from(authTime))

        if (nonce != null) {
            claimsBuilder.claim("nonce", nonce)
        }
        return sign(claimsBuilder.build())
    }

    private fun sign(jwtClaimsSet: JWTClaimsSet): String {
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyManager.keyId).build()
        val signedJWT = SignedJWT(header, jwtClaimsSet)
        val signer = RSASSASigner(keyManager.rsaKey.toRSAPrivateKey())
        signedJWT.sign(signer)
        return signedJWT.serialize()
    }

    fun issueRefreshToken(subject: String, clientId: String, scopes: Set<String>, authTime: Instant, nonce: String?): RefreshToken {
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        return RefreshToken.Builder()
            .token(token)
            .subject(subject)
            .clientId(clientId)
            .scopes(scopes)
            .authTime(authTime)
            .expiresAt(Instant.now().plusSeconds(refreshExpiryTime))
            .nonce(nonce)
            .build()
    }

    fun verify(token: String): JWTClaimsSet {
        val signedJWT = SignedJWT.parse(token)
        val rsaVerifier = RSASSAVerifier(keyManager.rsaKey.toRSAPublicKey())
        if (signedJWT.verify(rsaVerifier)) {
            val expirationTime = signedJWT.jwtClaimsSet.expirationTime?.toInstant()
                ?: throw IllegalArgumentException("Invalid token")
            if (expirationTime.isBefore(Instant.now())) {
                throw IllegalArgumentException("Token expired")
            }
            return signedJWT.jwtClaimsSet
        }
        throw IllegalArgumentException("Invalid token")
    }
}