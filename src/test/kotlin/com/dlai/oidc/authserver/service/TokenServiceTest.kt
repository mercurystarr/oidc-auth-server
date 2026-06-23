package com.dlai.oidc.authserver.service

import com.dlai.oidc.authserver.security.JwtSigningKeyManager
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.UUID

class TokenServiceTest {

    private val keyManager = JwtSigningKeyManager()
    private val issuer = "http://localhost:9000"
    private val expiryTime = 1L
    private val refreshExpiryTime = 10L
    private val tokenService = TokenService(keyManager, issuer, expiryTime, refreshExpiryTime)

    private val subject = "user-123"
    private val clientId = "demo-client"
    private val scopes = setOf("openid", "profile")

    @Test
    fun `issued access token verifies and round-trips its claims`() {
        val token = tokenService.issueAccessToken(subject, clientId, scopes)
        val claims = tokenService.verify(token)

        Assertions.assertEquals(subject, claims.subject)
        Assertions.assertEquals(issuer, claims.issuer)
        Assertions.assertTrue(claims.audience.contains(issuer))
        Assertions.assertEquals(clientId, claims.getStringClaim("client_id"))
        Assertions.assertEquals("openid profile", claims.getStringClaim("scope"))
    }

    @Test
    fun `issued ID token has client id as audience`() {
        val authTime = Instant.now()
        val token = tokenService.issueIdToken(subject, clientId, authTime, null)
        val claims = tokenService.verify(token)

        Assertions.assertEquals(subject, claims.subject)
        Assertions.assertEquals(issuer, claims.issuer)
        Assertions.assertTrue(claims.audience.contains(clientId))
        Assertions.assertEquals(Date.from(authTime.truncatedTo(ChronoUnit.SECONDS)), claims.getDateClaim("auth_time"))

    }

    @Test
    fun `nonce is present when provided`() {
        val authTime = Instant.now()
        val token = tokenService.issueIdToken(subject, clientId, authTime, "nonce")
        val claims = tokenService.verify(token)

        Assertions.assertEquals(subject, claims.subject)
        Assertions.assertEquals(issuer, claims.issuer)
        Assertions.assertTrue(claims.audience.contains(clientId))
        Assertions.assertEquals(Date.from(authTime.truncatedTo(ChronoUnit.SECONDS)), claims.getDateClaim("auth_time"))
        Assertions.assertEquals("nonce", claims.getStringClaim("nonce"))
    }

    @Test
    fun `nonce is absent when not provided`() {
        val authTime = Instant.now()
        val token = tokenService.issueIdToken(subject, clientId, authTime, null)
        val claims = tokenService.verify(token)

        Assertions.assertEquals(subject, claims.subject)
        Assertions.assertEquals(issuer, claims.issuer)
        Assertions.assertTrue(claims.audience.contains(clientId))
        Assertions.assertEquals(Date.from(authTime.truncatedTo(ChronoUnit.SECONDS)), claims.getDateClaim("auth_time"))
        Assertions.assertNull(claims.getStringClaim("nonce"))
    }

    @Test
    fun `verify rejects a token signed with a different key`() {
        val keyManager2 = JwtSigningKeyManager()
        val tokenService2 = TokenService(keyManager2, issuer, expiryTime, refreshExpiryTime)
        val token = tokenService2.issueAccessToken(subject, clientId, scopes)
        Assertions.assertThrows(IllegalArgumentException::class.java) { tokenService.verify(token) }
    }

    @Test
    fun `verify rejects an expired token`() {
        val token = tokenService.issueAccessToken(subject, clientId, scopes)
        Thread.sleep(1000)
        Assertions.assertThrows(IllegalArgumentException::class.java) { tokenService.verify(token) }
    }

    @Test
    fun `verify rejects a token missing the exp claim`() {
        // Build a claim set without exp claim
        val now = Instant.now()
        val claimsBuilder = JWTClaimsSet.Builder()
            .subject(subject)
            .issuer(issuer)
            .audience(issuer) //aud can also be a client id
            .issueTime(Date.from(now))
            .jwtID(UUID.randomUUID().toString())
            .claim("scope", scopes.joinToString(" "))
            .claim("client_id", clientId)
        // Sign the claim set
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyManager.keyId).build()
        val signedJWT = SignedJWT(header, claimsBuilder.build())
        val signer = RSASSASigner(keyManager.rsaKey.toRSAPrivateKey())
        signedJWT.sign(signer)

        val token = signedJWT.serialize()

        Assertions.assertThrows(IllegalArgumentException::class.java) { tokenService.verify(token) }
    }

    @Test
    fun `issued refresh tokens are non-blank and unique`() {
        val refreshToken = tokenService.issueRefreshToken()
        Assertions.assertNotNull(refreshToken)
        Assertions.assertNotEquals("", refreshToken.first)
        Assertions.assertNotEquals(tokenService.issueRefreshToken(), refreshToken)
    }

    @Test
    fun `refresh token expiry is approximately now plus refreshExpiryTime`() {
        val (refreshToken, expiry) = tokenService.issueRefreshToken()
        val now = Instant.now()
        Assertions.assertTrue(expiry.isAfter(now))
        Assertions.assertTrue(expiry.minusSeconds(refreshExpiryTime).isBefore(now))
    }


}