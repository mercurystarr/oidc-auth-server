package com.dlai.oidc.authserver.controller

import com.dlai.oidc.authserver.repository.AuthorizationCodeRepository
import com.dlai.oidc.authserver.repository.ClientRepository
import com.dlai.oidc.authserver.repository.RefreshTokenRepository
import com.dlai.oidc.authserver.security.JwtSigningKeyManager
import com.dlai.oidc.authserver.service.TokenService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertAll
import org.junit.jupiter.api.assertNotNull
import org.junit.jupiter.api.assertNull
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.web.util.UriComponentsBuilder

class AuthorizationControllerTest {
    val jwtSigningKeyManager = JwtSigningKeyManager()
    val issuer = "http://localhost:8080"
    val clientRepository = ClientRepository()
    val authCodeRepository = AuthorizationCodeRepository()
    val refreshTokenRepository = RefreshTokenRepository()
    val tokenService = TokenService(jwtSigningKeyManager, issuer, 1L, 10L)
    val authorizationController = AuthorizationController(
        clientRepository, authCodeRepository, refreshTokenRepository, tokenService, 1L, 1L
    )

    val authentication = TestingAuthenticationToken("test-user", "password", "USER")

    @Test
    fun `successful authorization with openid scope`() {
        val result = authorizationController.authorize(
            "code",
            "demo-client",
            "http://localhost:9700/callback",
            "openid profile",
            "state",
            "code_challenge",
            "S256",
            null,
            authentication
        )
        assertTrue(result.statusCode.is3xxRedirection)
        assertTrue(result.headers.location.toString().contains("code="))
        assertTrue(result.headers.location.toString().contains("state="))
    }

    @Test
    fun `expect exception when response_type is not code`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            authorizationController.authorize(
                "some_other_response_type",
                "demo-client",
                "http://localhost:9700/callback",
                "profile email",
                "state",
                "code_challenge",
                "S256",
                null,
                authentication
            )
        }
        assertEquals("response_type must be 'code'", exception.message)
    }

    @Test
    fun `expect exception when clientId not registered`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            authorizationController.authorize(
                "code",
                "other-client",
                "http://localhost:9700/callback",
                "profile email",
                "state",
                "code_challenge",
                "S256",
                null,
                authentication
            )
        }
        assertEquals("Invalid client_id", exception.message)
    }

    @Test
    fun `expect exception when redirectUri not registered`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            authorizationController.authorize(
                "code",
                "demo-client",
                "http://test.com/callback",
                "profile email",
                "state",
                "code_challenge",
                "S256",
                null,
                authentication
            )
        }
        assertEquals("Invalid redirect_uri", exception.message)
    }

    @Test
    fun `expect exception when code_challenge_method is not supported`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            authorizationController.authorize(
                "code",
                "demo-client",
                "http://localhost:9700/callback",
                "profile email",
                "state",
                "code_challenge",
                "OtherMethod",
                null,
                authentication
            )
        }
        assertEquals("code_challenge_method must be 'S256'", exception.message)
    }

    @Test
    fun `stored authorization code is has correct fields`() {
        val result = authorizationController.authorize(
            "code",
            "demo-client",
            "http://localhost:9700/callback",
            "openid profile",
            "state",
            "code_challenge",
            "S256",
            null,
            authentication
        )
        assertTrue(result.statusCode.is3xxRedirection)
        assertTrue(result.headers.location.toString().contains("code="))

        val location = result.headers.location!!
        val code = UriComponentsBuilder.fromUri(location).build().queryParams.getFirst("code")!!
        val authCode = authCodeRepository.consume(code)

        assertNotNull(authCode)
        assertAll(
            { assertEquals("demo-client", authCode.clientId) },
            { assertEquals("test-user", authCode.subject) },
            { assertEquals(setOf("openid", "profile"), authCode.scopes) },
            { assertEquals("code_challenge", authCode.codeChallenge) },
            { assertEquals("S256", authCode.codeChallengeMethod) },
            { assertNull(authCode.nonce) },
            { assertTrue(authCode.consumed) },
            { assertFalse(authCode.isExpired()) }
        )

    }

    @Test
    fun `nonce is stored when provided`() {
        val result = authorizationController.authorize(
            "code",
            "demo-client",
            "http://localhost:9700/callback",
            "openid profile",
            "state",
            "code_challenge",
            "S256",
            "nonce",
            authentication
        )
        assertTrue(result.statusCode.is3xxRedirection)
        assertTrue(result.headers.location.toString().contains("code="))

        val location = result.headers.location!!
        val code = UriComponentsBuilder.fromUri(location).build().queryParams.getFirst("code")!!
        val authCode = authCodeRepository.consume(code)

        assertNotNull(authCode)
        assertEquals("nonce", authCode.nonce)
    }


}