package com.dlai.oidc.authserver.controller

import com.dlai.oidc.authserver.exception.OAuthException
import com.dlai.oidc.authserver.repository.AuthorizationCodeRepository
import com.dlai.oidc.authserver.repository.ClientRepository
import com.dlai.oidc.authserver.repository.RefreshTokenRepository
import com.dlai.oidc.authserver.security.JwtSigningKeyManager
import com.dlai.oidc.authserver.service.TokenService
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertAll
import org.junit.jupiter.api.assertNotNull
import org.junit.jupiter.api.assertNull
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.web.util.UriComponentsBuilder
import java.security.MessageDigest
import java.util.Base64

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
    private val codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    private val codeChallenge = computeChallenge(codeVerifier)

    @Nested
    inner class AuthorizeEndpointTests {
        @Test
        fun `successful authorization with openid scope`() {
            val result = authorizationController.authorize(
                "code",
                "demo-client",
                "http://localhost:9700/callback",
                "openid profile",
                "state",
                codeChallenge,
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
            assertThrows(OAuthException::class.java) {
                authorizationController.authorize(
                    "some_other_response_type",
                    "demo-client",
                    "http://localhost:9700/callback",
                    "profile email",
                    "state",
                    codeChallenge,
                    "S256",
                    null,
                    authentication
                )
            }.also {
                assertEquals("invalid_request", it.error)
                assertEquals("response_type must be 'code'", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when clientId not registered`() {
            assertThrows(OAuthException::class.java) {
                authorizationController.authorize(
                    "code",
                    "other-client",
                    "http://localhost:9700/callback",
                    "profile email",
                    "state",
                    codeChallenge,
                    "S256",
                    null,
                    authentication
                )
            }.also {
                assertEquals("invalid_request", it.error)
                assertEquals("Invalid client_id", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when redirectUri not registered`() {
            assertThrows(OAuthException::class.java) {
                authorizationController.authorize(
                    "code",
                    "demo-client",
                    "http://test.com/callback",
                    "profile email",
                    "state",
                    codeChallenge,
                    "S256",
                    null,
                    authentication
                )
            }.also {
                assertEquals("invalid_request", it.error)
                assertEquals("Invalid redirect_uri", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when code_challenge_method is not supported for authorize request`() {
            assertThrows(OAuthException::class.java) {
                authorizationController.authorize(
                    "code",
                    "demo-client",
                    "http://localhost:9700/callback",
                    "profile email",
                    "state",
                    codeChallenge,
                    "OtherMethod",
                    null,
                    authentication
                )
            }.also {
                assertEquals("invalid_request", it.error)
                assertEquals("code_challenge_method must be 'S256'", it.errorDescription)
            }
        }

        @Test
        fun `stored authorization code has correct fields`() {
            val result = authorizationController.authorize(
                "code",
                "demo-client",
                "http://localhost:9700/callback",
                "openid profile",
                "state",
                codeChallenge,
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
                { assertEquals(codeChallenge, authCode.codeChallenge) },
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
                codeChallenge,
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

    @Nested
    inner class TokenEndpointAuthorizationCodeGrantTests {
        @Test
        fun `successful token request with authorization_code grant type`() {
            val authCodeResult = authorizationController.authorize(
                "code",
                "demo-client",
                "http://localhost:9700/callback",
                "openid profile",
                "state",
                codeChallenge,
                "S256",
                null,
                authentication
            )

            val location = authCodeResult.headers.location!!
            val code = UriComponentsBuilder.fromUri(location).build().queryParams.getFirst("code")!!

            val result = authorizationController.token(
                "authorization_code",
                code,
                "http://localhost:9700/callback",
                "demo-client",
                codeVerifier,
                null
            )
            assertTrue(result.statusCode.is2xxSuccessful)

            val responseBody = result.body!!
            assertNotNull(responseBody["access_token"])
            assertNotNull(responseBody["id_token"])
            assertNotNull(responseBody["refresh_token"])
            assertNotNull(responseBody["scope"])
            assertEquals("Bearer", responseBody["token_type"])
            assertEquals(1L, responseBody["expires_in"])
            assertTrue(responseBody["scope"].toString().contains("openid"))
            assertTrue(responseBody["scope"].toString().contains("profile"))
            assertEquals("no-store", result.headers.cacheControl)
            assertDoesNotThrow { tokenService.verify(responseBody["access_token"] as String) }
            assertDoesNotThrow { tokenService.verify(responseBody["id_token"] as String) }
        }

        @Test
        fun `successful token request with authorization_code grant type without openid scope`() {
            val authCodeResult = authorizationController.authorize(
                "code",
                "demo-client",
                "http://localhost:9700/callback",
                "profile email",
                "state",
                codeChallenge,
                "S256",
                null,
                authentication
            )

            val location = authCodeResult.headers.location!!
            val code = UriComponentsBuilder.fromUri(location).build().queryParams.getFirst("code")!!

            val result = authorizationController.token(
                "authorization_code",
                code,
                "http://localhost:9700/callback",
                "demo-client",
                codeVerifier,
                null
            )
            assertTrue(result.statusCode.is2xxSuccessful)

            val responseBody = result.body!!
            assertNotNull(responseBody["access_token"])
            assertNull(responseBody["id_token"])
            assertNotNull(responseBody["refresh_token"])
            assertNotNull(responseBody["scope"])
            assertEquals("Bearer", responseBody["token_type"])
            assertEquals(1L, responseBody["expires_in"])
            assertTrue(responseBody["scope"].toString().contains("profile"))
            assertTrue(responseBody["scope"].toString().contains("email"))
            assertEquals("no-store", result.headers.cacheControl)
            assertDoesNotThrow { tokenService.verify(responseBody["access_token"] as String) }
        }

        @Test
        fun `expect exception when code not present`() {
            assertThrows(OAuthException::class.java) {
                authorizationController.token(
                    "authorization_code",
                    null,
                    "http://localhost:9700/callback",
                    "demo-client",
                    codeVerifier,
                    null
                )
            }.also {
                assertEquals("invalid_request", it.error)
                assertEquals("code is required", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when code_verifier not present`() {
            assertThrows(OAuthException::class.java) {
                authorizationController.token(
                    "authorization_code",
                    "code",
                    "http://localhost:9700/callback",
                    "demo-client",
                    null,
                    null
                )
            }.also {
                assertEquals("invalid_request", it.error)
                assertEquals("code_verifier is required", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when code does not match`() {
            assertThrows(OAuthException::class.java) {
                authorizationController.token(
                    "authorization_code",
                    "some-other-code",
                    "http://localhost:9700/callback",
                    "demo-client",
                    codeVerifier,
                    null
                )
            }.also {
                assertEquals("invalid_grant", it.error)
                assertEquals("Invalid code", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when client_id does not match`() {
            val authCodeResult = authorizationController.authorize(
                "code",
                "demo-client",
                "http://localhost:9700/callback",
                "openid profile",
                "state",
                codeChallenge,
                "S256",
                null,
                authentication
            )

            val location = authCodeResult.headers.location!!
            val code = UriComponentsBuilder.fromUri(location).build().queryParams.getFirst("code")!!

            assertThrows(OAuthException::class.java) {
                authorizationController.token(
                    "authorization_code",
                    code,
                    "http://localhost:9700/callback",
                    "other-client",
                    codeVerifier,
                    null
                )
            }.also {
                assertEquals("invalid_grant", it.error)
                assertEquals("Invalid client_id", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when redirect_uri does not match`() {
            val authCodeResult = authorizationController.authorize(
                "code",
                "demo-client",
                "http://localhost:9700/callback",
                "openid profile",
                "state",
                codeChallenge,
                "S256",
                null,
                authentication
            )

            val location = authCodeResult.headers.location!!
            val code = UriComponentsBuilder.fromUri(location).build().queryParams.getFirst("code")!!

            assertThrows(OAuthException::class.java) {
                authorizationController.token(
                    "authorization_code",
                    code,
                    "http://test.com/callback",
                    "demo-client",
                    codeVerifier,
                    null
                )
            }.also {
                assertEquals("invalid_grant", it.error)
                assertEquals("Invalid redirect_uri", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when code_verifier does not match`() {
            val authCodeResult = authorizationController.authorize(
                "code",
                "demo-client",
                "http://localhost:9700/callback",
                "openid profile",
                "state",
                codeChallenge,
                "S256",
                null,
                authentication
            )

            val location = authCodeResult.headers.location!!
            val code = UriComponentsBuilder.fromUri(location).build().queryParams.getFirst("code")!!

            assertThrows(OAuthException::class.java) {
                authorizationController.token(
                    "authorization_code",
                    code,
                    "http://localhost:9700/callback",
                    "demo-client",
                    "a".repeat(43),
                    null
                )
            }.also {
                assertEquals("invalid_grant", it.error)
                assertEquals("Invalid code_verifier", it.errorDescription)
            }
        }
    }

    @Nested
    inner class TokenEndpointRefreshTokenGrantTests {

        @Test
        fun `successful token request with refresh_token grant type`() {
            val refreshToken = getRefreshTokenWithScope("openid profile")

            val refreshTokenResult = authorizationController.token(
                "refresh_token",
                null,
                null,
                "demo-client",
                null,
                refreshToken
            )

            assertTrue(refreshTokenResult.statusCode.is2xxSuccessful)
            val responseBody = refreshTokenResult.body!!
            assertNotNull(responseBody["access_token"])
            assertNotNull(responseBody["id_token"])
            assertNotNull(responseBody["refresh_token"])
            assertNotNull(responseBody["scope"])
            assertEquals("Bearer", responseBody["token_type"])
            assertEquals(1L, responseBody["expires_in"])
            assertTrue(responseBody["scope"].toString().contains("openid"))
            assertTrue(responseBody["scope"].toString().contains("profile"))
            assertEquals("no-store", refreshTokenResult.headers.cacheControl)

            assertDoesNotThrow { tokenService.verify(responseBody["access_token"] as String) }
            assertDoesNotThrow { tokenService.verify(responseBody["id_token"] as String) }
            assertNotEquals(refreshToken, responseBody["refresh_token"] as String)
        }

        @Test
        fun `successful token request with refresh_token grant type but without openid scope`() {
            val refreshToken = getRefreshTokenWithScope("profile email")

            val refreshTokenResult = authorizationController.token(
                "refresh_token",
                null,
                null,
                "demo-client",
                null,
                refreshToken
            )

            assertTrue(refreshTokenResult.statusCode.is2xxSuccessful)
            val responseBody = refreshTokenResult.body!!
            assertNotNull(responseBody["access_token"])
            assertNull(responseBody["id_token"])
            assertNotNull(responseBody["refresh_token"])
            assertNotNull(responseBody["scope"])
            assertEquals("Bearer", responseBody["token_type"])
            assertEquals(1L, responseBody["expires_in"])
            assertTrue(responseBody["scope"].toString().contains("profile"))
            assertTrue(responseBody["scope"].toString().contains("email"))
            assertEquals("no-store", refreshTokenResult.headers.cacheControl)

            assertDoesNotThrow { tokenService.verify(responseBody["access_token"] as String) }
            assertNotEquals(refreshToken, responseBody["refresh_token"] as String)
        }

        @Test
        fun `expect exception when client_id does not match`() {
            val refreshToken = getRefreshTokenWithScope("profile email")

            assertThrows(OAuthException::class.java) {
                authorizationController.token(
                    "refresh_token",
                    null,
                    null,
                    "other-client",
                    null,
                    refreshToken
                )
            }.also {
                assertEquals("invalid_grant", it.error)
                assertEquals("Invalid client_id", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when refresh_token is reused`() {
            val refreshToken = getRefreshTokenWithScope("profile email")
            refreshTokenRepository.consume(refreshToken)

            assertThrows(OAuthException::class.java) {
                authorizationController.token(
                    "refresh_token",
                    null,
                    null,
                    "demo-client",
                    null,
                    refreshToken
                )
            }.also {
                assertEquals("invalid_grant", it.error)
                assertEquals("Invalid refresh_token", it.errorDescription)
            }
        }

        @Test
        fun `expect exception when refresh_token is not found`() {
            assertThrows(OAuthException::class.java) {
                authorizationController.token(
                    "refresh_token",
                    null,
                    null,
                    "demo-client",
                    null,
                    "this-token-does-not-exist"
                )
            }.also {
                assertEquals("invalid_grant", it.error)
                assertEquals("Invalid refresh_token", it.errorDescription)
            }
        }
    }

    // === Helpers ===

    private fun computeChallenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }

    private fun getRefreshTokenWithScope(scope: String = "openid profile"): String {
        val codeResult = authorizationController.authorize(
            "code",
            "demo-client",
            "http://localhost:9700/callback",
            scope,
            "state",
            codeChallenge,
            "S256",
            null,
            authentication
        )
        val code = UriComponentsBuilder
            .fromUri(codeResult.headers.location!!)
            .build().queryParams.getFirst("code")!!
        return authorizationController.token(
            "authorization_code",
            code,
            "http://localhost:9700/callback",
            "demo-client",
            codeVerifier,
            null
        ).body!!["refresh_token"] as String
    }


}