package com.dlai.oidc.authserver

import com.dlai.oidc.authserver.service.TokenService
import org.hamcrest.CoreMatchers.containsString
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertNotNull
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.core.type.TypeReference
import tools.jackson.databind.ObjectMapper
import java.security.MessageDigest
import java.util.Base64

@SpringBootTest
@AutoConfigureMockMvc
class FullFlowIntegrationTest {
    @Autowired
    lateinit var mockMvc: MockMvc
    @Autowired lateinit var tokenService: TokenService

    private val codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    private val codeChallenge = computeChallenge(codeVerifier)

    @Test
    fun `authorization code PKCE flow returns signed access and id tokens`() {
        val authorizeResult = mockMvc.perform(
            get("/authorize")
                .with(user("test-user").password("password"))
                .param("response_type", "code")
                .param("client_id", "demo-client")
                .param("redirect_uri", "http://localhost:9700/callback")
                .param("scope", "openid profile")
                .param("state", "state")
                .param("code_challenge", codeChallenge)
                .param("code_challenge_method", "S256")
        ).andExpect(status().is3xxRedirection)
            .andExpect(header().string("Location", containsString("code=")))
            .andExpect(header().string("Location", containsString("state=")))
            .andReturn()

        val location = authorizeResult.response.getHeader("Location")!!
        val code = UriComponentsBuilder.fromUriString(location)
            .build().queryParams.getFirst("code")!!

        val tokenResult = mockMvc.perform(
            post("/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", "http://localhost:9700/callback")
                .param("client_id", "demo-client")
                .param("code_verifier", codeVerifier)
        ).andExpect(status().isOk)
            .andExpect(header().string("Cache-Control", "no-store"))
            .andReturn()

        val body = ObjectMapper().readValue(
            tokenResult.response.contentAsString,
            object : TypeReference<Map<String, Any>>() {}
        )
        assertNotNull(body["access_token"])
        assertNotNull(body["id_token"])
        assertNotNull(body["refresh_token"])
        assertDoesNotThrow { tokenService.verify(body["access_token"] as String) }
        assertDoesNotThrow { tokenService.verify(body["id_token"] as String) }
    }

    @Test
    fun `refresh token grant issues new signed tokens`() {
        val authorizeResult = mockMvc.perform(
            get("/authorize")
                .with(user("test-user").password("password"))
                .param("response_type", "code")
                .param("client_id", "demo-client")
                .param("redirect_uri", "http://localhost:9700/callback")
                .param("scope", "openid profile")
                .param("state", "state")
                .param("code_challenge", codeChallenge)
                .param("code_challenge_method", "S256")
        ).andExpect(status().is3xxRedirection)
            .andExpect(header().string("Location", containsString("code=")))
            .andExpect(header().string("Location", containsString("state=")))
            .andReturn()

        val location = authorizeResult.response.getHeader("Location")!!
        val code = UriComponentsBuilder.fromUriString(location)
            .build().queryParams.getFirst("code")!!

        val tokenResult = mockMvc.perform(
            post("/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", "http://localhost:9700/callback")
                .param("client_id", "demo-client")
                .param("code_verifier", codeVerifier)
        ).andExpect(status().isOk)
            .andExpect(header().string("Cache-Control", "no-store"))
            .andReturn()

        val initialBody = ObjectMapper().readValue(
            tokenResult.response.contentAsString,
            object : TypeReference<Map<String, Any>>() {}
        )
        assertNotNull(initialBody["refresh_token"])
        val refreshToken = initialBody["refresh_token"] as String

        val refreshTokenResult = mockMvc.perform(
            post("/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "refresh_token")
                .param("refresh_token", refreshToken)
                .param("client_id", "demo-client")
        ).andExpect(status().isOk)
            .andExpect(header().string("Cache-Control", "no-store"))
            .andReturn()

        val refreshBody = ObjectMapper().readValue(
            refreshTokenResult.response.contentAsString,
            object : TypeReference<Map<String, Any>>() {}
        )
        assertNotNull(refreshBody["access_token"])
        assertNotNull(refreshBody["id_token"])
        assertNotNull(refreshBody["refresh_token"])
        assertDoesNotThrow { tokenService.verify(refreshBody["access_token"] as String) }
        assertDoesNotThrow { tokenService.verify(refreshBody["id_token"] as String) }
        assertNotEquals(refreshToken, refreshBody["refresh_token"] as String)
    }

    // === Helpers ===

    private fun computeChallenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }
}
