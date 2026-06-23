package com.dlai.oidc.authserver.controller

import com.dlai.oidc.authserver.model.AuthorizationCode
import com.dlai.oidc.authserver.repository.AuthorizationCodeRepository
import com.dlai.oidc.authserver.repository.ClientRepository
import com.dlai.oidc.authserver.service.TokenService
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64

/**
 * Implements the authorization endpoint (RFC 6749 §3.1, with PKCE per RFC 7636) and the
 * token endpoint (RFC 6749 §3.2) for the authorization_code (§4.1) and refresh_token (§6)
 * grants.
 */
@RestController
class AuthorizationController(
    private val clientRepository: ClientRepository,
    private val authorizationCodeRepository: AuthorizationCodeRepository,
    private val tokenService: TokenService,
    @Value("\${auth.codeExpiryTime}") private val codeExpiryTime: Long,
) {

    private val secureRandom = SecureRandom()

    @GetMapping("/authorize")
    fun authorize(
        @RequestParam("response_type") responseType: String,
        @RequestParam("client_id") clientId: String,
        @RequestParam("redirect_uri") redirectUri: String,
        @RequestParam("scope") scope: String,
        @RequestParam("state") state: String,
        @RequestParam("code_challenge", required = false) codeChallenge: String,
        @RequestParam("code_challenge_method", required = false) codeChallengeMethod: String,
        @RequestParam("nonce", required = false) nonce: String?,
        authentication: Authentication
    ): ResponseEntity<Void> {
        if (responseType != "code") {
            throw IllegalArgumentException("response_type must be 'code'")
        }

        val client = clientRepository.findById(clientId) ?: throw IllegalArgumentException("Invalid client_id")
        if (!client.redirectUris.contains(redirectUri)) {
            throw IllegalArgumentException("Invalid redirect_uri")
        }

        if (codeChallengeMethod != "S256") {
            throw IllegalArgumentException("code_challenge_method must be 'S256'")
        }

        val authTime = Instant.now()
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        val code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        val authorizationCode = AuthorizationCode.Builder()
            .code(code)
            .clientId(clientId)
            .redirectUri(redirectUri)
            .scopes(scope.split(" ").toSet())
            .subject(authentication.name)
            .codeChallenge(codeChallenge)
            .codeChallengeMethod(codeChallengeMethod)
            .nonce(nonce)
            .authTime(authTime)
            .expiresAt(authTime.plusSeconds(codeExpiryTime))
            .build()

        authorizationCodeRepository.save(authorizationCode)

        val redirectUriWithCode: URI = UriComponentsBuilder
            .fromUriString(redirectUri)
            .queryParam("code", code)
            .queryParam("state", state)
            .build().toUri()

        return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(redirectUriWithCode)
            .build()
    }

    @PostMapping("/token")
    fun token(
        @RequestParam("grant_type") grantType: String,
        @RequestParam("code", required = false) code: String?,
        @RequestParam("redirect_uri", required = false) redirectUri: String?,
        @RequestParam("client_id") clientId: String,
        @RequestParam("code_verifier", required = false) codeVerifier: String?,
        @RequestParam("refresh_token", required = false) refreshToken: String?
    ): Map<String, Any> {
        // TODO: branch on grant_type:
        //   "authorization_code" ->
        //     1. Look up the stored AuthorizationCode by `code`
        //     2. Reject if missing, expired, or already consumed (single-use enforcement)
        //     3. Reject if redirect_uri doesn't match what was used at /authorize
        //     4. PkceValidator.verify(codeVerifier, storedCode.codeChallenge, storedCode.codeChallengeMethod)
        //     5. Mark the code consumed, issue access/ID/refresh tokens via tokenService
        //   "refresh_token" ->
        //     1. Look up the stored refresh token, reject if missing/expired/revoked
        //     2. Issue a new access token (and consider rotating the refresh token itself —
        //        rotation on use is current best practice per RFC 9700, since it lets you
        //        detect token theft if an old refresh token is replayed after rotation)
        throw NotImplementedError("Implement the token exchange — see TODOs above")
    }
}