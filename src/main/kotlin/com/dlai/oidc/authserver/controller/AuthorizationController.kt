package com.dlai.oidc.authserver.controller

import com.dlai.oidc.authserver.model.AuthorizationCode
import com.dlai.oidc.authserver.repository.AuthorizationCodeRepository
import com.dlai.oidc.authserver.repository.ClientRepository
import com.dlai.oidc.authserver.repository.RefreshTokenRepository
import com.dlai.oidc.authserver.security.PkceValidator
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
    private val authCodeRepository: AuthorizationCodeRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val tokenService: TokenService,
    @Value("\${auth.codeExpiryTime}") private val codeExpiryTime: Long,
    @Value("\${auth.expiryTime}") private val expiryTime: Long,
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

        authCodeRepository.save(authorizationCode)

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
    ): ResponseEntity<Map<String, Any>> {
        if (grantType == "authorization_code") {
            if (code == null) throw IllegalArgumentException("code is required")
            if (codeVerifier == null) throw IllegalArgumentException("code_verifier is required")

            val authCode = authCodeRepository.consume(code) ?: throw IllegalArgumentException("Invalid code")

            if (clientId != authCode.clientId) {
                throw IllegalArgumentException("Invalid client_id")
            }
            if (redirectUri != authCode.redirectUri) {
                throw IllegalArgumentException("Invalid redirect_uri")
            }
            if (!PkceValidator.verify(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
                throw IllegalArgumentException("Invalid code_verifier")
            }
            val responseBody = HashMap<String, Any>()
            responseBody["access_token"] = tokenService.issueAccessToken(authCode.subject, clientId, authCode.scopes)
            if (authCode.scopes.contains("openid")) {
                responseBody["id_token"] =
                    tokenService.issueIdToken(authCode.subject, clientId, authCode.authTime, authCode.nonce)
            }
            // Refresh tokens are currently issued on every authorization_code grant
            // For a public client, OAuth 2.1 §4.3.3 says they should only be issued when offline_access was explicitly
            // in the requested scopes
            val issuedRefreshToken = tokenService.issueRefreshToken(
                authCode.subject,
                clientId,
                authCode.scopes,
                authCode.authTime,
                authCode.nonce
            )
            refreshTokenRepository.save(issuedRefreshToken)
            responseBody["refresh_token"] = issuedRefreshToken.token
            if (authCode.scopes.isNotEmpty())
                responseBody["scope"] = authCode.scopes.joinToString(" ")
            responseBody["token_type"] = "Bearer"
            responseBody["expires_in"] = expiryTime
            return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .body(responseBody)
        } else if (grantType == "refresh_token") {
            if (refreshToken == null) throw IllegalArgumentException("refresh_token is required")
            when (val token = refreshTokenRepository.consume(refreshToken)) {
                is RefreshTokenRepository.RefreshTokenResult.Reused -> {
                    throw IllegalArgumentException("Invalid refresh_token")
                }

                is RefreshTokenRepository.RefreshTokenResult.Valid -> {

                    val responseBody = HashMap<String, Any>()
                    // RFC 6749 §6 ensure that the refresh token was issued to the authenticated client
                    if (clientId != token.refreshToken.clientId) {
                        throw IllegalArgumentException("Invalid client_id")
                    }
                    responseBody["access_token"] =
                        tokenService.issueAccessToken(token.refreshToken.subject, clientId, token.refreshToken.scopes)
                    if (token.refreshToken.scopes.contains("openid")) {
                        responseBody["id_token"] = tokenService.issueIdToken(
                            token.refreshToken.subject,
                            clientId,
                            token.refreshToken.authTime,
                            token.refreshToken.nonce
                        )
                    }
                    val newRefreshToken = tokenService.issueRefreshToken(
                        token.refreshToken.subject,
                        clientId,
                        token.refreshToken.scopes,
                        token.refreshToken.authTime,
                        token.refreshToken.nonce
                    )
                    refreshTokenRepository.save(newRefreshToken)
                    responseBody["refresh_token"] = newRefreshToken.token
                    if (token.refreshToken.scopes.isNotEmpty())
                        responseBody["scope"] = token.refreshToken.scopes.joinToString(" ")
                    responseBody["token_type"] = "Bearer"
                    responseBody["expires_in"] = expiryTime
                    return ResponseEntity.ok()
                        .header("Cache-Control", "no-store")
                        .header("Pragma", "no-cache")
                        .body(responseBody)
                }

                RefreshTokenRepository.RefreshTokenResult.NotFound -> {
                    throw IllegalArgumentException("Invalid refresh_token")
                }
            }
        } else {
            throw IllegalArgumentException("grant_type must be 'authorization_code' or 'refresh_token'")
        }
    }
}
