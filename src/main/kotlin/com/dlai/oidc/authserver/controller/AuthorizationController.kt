package com.dlai.oidc.authserver.controller

import com.dlai.oidc.authserver.exception.OAuthException
import com.dlai.oidc.authserver.model.AuthorizationCode
import com.dlai.oidc.authserver.repository.AuthorizationCodeRepository
import com.dlai.oidc.authserver.repository.ClientRepository
import com.dlai.oidc.authserver.repository.RefreshTokenRepository
import com.dlai.oidc.authserver.security.PkceValidator
import com.dlai.oidc.authserver.service.TokenService
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Timer
import org.slf4j.LoggerFactory
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
    private val meterRegistry: MeterRegistry,
    @Value("\${auth.codeExpiryTime}") private val codeExpiryTime: Long,
    @Value("\${auth.expiryTime}") private val expiryTime: Long,
) {

    private val secureRandom = SecureRandom()
    private val logger = LoggerFactory.getLogger(AuthorizationController::class.java)

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
            throw OAuthException("invalid_request", "response_type must be 'code'")
        }
        val client = clientRepository.findById(clientId)
        if (client == null) {
            logger.warn("endpoint=authorize client_id={} subject={} outcome=failure error=invalid_request", clientId, authentication.name)
            throw OAuthException("invalid_request", "Invalid client_id")
        }

        if (!client.redirectUris.contains(redirectUri)) {
            logger.warn("endpoint=authorize client_id={} subject={} outcome=failure error=invalid_request", clientId, authentication.name)
            throw OAuthException("invalid_request", "Invalid redirect_uri")
        }

        if (codeChallengeMethod != "S256") {
            logger.warn("endpoint=authorize client_id={} subject={} outcome=failure error=invalid_request", clientId, authentication.name)
            throw OAuthException("invalid_request", "code_challenge_method must be 'S256'")
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

        logger.info("endpoint=authorize client_id={} subject={} scope={} outcome=success",
            clientId, authentication.name, scope)

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
        val sample = Timer.start(meterRegistry)
        try {
            if (grantType == "authorization_code") {
                if (code == null) throw OAuthException("invalid_request", "code is required")
                if (codeVerifier == null) throw OAuthException("invalid_request", "code_verifier is required")

                val authCode = authCodeRepository.consume(code) ?: throw OAuthException("invalid_grant", "Invalid code")

                if (clientId != authCode.clientId) {
                    logger.warn("endpoint=token grant_type=authorization_code client_id={} outcome=failure error=invalid_grant", clientId)
                    throw OAuthException("invalid_grant", "Invalid client_id")
                }
                if (redirectUri != authCode.redirectUri) {
                    logger.warn("endpoint=token grant_type=authorization_code client_id={} outcome=failure error=invalid_grant", clientId)
                    throw OAuthException("invalid_grant", "Invalid redirect_uri")
                }
                if (!PkceValidator.verify(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
                    logger.warn("endpoint=token grant_type=authorization_code client_id={} outcome=failure error=invalid_grant", clientId)
                    meterRegistry.counter("oidc.token.errors", "error", "pkce_failure").increment()
                    throw OAuthException("invalid_grant", "Invalid code_verifier")
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

                logger.info("endpoint=token grant_type=authorization_code client_id={} subject={} scope={} outcome=success",
                    clientId, authCode.subject, authCode.scopes.joinToString(" "))
                meterRegistry.counter("oidc.token.issued", "grant_type", "authorization_code").increment()

                return ResponseEntity.ok()
                    .header("Cache-Control", "no-store")
                    .header("Pragma", "no-cache")
                    .body(responseBody)
            } else if (grantType == "refresh_token") {
                if (refreshToken == null) throw OAuthException("invalid_request", "refresh_token is required")
                when (val token = refreshTokenRepository.consume(refreshToken)) {
                    is RefreshTokenRepository.RefreshTokenResult.Reused -> {
                        logger.warn("endpoint=token grant_type=refresh_token client_id={} outcome=failure error=invalid_grant reason=token_reuse", clientId)
                        meterRegistry.counter("oidc.token.errors", "error", "token_reuse").increment()
                        throw OAuthException("invalid_grant", "Invalid refresh_token")
                    }

                    is RefreshTokenRepository.RefreshTokenResult.Valid -> {

                        val responseBody = HashMap<String, Any>()
                        // RFC 6749 §6 ensure that the refresh token was issued to the authenticated client
                        if (clientId != token.refreshToken.clientId) {
                            logger.warn("endpoint=token grant_type=refresh_token client_id={} outcome=failure error=invalid_grant", clientId)
                            throw OAuthException("invalid_grant", "Invalid client_id")
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

                        logger.info("endpoint=token grant_type=refresh_token client_id={} subject={} scope={} outcome=success",
                            clientId, token.refreshToken.subject, token.refreshToken.scopes.joinToString(" "))
                        meterRegistry.counter("oidc.token.issued", "grant_type", "refresh_token").increment()

                        return ResponseEntity.ok()
                            .header("Cache-Control", "no-store")
                            .header("Pragma", "no-cache")
                            .body(responseBody)
                    }

                    RefreshTokenRepository.RefreshTokenResult.NotFound -> {
                        logger.warn("endpoint=token grant_type=refresh_token client_id={} outcome=failure error=invalid_grant", clientId)
                        throw OAuthException("invalid_grant", "Invalid refresh_token")
                    }
                }
            } else {
                logger.warn("endpoint=token grant_type={} outcome=failure error=unsupported_grant_type", grantType)
                meterRegistry.counter("oidc.token.errors", "error", "unsupported_grant_type").increment()
                throw OAuthException("unsupported_grant_type", "grant_type must be 'authorization_code' or 'refresh_token'")
            }
        } finally {
            sample.stop(meterRegistry.timer("token.duration", "grant_type", grantType))
        }
    }
}
