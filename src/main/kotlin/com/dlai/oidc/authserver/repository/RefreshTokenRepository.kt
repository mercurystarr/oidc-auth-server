package com.dlai.oidc.authserver.repository

import com.dlai.oidc.authserver.model.RefreshToken
import org.springframework.stereotype.Repository
import java.util.concurrent.ConcurrentHashMap

/**
 * Threadsafe, in-memory refresh token store.
 */
@Repository
class RefreshTokenRepository {

    sealed class RefreshTokenResult {
        data class Valid(val refreshToken: RefreshToken) : RefreshTokenResult()
        object NotFound : RefreshTokenResult()
        data class Reused(val refreshToken: RefreshToken) : RefreshTokenResult()
    }

    private val refreshTokens = ConcurrentHashMap<String, RefreshToken>()

    fun save(refreshToken: RefreshToken) = refreshTokens.put(refreshToken.token, refreshToken)

    fun consume(token: String): RefreshTokenResult {
        var wasReused = false
        val result = refreshTokens.computeIfPresent(token) { _, stored ->
            if (stored.consumed) {
                wasReused = true
                stored
            } else if (stored.isExpired()) {
                null
            } else {
                stored.copy(consumed = true)
            }
        }
        return when {
            result == null -> RefreshTokenResult.NotFound
            wasReused -> RefreshTokenResult.Reused(result)
            else -> RefreshTokenResult.Valid(result)
        }
    }

}