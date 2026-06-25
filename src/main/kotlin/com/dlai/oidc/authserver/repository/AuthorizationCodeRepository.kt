package com.dlai.oidc.authserver.repository

import com.dlai.oidc.authserver.model.AuthorizationCode
import org.springframework.stereotype.Repository
import java.util.concurrent.ConcurrentHashMap

/**
 * Threadsafe, in-memory authorization code store.
 */
@Repository
class AuthorizationCodeRepository {
    private val authCodes = ConcurrentHashMap<String, AuthorizationCode>()

    fun consume(code: String): AuthorizationCode? {
        return authCodes.computeIfPresent(code) { _, authCode ->
           if (authCode.consumed || authCode.isExpired())
               null
           else
               authCode.copy(consumed = true)
        }
    }

    fun save(code: AuthorizationCode) {
        authCodes[code.code] = code
    }
}