package com.dlai.oidc.authserver.repository

import com.dlai.oidc.authserver.model.AuthorizationCode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertNotNull
import org.junit.jupiter.api.assertNull
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

class AuthorizationCodeRepositoryTest {

    val repository = AuthorizationCodeRepository()

    fun authCodeExpiringAt(instant: Instant): AuthorizationCode {
        return AuthorizationCode.Builder()
            .code("code")
            .clientId("clientId")
            .redirectUri("redirectUri")
            .subject("subject")
            .codeChallenge("codeChallenge")
            .codeChallengeMethod("codeChallengeMethod")
            .authTime(instant)
            .expiresAt(instant.plusSeconds(10))
            .build()
    }

    @Test
    fun `consume when code is present`() {
        repository.save(authCodeExpiringAt(Instant.now()))
        assertNotNull(repository.consume("code"))
        assertNull(repository.consume("code"))
    }

    @Test
    fun `consume when code is not present`() {
        assertNull(repository.consume("code"))
    }

    @Test
    fun `consume when code is expired`() {
        repository.save(authCodeExpiringAt(Instant.now().minusSeconds(20)))
        assertNull(repository.consume("code"))
    }

    @Test
    fun `only one thread wins when racing to consume the same code`() {
        repository.save(authCodeExpiringAt(Instant.now()))
        val threadCount = 20
        val startGate = CountDownLatch(1)
        Executors.newFixedThreadPool(threadCount).use { executor ->
            val futures = List(threadCount) {
                executor.submit<AuthorizationCode?> {
                    startGate.await()      // every thread blocks here until released together
                    repository.consume("code")
                }
            }
            startGate.countDown()
            val results = futures.map { it.get() }
            assertEquals(1, results.count { it != null })
        }
    }

}