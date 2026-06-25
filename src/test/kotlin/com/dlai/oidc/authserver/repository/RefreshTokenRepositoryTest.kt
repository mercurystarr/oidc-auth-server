package com.dlai.oidc.authserver.repository

import com.dlai.oidc.authserver.model.RefreshToken
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.use

class RefreshTokenRepositoryTest {
    val repository = RefreshTokenRepository()

    fun refreshTokenExpiringAt(instant: Instant): RefreshToken {
        return RefreshToken.Builder()
            .token("refreshToken")
            .clientId("clientId")
            .subject("subject")
            .authTime(instant)
            .expiresAt(instant.plusSeconds(10))
            .build()
    }

    @Test
    fun `consume when refresh token is not present`() {
        assertEquals(RefreshTokenRepository.RefreshTokenResult.NotFound, repository.consume("refreshToken"))
    }

    @Test
    fun `consume when refresh token is present`() {
        repository.save(refreshTokenExpiringAt(Instant.now()))
        when (val actual = repository.consume("refreshToken")) {
            is RefreshTokenRepository.RefreshTokenResult.Valid -> assertEquals("refreshToken", actual.refreshToken.token)
            else -> fail("Unexpected result: $actual")
        }
    }

    @Test
    fun `consume when refresh token is expired`() {
        repository.save(refreshTokenExpiringAt(Instant.now().minusSeconds(20)))
        assertEquals(RefreshTokenRepository.RefreshTokenResult.NotFound, repository.consume("refreshToken"))
    }

    @Test
    fun `consume when refresh token is consumed`() {
        repository.save(refreshTokenExpiringAt(Instant.now()))
        repository.consume("refreshToken")
        when (val actual = repository.consume("refreshToken")) {
            is RefreshTokenRepository.RefreshTokenResult.Reused -> assertTrue(actual.refreshToken.consumed)
            else -> fail("Unexpected result: $actual")
        }
    }

    @Test
    fun `only one thread wins when racing to consume the same code`() {
        repository.save(refreshTokenExpiringAt(Instant.now()))
        val threadCount = 20
        val startGate = CountDownLatch(1)
        Executors.newFixedThreadPool(threadCount).use { executor ->
            val futures = List(threadCount) {
                executor.submit<RefreshTokenRepository.RefreshTokenResult?> {
                    startGate.await()      // every thread blocks here until released together
                    repository.consume("refreshToken")
                }
            }
            startGate.countDown()
            val results = futures.map { it.get() }
            assertEquals(1, results.count { it is RefreshTokenRepository.RefreshTokenResult.Valid })
            assertEquals(threadCount - 1, results.count { it is RefreshTokenRepository.RefreshTokenResult.Reused })
        }
    }
}