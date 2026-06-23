package com.dlai.oidc.authserver.security

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.Base64

class PkceValidatorTest {

    private fun challengeFor(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    @Test
    fun `valid verifier against its own S256 challenge succeeds`() {
        val verifier = "a-sufficiently-random-code-verifier-1234567890"
        val challenge = challengeFor(verifier)

        Assertions.assertTrue(PkceValidator.verify(verifier, challenge, "S256"))
    }

    @Test
    fun `mismatched verifier fails`() {
        val challenge = challengeFor("the-real-verifier")
        Assertions.assertFalse(PkceValidator.verify("a-different-verifier", challenge, "S256"))
    }

    @Test
    fun `plain method is rejected even with a matching value`() {
        // Even if verifier == challenge (what "plain" would consider valid), this server
        // must reject it outright since only S256 is supported. See PkceValidator KDoc.
        val value = "same-value-both-sides"
        Assertions.assertFalse(PkceValidator.verify(value, value, "plain"))
    }

    @Test
    fun `unknown method is rejected`() {
        val challenge = challengeFor("some-verifier")
        Assertions.assertFalse(PkceValidator.verify("some-verifier", challenge, "S512"))
    }

    @Test
    fun `empty verifier fails`() {
        val challenge = challengeFor("some-verifier")
        Assertions.assertFalse(PkceValidator.verify("", challenge, "S256"))
    }

    @Test
    fun `verifier less than minimum length fails`() {
        val verifier = "a".repeat(42)
        val challenge = challengeFor("some-verifier")
        Assertions.assertFalse(PkceValidator.verify(verifier, challenge, "S256"))
    }

    @Test
    fun `verifier at exactly minimum length succeeds`() {
        val verifier = "a".repeat(43)
        val challenge = challengeFor(verifier)
        Assertions.assertTrue(PkceValidator.verify(verifier, challenge, "S256"))
    }

    @Test
    fun `verifier at exactly maximum length succeeds`() {
        val verifier = "a".repeat(128)
        val challenge = challengeFor(verifier)
        Assertions.assertTrue(PkceValidator.verify(verifier, challenge, "S256"))
    }

    @Test
    fun `verifier greater than maximum length fails`() {
        val challenge = challengeFor("some-verifier")
        Assertions.assertFalse(PkceValidator.verify("a".repeat(129), challenge, "S256"))
    }

    @Test
    fun `verifier using standard base64 characters instead of base64url fails`() {
        val verifier = "a".repeat(42) + "+"
        val challenge = challengeFor("some-verifier")
        Assertions.assertFalse(PkceValidator.verify(verifier, challenge, "S256"))
    }

    // TODO: once /authorize and /token are implemented, add an integration tests
}