package com.dlai.oidc.authserver

import java.security.MessageDigest
import java.util.Base64

/**
 * Validates a PKCE code_verifier against the code_challenge stored at authorization time
 * (RFC 7636). Only S256 is supported, not "plain".
 *
 *  RFC 9700 (OAuth 2.0 Security Best Current Practice, January 2025) now recommends PKCE for *all* clients,
 *  confidential or not, because it also defends against authorization code injection attacks regardless of client type.
 */
object PkceValidator {

    private val unreservedRegex = Regex("^[A-Za-z0-9\\-_.~]+$")

    fun verify(codeVerifier: String, storedChallenge: String, method: String): Boolean {
        // Reject "plain" and anything else.
        if (method != "S256") {
            return false
        }

        // code_verifier constraints (RFC 7636 §4.1): 43–128 characters
        if (codeVerifier.length !in 43..128) {
            return false
        }
        // code_verifier constraints (RFC 7636 §4.1): unreserved URL character set only [A-Z] [a-z] [0-9] -. _ ~.
        if(!unreservedRegex.matches(codeVerifier)) {
            return false
        }

        val computedChallenge = sha256Base64Url(codeVerifier)
        return MessageDigest.isEqual(
            computedChallenge.toByteArray(Charsets.UTF_8),
            storedChallenge.toByteArray(Charsets.UTF_8)
        )
    }

    private fun sha256Base64Url(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
