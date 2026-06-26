package com.dlai.oidc.authserver.controller

import com.dlai.oidc.authserver.exception.OAuthException
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler

@ControllerAdvice
class OAuthExceptionHandler {
    @ExceptionHandler(OAuthException::class)
    fun handle(ex: OAuthException): ResponseEntity<Map<String, String>> {
        val body = mapOf("error" to ex.error, "error_description" to ex.errorDescription)
        return ResponseEntity.badRequest()
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .body(body)
    }
}