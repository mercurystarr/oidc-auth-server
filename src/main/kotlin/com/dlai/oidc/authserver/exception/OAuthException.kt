package com.dlai.oidc.authserver.exception

class OAuthException(val error: String, val errorDescription: String)
    : RuntimeException(errorDescription)
