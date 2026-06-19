package com.dlai.oidc.authserver

import org.springframework.stereotype.Repository
import java.util.concurrent.ConcurrentHashMap

/**
 * Static, in-memory client store.
 */
@Repository
class ClientRepository {
    private val clients = ConcurrentHashMap<String, RegisteredClient>()

    init {
        register(
            RegisteredClient(
                clientId = "demo-client",
                clientSecret = null,
                redirectUris = setOf("http://localhost:9700/callback"),
                scopes = setOf("openid", "profile"),
                requirePkce = true
            )
        )
    }

    fun register(client: RegisteredClient) {
        clients[client.clientId] = client
    }

    fun findById(id: String): RegisteredClient? = clients[id]
}