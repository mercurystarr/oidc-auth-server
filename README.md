# oidc-auth-server

A minimal OAuth 2.0 / OpenID Connect authorization server implemented from the protocol level, not configured on top of an off-the-shelf IdP. Built to demonstrate understanding of the core specs: Authorization Code flow with PKCE, RS256-signed JWTs, OIDC discovery, and refresh token rotation.

**Stack:** Kotlin · Spring Boot 4.1.0 · Nimbus JOSE+JWT · Spring Security · Micrometer

---

## What it implements

| Spec | Feature |
|---|---|
| RFC 6749 §4.1 | Authorization Code grant |
| RFC 6749 §6 | Refresh token grant with rotation |
| RFC 6749 §5.2 | Structured error responses (`{"error": "...", "error_description": "..."}`) |
| RFC 7636 | PKCE — S256 only, mandatory for all clients |
| RFC 7517 | JWKS endpoint |
| RFC 9700 | Refresh token reuse detection (theft signal) |
| OIDC Core 1.0 | ID token issuance, `auth_time`, `nonce` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` |

## What it does not implement

- Client authentication (confidential clients, client secrets) — the demo client is public with mandatory PKCE
- User management — one hardcoded test user (`test-user` / `password`)
- Persistent storage — all state is in-memory; a restart invalidates all outstanding tokens
- Token introspection or revocation endpoints
- Refresh token scope downscoping

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/authorize` | Authorization endpoint — requires login, issues a PKCE-bound code |
| `POST` | `/token` | Token endpoint — redeems a code or rotates a refresh token |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | Public RSA key set |
| `GET` | `/actuator/metrics` | Micrometer metrics |

---

## Running

```bash
./gradlew bootRun
```

The server starts on port `9000`. The issuer is `http://localhost:9000`.

---

## Full flow example

### 1. Compute a PKCE challenge

```bash
CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
```

### 2. Authorize

Open in a browser (you will be prompted to log in as `test-user` / `password`):

```
http://localhost:9000/authorize
  ?response_type=code
  &client_id=demo-client
  &redirect_uri=http://localhost:9700/callback
  &scope=openid%20profile
  &state=abc123
  &code_challenge=<CODE_CHALLENGE>
  &code_challenge_method=S256
```

The server redirects to `http://localhost:9700/callback?code=<CODE>&state=abc123`.

### 3. Exchange the code for tokens

```bash
curl -X POST http://localhost:9000/token \
  -d "grant_type=authorization_code" \
  -d "code=<CODE>" \
  -d "redirect_uri=http://localhost:9700/callback" \
  -d "client_id=demo-client" \
  -d "code_verifier=$CODE_VERIFIER"
```

Response:

```json
{
  "access_token": "eyJ...",
  "id_token": "eyJ...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid profile"
}
```

### 4. Refresh

```bash
curl -X POST http://localhost:9000/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<REFRESH_TOKEN>" \
  -d "client_id=demo-client"
```

The server rotates the refresh token on every use — the old token is immediately invalidated and a new one is returned. Presenting a consumed token returns `invalid_grant` and is logged as a potential theft signal.

---

## Configuration

| Property | Default | Description |
|---|---|---|
| `auth.issuer` | `http://localhost:9000` | Issuer identifier included in all JWTs |
| `auth.expiryTime` | `300` | Access and ID token lifetime in seconds |
| `auth.codeExpiryTime` | `300` | Authorization code lifetime in seconds |
| `auth.refreshExpiryTime` | `1209600` | Refresh token lifetime in seconds (14 days) |

---

## Design notes

**Why RS256 over HS256?** RS256 uses an asymmetric keypair. The private key signs tokens; the public key (served at `/jwks.json`) lets resource servers verify them without sharing a secret. HS256 would require the same secret on both the authorization server and every resource server.

**Why is `aud` different between access and ID tokens?** Per OIDC Core, an ID token's `aud` must be the `client_id` — it is a credential for the client. An access token's `aud` is the resource server it is intended for. Mixing them up is a common source of token confusion attacks.

**PKCE single-use codes via `computeIfPresent`:** Authorization codes are consumed atomically using `ConcurrentHashMap.computeIfPresent`. This guarantees exactly-once redemption under concurrent requests without explicit locking.

**Refresh token reuse detection (RFC 9700 §2.2.2):** When a consumed refresh token is presented again, the server returns `invalid_grant` and emits a `token_reuse` metric. In a production system this should trigger family revocation (invalidating all tokens issued from the same authorization grant).

---

## Running the tests

```bash
./gradlew test
```

The test suite includes unit tests for all controller error branches and two end-to-end integration tests via MockMvc that exercise the full HTTP stack.

---

## Metrics

Exposed via `/actuator/metrics`. Key metrics:

| Metric | Tags | Description |
|---|---|---|
| `oidc.token.issued` | `grant_type` | Successful token issuances |
| `oidc.token.errors` | `error` | Failures by error type (`pkce_failure`, `token_reuse`, `unsupported_grant_type`) |
| `token.duration` | `grant_type` | Token endpoint latency |
