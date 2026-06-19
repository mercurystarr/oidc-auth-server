# oidc-auth-server — build plan

Portfolio project: an OAuth 2.0 / OIDC authorization server implemented from the protocol
level (Authorization Code + PKCE, RS256 JWTs, OIDC discovery), built against the scaffold
in `../oidc-auth-server-template`. Goal is genuine incremental commits that demonstrate the
author's own understanding of the protocol, not a copy of the template.

**Collaboration mode: pure tutor.** Claude does not write or edit implementation files.
Claude explains concepts, points to relevant RFC sections, and reviews code after it's
written. All code, including boilerplate, is written by the author. Plan/progress docs
like this one are the exception — Claude maintains this file.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

## Steps

- [x] **0. Repo hygiene** — stop tracking build artifacts.
  Done in commit `3103c2b` ("Stop tracking build artifacts"), pushed to `origin/main`.
  Note: the `Main.kt` package rename got bundled into this commit too — not a problem since
  it's already pushed, but a reminder to keep hygiene/restructuring commits separate going
  forward.

- [ ] **1. Project setup** — convert the bare Kotlin console app to Spring Boot + Kotlin.
  Plugins: `org.springframework.boot`, `io.spring.dependency-management`, `kotlin("plugin.spring")`.
  Dependencies: `spring-boot-starter-web`, `spring-boot-starter-security`,
  `spring-boot-starter-data-jpa` + `h2` (runtime-only), `spring-boot-starter-validation`,
  `kotlin-reflect`, `com.nimbusds:nimbus-jose-jwt`. Drop the `application {}` block (Boot's
  plugin provides `bootRun`/`bootJar`). Add `application.properties` (port, `auth.issuer`)
  and a `@SpringBootApplication` main. Verify with `./gradlew bootRun`.

- [ ] **2. Domain models** — `RegisteredClient`, `AuthorizationCode` data classes, and a
  static in-memory `ClientRepository`.

- [ ] **3. PKCE validator** — S256 `code_verifier`/`code_challenge` check (RFC 7636), with
  unit tests. Self-contained, no Spring wiring needed — first real logic to write solo.

- [ ] **4. Signing key manager + token service** — RSA keypair generation, JWKS export,
  signed access/ID token issuance (know *why* they differ), opaque refresh tokens.

- [ ] **5. Discovery endpoints** — `/.well-known/openid-configuration` and
  `/.well-known/jwks.json`, wiring up step 4.

- [ ] **6. `/authorize` endpoint** — validate request, authenticate a hardcoded test user,
  issue + store an authorization code bound to the PKCE challenge. Requires writing a small
  `AuthorizationCodeRepository` (intentionally not in the template).

- [ ] **7. `/token` endpoint — `authorization_code` grant** — redeem the code: verify PKCE,
  enforce single-use, issue tokens.

- [ ] **8. `/token` endpoint — `refresh_token` grant** — with rotation on use.

- [ ] **9. Integration test** — full round trip: request a code, redeem it, assert a valid
  signed JWT comes back.

## Notes / decisions

- Package name: `com.dlai.oidc.authserver` (author's own, doesn't need to match the
  template's `com.dianaoidc.authserver`).
- `build/` and `.gradle/` are currently tracked in git — needs the step 0 fix before
  continuing.
- Spring Boot version: **4.1.0** (latest stable, ahead of the template's 3.3.4). Chosen
  over the more-documented 3.x line since the value of this project is protocol-level
  understanding, not Spring config — worth eating a bit of doc-lag friction to build on
  current APIs. Paired with `io.spring.dependency-management` **1.1.7** and
  `com.nimbusds:nimbus-jose-jwt` **10.9.1**.
