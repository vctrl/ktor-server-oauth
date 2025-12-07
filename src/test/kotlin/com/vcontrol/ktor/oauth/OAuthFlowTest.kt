package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.model.AuthorizationServerMetadata
import com.vcontrol.ktor.oauth.model.ClientRegistrationRequest
import com.vcontrol.ktor.oauth.model.ClientRegistrationResponse
import com.vcontrol.ktor.oauth.model.ProtectedResourceMetadata
import com.vcontrol.ktor.oauth.model.TokenResponse
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNamingStrategy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class OAuthFlowTest {

    private val json = Json {
        ignoreUnknownKeys = true
        namingStrategy = JsonNamingStrategy.SnakeCase
    }

    /** OAuth endpoints from config (respects routePrefix) */
    private val endpoints = OAuthEndpoints()

    /**
     * Test the full OAuth 2.0 discovery and client registration flow:
     * 1. GET /whoami - Hit protected resource, get 401 with WWW-Authenticate header
     * 2. GET /.well-known/oauth-protected-resource - Discover authorization server
     * 3. GET /.well-known/oauth-authorization-server - Get OAuth endpoints
     * 4. POST /register - Dynamic client registration
     * 5. GET /authorize - Authorization with PKCE (redirects to /provision)
     * 6. POST /provision - Provision form submission (sets session)
     * 7. GET /authorize - Resume after provision, get auth code
     * 8. POST /token - Exchange code for access token
     * 9. GET /whoami - Verify token works and session username is returned
     */
    @Test
    fun `full OAuth flow with provision and session`() = testApplication {
        application {
            testModule()
        }

        val httpClient = createClient {
            install(HttpCookies)
            install(ContentNegotiation) {
                json(json)
            }
            followRedirects = false
        }

        // 1. Hit protected resource without auth - should get 401
        val unauthorizedResponse = httpClient.get("/whoami")
        assertEquals(HttpStatusCode.Unauthorized, unauthorizedResponse.status)
        val wwwAuth = unauthorizedResponse.headers[HttpHeaders.WWWAuthenticate]
        assertNotNull(wwwAuth, "Expected WWW-Authenticate header on 401")
        assertTrue(wwwAuth.contains("Bearer"), "Expected Bearer auth scheme")

        // 2. Discover authorization server via protected resource metadata
        val resourceMetadataResponse = httpClient.get(endpoints.protectedResourceMetadata)
        assertEquals(HttpStatusCode.OK, resourceMetadataResponse.status)
        val resourceMetadata = resourceMetadataResponse.body<ProtectedResourceMetadata>()
        assertNotNull(resourceMetadata.authorizationServers.firstOrNull(), "Expected authorization server in metadata")

        // 3. Get authorization server metadata to discover endpoints
        val authServerMetadataResponse = httpClient.get(endpoints.authServerMetadata)
        assertEquals(HttpStatusCode.OK, authServerMetadataResponse.status)
        val authServerMetadata = authServerMetadataResponse.body<AuthorizationServerMetadata>()
        assertNotNull(authServerMetadata.registrationEndpoint, "Expected registration endpoint")
        assertNotNull(authServerMetadata.authorizationEndpoint, "Expected authorization endpoint")
        assertNotNull(authServerMetadata.tokenEndpoint, "Expected token endpoint")

        // 4. Register client
        val registerResponse = httpClient.post(endpoints.register) {
            contentType(ContentType.Application.Json)
            setBody(ClientRegistrationRequest(
                clientName = "test-client",
                redirectUris = listOf("http://localhost/callback")
            ))
        }
        assertEquals(HttpStatusCode.Created, registerResponse.status)
        val clientInfo = registerResponse.body<ClientRegistrationResponse>()
        val clientId = clientInfo.clientId
        assertNotNull(clientId)

        // 5. Generate PKCE
        val codeVerifier = generateCodeVerifier()
        val codeChallenge = generateCodeChallenge(codeVerifier)

        // 6. Start authorization (should redirect to provision)
        val authResponse = httpClient.get(endpoints.authorize) {
            parameter("response_type", "code")
            parameter("client_id", clientId)
            parameter("redirect_uri", "http://localhost/callback")
            parameter("code_challenge", codeChallenge)
            parameter("code_challenge_method", "S256")
        }
        assertEquals(HttpStatusCode.Found, authResponse.status)
        val provisionRedirect = authResponse.headers[HttpHeaders.Location]
        assertNotNull(provisionRedirect)
        assertEquals(endpoints.provision, provisionRedirect)

        // 7. GET provision page (shows provision form)
        val provisionGetResponse = httpClient.get(endpoints.provision)
        assertEquals(HttpStatusCode.OK, provisionGetResponse.status)

        // 8. POST provision form with username/password
        val provisionPostResponse = httpClient.submitForm(
            url = endpoints.provision,
            formParameters = parameters {
                append("username", "testuser")
                append("password", "letmein")
            }
        )
        // Should redirect back to authorize
        assertEquals(HttpStatusCode.Found, provisionPostResponse.status)
        val authorizeRedirect = provisionPostResponse.headers[HttpHeaders.Location]
        assertNotNull(authorizeRedirect)
        assertEquals(endpoints.authorize, authorizeRedirect)

        // 9. Resume authorization - should redirect with code
        val codeResponse = httpClient.get(endpoints.authorize)
        assertEquals(HttpStatusCode.Found, codeResponse.status, "Expected redirect after authorize resume")
        val callbackRedirect = codeResponse.headers[HttpHeaders.Location]
        assertNotNull(callbackRedirect, "Expected Location header after authorize resume")

        // If redirected back to provision, the auth_request cookie wasn't preserved
        if (callbackRedirect == endpoints.provision) {
            error("Redirected back to provision - auth_request cookie not preserved")
        }

        val code = extractCodeFromRedirectUrl(callbackRedirect)
        assertNotNull(code, "Expected authorization code in redirect URL: $callbackRedirect")

        // 10. Exchange code for token
        val tokenResponse = httpClient.submitForm(
            url = endpoints.token,
            formParameters = parameters {
                append("grant_type", "authorization_code")
                append("code", code)
                append("client_id", clientId)
                append("redirect_uri", "http://localhost/callback")
                append("code_verifier", codeVerifier)
            }
        )
        assertEquals(HttpStatusCode.OK, tokenResponse.status)
        val tokenInfo = tokenResponse.body<TokenResponse>()
        val accessToken = tokenInfo.accessToken
        assertNotNull(accessToken)

        // 11. Verify token works and session was stored
        val whoamiResponse = httpClient.get("/whoami") {
            bearerAuth(accessToken)
        }
        assertEquals(HttpStatusCode.OK, whoamiResponse.status)
        assertEquals("testuser (secret: letmein)", whoamiResponse.bodyAsText())
    }

    /**
     * Test named provider registration with custom claims:
     * 1. Register client with resource=test
     * 2. Authorize (redirects to provision for "test" resource at /provision/test)
     * 3. Provision handler auto-completes with test_claim
     * 4. Get token with embedded claim
     * 5. Verify /test/whoami returns the claim from JWT
     */
    @Test
    fun `named provider registration with custom claims`() = testApplication {
        application {
            testModule()
        }

        val httpClient = createClient {
            install(HttpCookies)
            install(ContentNegotiation) {
                json(json)
            }
            followRedirects = false
        }

        // 1. Register client with resource=test
        val registerResponse = httpClient.post("${endpoints.register}?resource=test") {
            contentType(ContentType.Application.Json)
            setBody(ClientRegistrationRequest(
                clientName = "test-client",
                redirectUris = listOf("http://localhost/callback")
            ))
        }
        assertEquals(HttpStatusCode.Created, registerResponse.status)
        val clientInfo = registerResponse.body<ClientRegistrationResponse>()
        val clientId = clientInfo.clientId
        assertNotNull(clientId)

        // 2. Generate PKCE
        val codeVerifier = generateCodeVerifier()
        val codeChallenge = generateCodeChallenge(codeVerifier)

        // 3. Start authorization with resource=test
        val authResponse = httpClient.get(endpoints.authorize) {
            parameter("response_type", "code")
            parameter("client_id", clientId)
            parameter("redirect_uri", "http://localhost/callback")
            parameter("code_challenge", codeChallenge)
            parameter("code_challenge_method", "S256")
            parameter("resource", "test")
        }
        assertEquals(HttpStatusCode.Found, authResponse.status)
        val provisionRedirect = authResponse.headers[HttpHeaders.Location]
        assertNotNull(provisionRedirect)
        assertTrue(provisionRedirect.contains("provision"), "Expected redirect to provision path")

        // 4. GET provision page (for "test" provider, uses handle{} which redirects immediately)
        val provisionGetResponse = httpClient.get(provisionRedirect)
        assertEquals(HttpStatusCode.Found, provisionGetResponse.status, "Expected redirect from provision handle{}")
        val authorizeRedirect = provisionGetResponse.headers[HttpHeaders.Location]
        assertNotNull(authorizeRedirect)

        // 5. Resume authorization - should redirect with code
        val codeResponse = httpClient.get(endpoints.authorize)
        assertEquals(HttpStatusCode.Found, codeResponse.status, "Expected redirect after authorize resume")
        val callbackRedirect = codeResponse.headers[HttpHeaders.Location]
        assertNotNull(callbackRedirect, "Expected Location header after authorize resume")

        val code = extractCodeFromRedirectUrl(callbackRedirect)
        assertNotNull(code, "Expected authorization code in redirect URL: $callbackRedirect")

        // 6. Exchange code for token
        val tokenResponse = httpClient.submitForm(
            url = endpoints.token,
            formParameters = parameters {
                append("grant_type", "authorization_code")
                append("code", code)
                append("client_id", clientId)
                append("redirect_uri", "http://localhost/callback")
                append("code_verifier", codeVerifier)
            }
        )
        assertEquals(HttpStatusCode.OK, tokenResponse.status)
        val tokenInfo = tokenResponse.body<TokenResponse>()
        val accessToken = tokenInfo.accessToken
        assertNotNull(accessToken)

        // 7. Verify token works and test_claim is embedded
        val whoamiResponse = httpClient.get("/test/whoami") {
            bearerAuth(accessToken)
        }
        assertEquals(HttpStatusCode.OK, whoamiResponse.status)
        assertEquals("got claims: working", whoamiResponse.bodyAsText())
    }

    /**
     * Test encrypted claims flow:
     * 1. Register client with resource=enc-claim-test
     * 2. Authorize and provision (sets encrypted claim)
     * 3. Get token with embedded encrypted claim
     * 4. Verify /enc-test/whoami can decrypt and return the claim value
     */
    @Test
    fun `encrypted claims are stored and decrypted correctly`() = testApplication {
        application {
            testModule()
        }

        val httpClient = createClient {
            install(HttpCookies)
            install(ContentNegotiation) {
                json(json)
            }
            followRedirects = false
        }

        // 1. Register client with resource=enc-claim-test
        val registerResponse = httpClient.post("${endpoints.register}?resource=enc-claim-test") {
            contentType(ContentType.Application.Json)
            setBody(ClientRegistrationRequest(
                clientName = "enc-test-client",
                redirectUris = listOf("http://localhost/callback")
            ))
        }
        assertEquals(HttpStatusCode.Created, registerResponse.status)
        val clientInfo = registerResponse.body<ClientRegistrationResponse>()
        val clientId = clientInfo.clientId
        assertNotNull(clientId)

        // 2. Generate PKCE
        val codeVerifier = generateCodeVerifier()
        val codeChallenge = generateCodeChallenge(codeVerifier)

        // 3. Start authorization with resource=enc-claim-test
        val authResponse = httpClient.get(endpoints.authorize) {
            parameter("response_type", "code")
            parameter("client_id", clientId)
            parameter("redirect_uri", "http://localhost/callback")
            parameter("code_challenge", codeChallenge)
            parameter("code_challenge_method", "S256")
            parameter("resource", "enc-claim-test")
        }
        assertEquals(HttpStatusCode.Found, authResponse.status)
        val provisionRedirect = authResponse.headers[HttpHeaders.Location]
        assertNotNull(provisionRedirect)
        assertTrue(provisionRedirect.contains("provision"), "Expected redirect to provision path")

        // 4. GET provision page (for "enc-claim-test" provider, uses handle{} which redirects immediately)
        val provisionGetResponse = httpClient.get(provisionRedirect)
        assertEquals(HttpStatusCode.Found, provisionGetResponse.status, "Expected redirect from provision handle{}")

        // 5. Resume authorization - should redirect with code
        val codeResponse = httpClient.get(endpoints.authorize)
        assertEquals(HttpStatusCode.Found, codeResponse.status, "Expected redirect after authorize resume")
        val callbackRedirect = codeResponse.headers[HttpHeaders.Location]
        assertNotNull(callbackRedirect, "Expected Location header after authorize resume")

        val code = extractCodeFromRedirectUrl(callbackRedirect)
        assertNotNull(code, "Expected authorization code in redirect URL: $callbackRedirect")

        // 6. Exchange code for token
        val tokenResponse = httpClient.submitForm(
            url = endpoints.token,
            formParameters = parameters {
                append("grant_type", "authorization_code")
                append("code", code)
                append("client_id", clientId)
                append("redirect_uri", "http://localhost/callback")
                append("code_verifier", codeVerifier)
            }
        )
        assertEquals(HttpStatusCode.OK, tokenResponse.status)
        val tokenInfo = tokenResponse.body<TokenResponse>()
        val accessToken = tokenInfo.accessToken
        assertNotNull(accessToken)

        // 7. Verify encrypted claim is decrypted correctly
        val whoamiResponse = httpClient.get("/enc-test/whoami") {
            bearerAuth(accessToken)
        }
        assertEquals(HttpStatusCode.OK, whoamiResponse.status)
        assertEquals("got claims: my-secret-value", whoamiResponse.bodyAsText())
    }

    @Test
    fun `provision form shows error for invalid password`() = testApplication {
        application {
            testModule()
        }

        val httpClient = createClient {
            install(HttpCookies)
            install(ContentNegotiation) {
                json(json)
            }
            followRedirects = false
        }

        // Register client and start OAuth flow
        val registerResponse = httpClient.post(endpoints.register) {
            contentType(ContentType.Application.Json)
            setBody(ClientRegistrationRequest(
                clientName = "test-client",
                redirectUris = listOf("http://localhost/callback")
            ))
        }
        val clientId = registerResponse.body<ClientRegistrationResponse>().clientId
        val codeVerifier = generateCodeVerifier()
        val codeChallenge = generateCodeChallenge(codeVerifier)

        httpClient.get(endpoints.authorize) {
            parameter("response_type", "code")
            parameter("client_id", clientId)
            parameter("redirect_uri", "http://localhost/callback")
            parameter("code_challenge", codeChallenge)
            parameter("code_challenge_method", "S256")
        }

        httpClient.get(endpoints.provision)

        // Submit with wrong password
        val provisionResponse = httpClient.submitForm(
            url = endpoints.provision,
            formParameters = parameters {
                append("username", "testuser")
                append("password", "wrongpassword")
            }
        )
        // Should show error, not redirect
        assertEquals(HttpStatusCode.OK, provisionResponse.status)
        val body = provisionResponse.bodyAsText()
        assertTrue(body.contains("Invalid password"), "Expected error message in response")
    }
}
