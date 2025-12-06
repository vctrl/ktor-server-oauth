package com.vcontrol.ktor.oauth

import com.vcontrol.ktor.oauth.route.provision
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.serialization.Serializable

/**
 * Test application module for OAuth plugin tests.
 * Simplified version without MCP dependencies.
 */
@Suppress("unused")
fun Application.testModule() {
    install(OAuth) {
        authorizationServer(LocalAuthServer) {
            openRegistration = true
        }
    }

    install(OAuthSessions) {
        session<TestSession>()
    }

    install(Authentication) {
        oauthJwt()
        oauthJwt("test")
    }

    // Standard Ktor routing with provision and authenticate
    routing {
        // Provision routes (OAuth setup phase)
        provision {
            get {
                call.respondProvisionForm()
            }
            post {
                val parameters = call.receiveParameters()
                val username = parameters["username"]
                val password = parameters["password"]

                when {
                    username.isNullOrBlank() -> {
                        call.respondProvisionForm("Username is required")
                    }
                    password.isNullOrBlank() -> {
                        call.respondProvisionForm("Password is required")
                    }
                    password != "letmein" -> {
                        call.respondProvisionForm("Invalid password")
                    }
                    else -> {
                        sessions.set(TestSession(username, password))
                        complete(claims = mapOf("username" to username))
                    }
                }
            }
        }

        provision("test") {
            handle {
                complete(claims = mapOf("test_claim" to "working"))
            }
        }

        // Protected routes
        authenticate {
            get("/whoami") {
                val session = call.sessions.get<TestSession>()
                val username = session?.username ?: "anonymous"
                val password = session?.password ?: "none"
                call.respondText("$username (secret: $password)")
            }
        }

        authenticate("test") {
            get("/test/whoami") {
                val testClaim = call.principal<JWTPrincipal>()?.let {
                    it.payload.getClaim("test_claim").asString()
                }
                call.respondText("got claims: $testClaim")
            }
        }
    }
}

@Serializable
data class TestSession(val username: String, val password: String)

private suspend fun ApplicationCall.respondProvisionForm(errorMessage: String? = null) {
    val errorHtml = errorMessage?.let { """<div class="error">$it</div>""" } ?: ""
    respondText(
        """
        <!DOCTYPE html>
        <html>
        <head><title>Provision</title></head>
        <body>
            $errorHtml
            <form method="post">
                <input name="username" placeholder="Username">
                <input name="password" type="password" placeholder="Password">
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
        """.trimIndent(),
        ContentType.Text.Html
    )
}
