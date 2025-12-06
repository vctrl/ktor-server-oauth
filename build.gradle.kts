plugins {
    id("buildsrc.convention.kotlin-jvm")
    `java-library`
    alias(libs.plugins.kotlinPluginSerialization)
    id("com.vanniktech.maven.publish") version "0.30.0"
}

group = "com.vcontrol"
version = file("version.properties")
    .readLines().first { it.startsWith("version=") }.substringAfter("=")

dependencies {
    // Ktor BOM for version alignment
    api(platform(libs.ktorBom))

    // Coroutines
    implementation(libs.kotlinxCoroutines)

    // Kotlin serialization
    implementation(libs.kotlinxSerialization)

    // Ktor server
    implementation(libs.ktorServerCore)
    api(libs.ktorServerAuth)
    api(libs.ktorServerAuthJwt)
    implementation(libs.ktorServerContentNegotiation)
    implementation(libs.ktorSerializationJson)
    implementation(libs.ktorServerStatusPages)
    implementation(libs.ktorServerForwardedHeader)
    api(libs.ktorServerSessions)

    // JWT
    implementation(libs.javaJwt)

    // Logging
    api(libs.kotlinLogging)

    // Test dependencies
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinxCoroutines)
    testImplementation(libs.ktorServerTests)
    testImplementation(libs.ktorServerCio)
    testImplementation(libs.ktorClientContentNegotiation)
    testImplementation(libs.ktorSerializationJson)
    testImplementation(libs.slf4jSimple)
}

// Generate version file for runtime access
val generateVersionFile = tasks.register("generateVersionFile") {
    val outputDir = layout.buildDirectory.dir("generated/resources")
    val versionFile = outputDir.map { it.file("ktor-oauth-version.properties") }
    val versionValue = version.toString()

    inputs.property("version", versionValue)
    outputs.file(versionFile)

    doLast {
        outputDir.get().asFile.mkdirs()
        versionFile.get().asFile.writeText("version=$versionValue\n")
    }
}

tasks.processResources {
    dependsOn(generateVersionFile)
}

sourceSets.main {
    resources.srcDir(layout.buildDirectory.dir("generated/resources"))
}

// Ensure sourcesJar depends on generateVersionFile since it includes generated resources
tasks.withType<Jar>().configureEach {
    if (name == "sourcesJar") {
        dependsOn(generateVersionFile)
    }
}

// Enable experimental APIs globally
kotlin {
    compilerOptions {
        freeCompilerArgs.addAll(
            "-opt-in=kotlin.time.ExperimentalTime",
            "-opt-in=kotlinx.serialization.InternalSerializationApi",
            "-opt-in=kotlinx.serialization.ExperimentalSerializationApi"
        )
    }
}

// CLI task for generating bearer tokens
tasks.register<JavaExec>("generateToken") {
    group = "application"
    description = "Generate a bearer token and setup URL for clients that don't support OAuth"
    mainClass.set("com.vcontrol.ktor.oauth.cli.GenerateTokenKt")
    classpath = sourceSets["main"].runtimeClasspath
    if (project.hasProperty("args")) {
        args = (project.property("args") as String).split(" ")
    }
}

// CLI task for generating setup URLs for existing clients
tasks.register<JavaExec>("generateSetupUrl") {
    group = "application"
    description = "Generate a setup URL for an existing client ID (e.g., OAuth clients)"
    mainClass.set("com.vcontrol.ktor.oauth.cli.GenerateSetupUrlKt")
    classpath = sourceSets["main"].runtimeClasspath
    if (project.hasProperty("args")) {
        args = (project.property("args") as String).split(" ")
    }
}

// Maven Central publishing via vanniktech plugin
mavenPublishing {
    publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    pom {
        name.set("Ktor Server OAuth")
        description.set("OAuth 2.0 authorization server plugin for Ktor with dynamic client registration and JWT tokens")
        url.set("https://github.com/vctrl/ktor-server-oauth")

        licenses {
            license {
                name.set("Apache License 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0")
            }
        }

        developers {
            developer {
                id.set("pmokbel")
                name.set("Paul Mokbel")
                email.set("paul@mokbel.com")
            }
        }

        scm {
            url.set("https://github.com/vctrl/ktor-server-oauth")
            connection.set("scm:git:git://github.com/vctrl/ktor-server-oauth.git")
            developerConnection.set("scm:git:ssh://git@github.com/vctrl/ktor-server-oauth.git")
        }
    }
}
