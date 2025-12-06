plugins {
    `kotlin-dsl`
}

val jvmVersion = file("../gradle.properties").readLines()
    .first { it.startsWith("jvmToolchain=") }
    .substringAfter("=").toInt()

kotlin {
    jvmToolchain(jvmVersion)
}

dependencies {
    implementation(libs.kotlinGradlePlugin)
}
