
plugins {
    kotlin("jvm") version "1.5.30"
    id("org.jetbrains.kotlin.plugin.allopen") version "1.5.30"
    id("io.quarkus") version "1.12.0.Final"
    java
}


group = "cu"
version = "1.0"

val kotestVersion = "4.6.1"
val junitJupiterVersion = "5.6.0"
val testContainersVersion = "1.16.0"
val quarkusVersion = "1.12.0.Final"

repositories {
    mavenCentral()
}

dependencies {
    files("${System.getProperty("java.home")}/../lib/tools.jar")
    implementation(enforcedPlatform("io.quarkus:quarkus-universe-bom:${quarkusVersion}"))

    implementation(kotlin("stdlib"))
    implementation("commons-codec:commons-codec:1.15")
    implementation("io.quarkus:quarkus-resteasy:${quarkusVersion}")
    implementation("io.quarkus:quarkus-resteasy-jackson:${quarkusVersion}")
    implementation("io.quarkus:quarkus-rest-client:${quarkusVersion}")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitJupiterVersion")
    testImplementation("io.quarkus:quarkus-junit5:${quarkusVersion}")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitJupiterVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-params:$junitJupiterVersion")
    testImplementation("io.kotest:kotest-runner-junit5:$kotestVersion")
    testImplementation("io.kotest:kotest-assertions-core:$kotestVersion")
    testImplementation("io.kotest:kotest-property:$kotestVersion")
    testImplementation("io.kotest.extensions:kotest-extensions-testcontainers:1.0.1")
    testImplementation("org.testcontainers:testcontainers:$testContainersVersion")
    testImplementation("org.testcontainers:junit-jupiter:$testContainersVersion")
    testImplementation("com.github.tomakehurst:wiremock-jre8:2.30.1")    // Native testing
    nativeTestImplementation("io.quarkus:quarkus-junit5")
    nativeTestImplementation("io.rest-assured:rest-assured")
}

allOpen {
    annotation("javax.ws.rs.Path")
    annotation("javax.enterprise.context.ApplicationScoped")
    annotation("javax.persistence.Entity")
    annotation("org.eclipse.microprofile.rest.client.inject")
    annotation("io.quarkus.test.junit.QuarkusTest")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
