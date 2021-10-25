package cu

import com.github.tomakehurst.wiremock.client.WireMock.*
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager
import org.testcontainers.containers.BindMode
import org.testcontainers.containers.GenericContainer
import org.testcontainers.utility.DockerImageName
import java.io.File

class WiremockContainer : QuarkusTestResourceLifecycleManager {
    private val container = GenericContainer<Nothing>(
        DockerImageName.parse("rodolpheche/wiremock:2.28.0")
    ).apply {
        setupKeystores()
        withFileSystemBind(
            "security",
            "/etc/security/conf",
            BindMode.READ_WRITE
        )
        withCommand("--verbose --https-require-client-cert --disable-gzip --https-port 8443 --https-keystore /etc/security/conf/wiremock-keystore --https-truststore /etc/security/conf/wiremock-truststore")
        addExposedPorts(8443, 8080)
    }

    override fun start(): MutableMap<String, String> {
        container.start()
        configureFor(container.getMappedPort(8080))
        givenThat(
            get("/health")
                .willReturn(
                    aResponse()
                        .withHeader("Content-Type", "text/plain")
                        .withBody("Ok")
                )
        )

        System.setProperty("wiremock-container.ssl.port", "${container.getMappedPort(8443)}")

        return mutableMapOf()
    }

    override fun stop() {
        container.stop()
    }

    private fun setupKeystores() {
        initKeyStore(
            keystorePath = "security/wiremock-keystore",
            keystorePass = "password".toCharArray(),
            certificateChainString = wiremockCertificate,
            noDesPrivateKeyString = wiremockPrivateKey,
            alias = "wiremock",
            "JKS"
        )

        initTrustStore(
            keystorePath = "security/wiremock-truststore",
            keystorePass = "password",
            certificateString = clientCertificate,
            "wiremock",
            "JKS"
        )

        initKeyStore(
            keystorePath = "security/client-keystore",
            keystorePass = "password".toCharArray(),
            certificateChainString = clientCertificate,
            noDesPrivateKeyString = clientPrivateKey,
            alias = "client",
            "PKCS12"
        )

        initTrustStore(
            keystorePath = "security/client-truststore",
            keystorePass = "password",
            certificateString = wiremockCertificate,
            "client",
            "PKCS12"
        )
    }

    companion object {
        private const val wiremockCertificatePath = "src/main/resources/wiremock-certificate"
        private const val wiremockPrivateKeyPath = "src/main/resources/wiremock-private-key"
        private const val clientCertificatePath = "src/main/resources/client-certificate"
        private const val clientPrivateKeyPath = "src/main/resources/client-private-key"

        val wiremockCertificate = File(wiremockCertificatePath).readText()
        val wiremockPrivateKey = File(wiremockPrivateKeyPath).readText()

        val clientCertificate = File(clientCertificatePath).readText()
        val clientPrivateKey = File(clientPrivateKeyPath).readText()
    }
}
