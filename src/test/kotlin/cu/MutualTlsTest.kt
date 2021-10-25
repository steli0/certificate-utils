package cu

import cu.client.RestService
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeTypeOf
import io.quarkus.restclient.NoopHostnameVerifier
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import org.eclipse.microprofile.rest.client.RestClientBuilder
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestInstance.Lifecycle
import java.io.File
import java.io.FileInputStream
import java.net.URI
import java.security.KeyStore
import javax.net.ssl.SSLHandshakeException
import javax.ws.rs.ProcessingException


@QuarkusTest
@QuarkusTestResource(WiremockContainer::class)
@TestInstance(Lifecycle.PER_CLASS)
class MutualTlsTest {

    @Test
    fun `Given a service that require client certificate When a client tries to handshake And the client does not provide a keystore Then the mutual tls handshake should fail`() {
        val client = buildClient()

        shouldThrow<ProcessingException> {
            client.health()
        }.cause.shouldBeTypeOf<SSLHandshakeException>()
    }

    @Test
    fun `Given a service that require client certificate When a client tries to handshake And the client provides a keystore without verifying the hostname And the server trusts client's certificate And the server's CN is is different than the one presented with the certificate Then the mutual tls handshake should be successful`() {
        val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
        FileInputStream("security/client-keystore").use {
            keystore.load(it, "password".toCharArray())
        }

        val truststore = KeyStore.getInstance(KeyStore.getDefaultType())
        FileInputStream("security/client-truststore").use {
            truststore.load(it, "password".toCharArray())
        }

        val client = buildClient(keystore, truststore)

        val response = client.health()

        with(response) {
            status shouldBe 200
            response.readEntity(String::class.java) shouldBe "Ok"
        }
    }

    @Test
    fun `Given a service that require client certificate When a client tries to handshake And the client provides a keystore And the server does not trust client's certificate Then the mutual tls handshake should fail`() {
        initKeyStore(
            keystorePath = "security/fake-keystore",
            keystorePass = "password".toCharArray(),
            certificateChainString = fakeCertificate,
            noDesPrivateKeyString = fakePrivateKey,
            alias = "client",
            "PKCS12"
        )

        val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
        FileInputStream("security/fake-keystore").use {
            keystore.load(it, "password".toCharArray())
        }

        val truststore = KeyStore.getInstance(KeyStore.getDefaultType())
        FileInputStream("security/client-truststore").use {
            truststore.load(it, "password".toCharArray())
        }

        val client = buildClient(keystore, truststore)

        shouldThrow<ProcessingException> {
            client.health()
        }.cause.shouldBeTypeOf<SSLHandshakeException>()
    }

    @Test
    fun `Given a service that require client certificate When a client tries to handshake And the client provides a keystore And the client trusts the server certificate And the server trusts the client certificate Then the mutual tls handshake should be successful`() {
        val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
        FileInputStream("security/client-keystore").use {
            keystore.load(it, "password".toCharArray())
        }

        val truststore = KeyStore.getInstance(KeyStore.getDefaultType())
        FileInputStream("security/client-truststore").use {
            truststore.load(it, "password".toCharArray())
        }

        val client = buildClient(keystore, truststore)
        val response = client.health()

        with(response) {
            status shouldBe 200
            response.readEntity(String::class.java) shouldBe "Ok"
        }
    }

    private fun buildClient(keyStore: KeyStore? = null, trustStore: KeyStore? = null): RestService {
        val clientBuilder = RestClientBuilder.newBuilder()
            .baseUri(URI("https://localhost:${System.getProperty("wiremock-container.ssl.port")}"))

        keyStore?.apply {
            clientBuilder.keyStore(this, "password")
        }

        trustStore?.apply {
            clientBuilder.trustStore(this)
        }

//        clientBuilder.hostnameVerifier(NoopHostnameVerifier())

        return clientBuilder.build(RestService::class.java)
    }

    companion object {
        private const val fakeCertificatePath = "src/main/resources/fake-certificate"
        private const val fakePrivateKeyPath = "src/main/resources/fake-private-key"

        val fakeCertificate = File(fakeCertificatePath).readText()
        val fakePrivateKey = File(fakePrivateKeyPath).readText()
    }
}
