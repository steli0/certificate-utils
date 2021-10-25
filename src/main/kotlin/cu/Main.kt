package cu

import org.apache.commons.codec.binary.Base64
import sun.security.x509.*
import java.io.FileOutputStream
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

fun main() {

    // Generate wiremock key-pair
    val wiremockPrivateKeyPairGenerator = KeyPairGenerator.getInstance("RSA")
    wiremockPrivateKeyPairGenerator.initialize(4096)
    val wiremockKeyPair = wiremockPrivateKeyPairGenerator.generateKeyPair()
    val wiremockCertificate = generateCertificate("cn=localhost", wiremockKeyPair, 365, "SHA256withRSA")
        ?: throw IllegalArgumentException("Could not generate certificate for Wiremock")

    // Generate client key-pair
    val clientPrivateKeyPairGenerator = KeyPairGenerator.getInstance("RSA")
    clientPrivateKeyPairGenerator.initialize(4096)
    val clientKeyPair = clientPrivateKeyPairGenerator.generateKeyPair()
    val clientCertificate = generateCertificate("cn=client", clientKeyPair, 365, "SHA256withRSA")
        ?: throw IllegalArgumentException("Could not generate certificate for the Client")

    // Generate keystore / truststore
    initKeyStore(wiremockKeyPair.private, wiremockCertificate, "JKS", "wiremock", "security2/wiremock-keystore")
    initKeyStore(clientKeyPair.private, clientCertificate, "PKCS12", "client", "security2/client-keystore")

    initTrustStore(clientCertificate, "JKS", "wiremock", "security2/wiremock-truststore")
    initTrustStore(wiremockCertificate, "PKCS12", "client", "security2/client-truststore")
}

fun initTrustStore(certificate: Certificate, type: String, alias: String, path: String) {
    KeyStore.getInstance(type).apply {
        load(null, null)
        setCertificateEntry(alias, certificate)
        FileOutputStream(path).use { fos ->
            store(fos, "password".toCharArray())
        }
    }
}

fun initKeyStore(privateKey: PrivateKey, certificate: Certificate, type: String, alias: String, path: String) {
    KeyStore.getInstance(type).apply {
        load(null, null)
        setKeyEntry(alias, privateKey, "password".toCharArray(), arrayOf(certificate))

        FileOutputStream(path).use { fos ->
            store(fos, "password".toCharArray())
        }
    }
}

@Suppress("JAVA_MODULE_DOES_NOT_EXPORT_PACKAGE")
private fun generateCertificate(dn: String, keyPair: KeyPair, validity: Int, sigAlgName: String): X509Certificate? {
    val privateKey = keyPair.private
    val info = X509CertInfo()
    val from = Date()
    val to = Date(from.time + validity * 1000L * 24L * 60L * 60L)
    val interval = CertificateValidity(from, to)
    val serialNumber = BigInteger(64, SecureRandom())
    val owner = X500Name(dn)
    var sigAlgId = AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid)
    info[X509CertInfo.VALIDITY] = interval
    info[X509CertInfo.SERIAL_NUMBER] = CertificateSerialNumber(serialNumber)
    info[X509CertInfo.SUBJECT] = owner
    info[X509CertInfo.ISSUER] = owner
    info[X509CertInfo.KEY] = CertificateX509Key(keyPair.public)
    info[X509CertInfo.VERSION] = CertificateVersion(CertificateVersion.V3)
    info[X509CertInfo.ALGORITHM_ID] = CertificateAlgorithmId(sigAlgId)

    // Sign the cert to identify the algorithm that's used.
    var certificate = X509CertImpl(info)
    certificate.sign(privateKey, sigAlgName)

    // Update the algorithm, and resign.
    sigAlgId = certificate[X509CertImpl.SIG_ALG] as AlgorithmId
    info[CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM] = sigAlgId
    certificate = X509CertImpl(info)
    certificate.sign(privateKey, sigAlgName)
    return certificate
}

/**
 * Generates trust store by given certificate in .pem format
 *
 * @param certificateString the certificate in plain string
 */
fun initTrustStore(
    keystorePath: String,
    keystorePass: String,
    certificateString: String,
    alias: String,
    keystoreType: String
) = KeyStore.getInstance(keystoreType).apply {
    val cf = CertificateFactory.getInstance("X.509")
    val certificate = cf.generateCertificate(certificateString.byteInputStream(Charset.defaultCharset()))
    load(null, keystorePass.toCharArray())
    setCertificateEntry(alias, certificate)
    FileOutputStream(keystorePath).use { fos ->
        store(fos, keystorePass.toCharArray())
    }
}

/**
 * Generates key store by given certificate in .pem format and private key in .pem format, not encrypted
 *
 * @param certificateChainString the certificate chain in plain string
 * @param noDesPrivateKeyString the private key in plain string without encryption
 */
fun initKeyStore(
    keystorePath: String,
    keystorePass: CharArray,
    certificateChainString: String,
    noDesPrivateKeyString: String,
    alias: String,
    keystoreType: String
) = KeyStore.getInstance(keystoreType).apply {
    val keySpec = PKCS8EncodedKeySpec(Base64.decodeBase64(noDesPrivateKeyString))
    val keyFactory = KeyFactory.getInstance("RSA")
    val privateKey = keyFactory.generatePrivate(keySpec)
    val factory = CertificateFactory.getInstance("X.509")
    val certificateChain = factory.generateCertificates(
        certificateChainString.byteInputStream(Charset.forName("UTF-8"))
    )

    load(null, keystorePass)
    setKeyEntry(alias, privateKey, keystorePass, certificateChain.toTypedArray())
    FileOutputStream(keystorePath).use { fos ->
        store(fos, keystorePass)
    }
}
