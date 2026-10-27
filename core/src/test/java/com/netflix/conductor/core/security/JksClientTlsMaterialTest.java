/*
 * Copyright 2026 Conductor Authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.netflix.conductor.core.security;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.util.Arrays;

import javax.net.ssl.SSLParameters;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.netflix.conductor.common.utils.TestTlsCertificates;

import static org.junit.jupiter.api.Assertions.*;

class JksClientTlsMaterialTest {

    @TempDir static Path directory;

    private static TestTlsCertificates certificates;

    @BeforeAll
    static void createCertificates() throws Exception {
        certificates = TestTlsCertificates.create(directory);
    }

    @Test
    void validMaterialProvidesPrivateIdentityAndStrictTlsParameters() {
        ClientTlsMaterial material =
                load(
                        certificates.keyStore(),
                        certificates.trustStore(),
                        certificates.passwordFile());

        assertNotNull(material.getSocketFactory());
        assertNotNull(material.getKeyManagerFactory());
        assertNotNull(material.getTrustManagerFactory());
        SSLParameters parameters = material.getSslParameters();
        assertArrayEquals(new String[] {"TLSv1.3", "TLSv1.2"}, parameters.getProtocols());
        assertEquals("HTTPS", parameters.getEndpointIdentificationAlgorithm());
        assertNotSame(parameters, material.getSslParameters());
    }

    @Test
    void missingOrRelativeMaterialPathsFailClosed() {
        Path missing = directory.resolve("missing");
        assertThrows(
                IllegalStateException.class,
                () -> load(missing, certificates.trustStore(), certificates.passwordFile()));
        assertThrows(
                IllegalStateException.class,
                () -> load(certificates.keyStore(), certificates.trustStore(), missing));
        assertThrows(
                IllegalStateException.class,
                () ->
                        load(
                                Path.of("relative.jks"),
                                certificates.trustStore(),
                                certificates.passwordFile()));
    }

    @Test
    void wrongOrEmptyStorePasswordFailsClosed() throws Exception {
        Path wrong = directory.resolve("wrong-password");
        Files.writeString(wrong, "incorrect-test-password");
        assertThrows(
                IllegalStateException.class,
                () -> load(certificates.keyStore(), certificates.trustStore(), wrong));

        Path empty = directory.resolve("empty-password");
        Files.writeString(empty, "\n");
        assertThrows(
                IllegalStateException.class,
                () -> load(certificates.keyStore(), certificates.trustStore(), empty));
    }

    @Test
    void clientIdentityRequiresAPrivateKeyAndALeafCertificate() throws Exception {
        IllegalStateException noKey =
                assertThrows(
                        IllegalStateException.class,
                        () ->
                                load(
                                        certificates.trustStore(),
                                        certificates.trustStore(),
                                        certificates.passwordFile()));
        assertTrue(noKey.getCause().getMessage().contains("no private key"));

        KeyStore identity = readStore(certificates.keyStore());
        KeyStore trust = readStore(certificates.trustStore());
        KeyStore caIdentity = emptyStore();
        char[] password = password();
        try {
            PrivateKey key = (PrivateKey) identity.getKey("test-leaf", password);
            caIdentity.setKeyEntry(
                    "ca-client",
                    key,
                    password,
                    new Certificate[] {trust.getCertificate("test-ca")});
        } finally {
            Arrays.fill(password, '\0');
        }
        Path caStore = writeStore("ca-client.jks", caIdentity);
        IllegalStateException caLeaf =
                assertThrows(
                        IllegalStateException.class,
                        () ->
                                load(
                                        caStore,
                                        certificates.trustStore(),
                                        certificates.passwordFile()));
        assertTrue(caLeaf.getCause().getMessage().contains("leaf with explicit clientAuth EKU"));
    }

    @Test
    void rejectsExpiredClientCertificates() throws Exception {
        Path expired = certificates.expiredKeyStore();
        IllegalStateException failure =
                assertThrows(
                        IllegalStateException.class,
                        () ->
                                load(
                                        expired,
                                        certificates.trustStore(),
                                        certificates.passwordFile()));
        assertInstanceOf(CertificateExpiredException.class, failure.getCause());
    }

    @Test
    void trustStoreMustContainCaCertificates() throws Exception {
        Path emptyTrust = writeStore("empty-trust.jks", emptyStore());
        assertThrows(
                IllegalStateException.class,
                () -> load(certificates.keyStore(), emptyTrust, certificates.passwordFile()));

        KeyStore leafTrust = emptyStore();
        leafTrust.setCertificateEntry("leaf", certificates.certificate());
        Path nonCaTrust = writeStore("leaf-trust.jks", leafTrust);
        IllegalStateException failure =
                assertThrows(
                        IllegalStateException.class,
                        () ->
                                load(
                                        certificates.keyStore(),
                                        nonCaTrust,
                                        certificates.passwordFile()));
        assertTrue(failure.getCause().getMessage().contains("only X.509 CA certificates"));
    }

    private static ClientTlsMaterial load(Path keys, Path trust, Path passwordFile) {
        return ClientTlsMaterial.loadJks(
                keys.toString(), trust.toString(), passwordFile.toString());
    }

    private static char[] password() throws Exception {
        return Files.readString(certificates.passwordFile()).strip().toCharArray();
    }

    private static KeyStore readStore(Path path) throws Exception {
        KeyStore store = KeyStore.getInstance("JKS");
        char[] password = password();
        try (InputStream input = Files.newInputStream(path)) {
            store.load(input, password);
        } finally {
            Arrays.fill(password, '\0');
        }
        return store;
    }

    private static KeyStore emptyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, null);
        return store;
    }

    private static Path writeStore(String name, KeyStore store) throws Exception {
        Path path = directory.resolve(name);
        char[] password = password();
        try (OutputStream output = Files.newOutputStream(path)) {
            store.store(output, password);
        } finally {
            Arrays.fill(password, '\0');
        }
        return path;
    }
}
