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
package com.netflix.conductor.common.utils;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Generates temporary test certificates using only the running JDK's keytool. */
public final class TestTlsCertificates {

    private static final String PASSWORD = "conductor-test-only-password";
    private static final String LEAF_ALIAS = "test-leaf";

    private final Path keyStore;
    private final Path trustStore;
    private final Path passwordFile;

    private TestTlsCertificates(Path directory) {
        keyStore = directory.resolve("client.jks");
        trustStore = directory.resolve("trust.jks");
        passwordFile = directory.resolve("password");
    }

    /** Creates a fresh CA and a localhost identity valid for both TLS client and server use. */
    public static TestTlsCertificates create(Path directory) throws Exception {
        Files.createDirectories(directory);
        Path work = Files.createTempDirectory(directory, "tls-");
        restrictPermissions(work, "rwx------");
        TestTlsCertificates result = new TestTlsCertificates(work);
        Files.writeString(result.passwordFile, PASSWORD, StandardCharsets.UTF_8);
        restrictPermissions(result.passwordFile, "rw-------");

        Path caStore = work.resolve("ca.jks");
        Path caCertificate = work.resolve("ca.pem");
        Path request = work.resolve("leaf.csr");
        Path leafCertificate = work.resolve("leaf.pem");
        result.keytool(
                "-genkeypair",
                "-alias",
                "test-ca",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-sigalg",
                "SHA256withRSA",
                "-dname",
                "CN=Conductor Test CA",
                "-validity",
                "7",
                "-ext",
                "bc:c",
                "-ext",
                "KU=keyCertSign,cRLSign",
                "-keystore",
                caStore.toString(),
                "-storetype",
                "JKS",
                "-keypass:file",
                result.passwordFile.toString());
        result.keytool(
                "-exportcert",
                "-rfc",
                "-alias",
                "test-ca",
                "-keystore",
                caStore.toString(),
                "-file",
                caCertificate.toString());
        result.keytool(
                "-genkeypair",
                "-alias",
                LEAF_ALIAS,
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-sigalg",
                "SHA256withRSA",
                "-dname",
                "CN=localhost",
                "-validity",
                "3",
                "-ext",
                "SAN=dns:localhost",
                "-ext",
                "EKU=serverAuth,clientAuth",
                "-ext",
                "KU=digitalSignature,keyEncipherment",
                "-keystore",
                result.keyStore.toString(),
                "-storetype",
                "JKS",
                "-keypass:file",
                result.passwordFile.toString());
        result.keytool(
                "-certreq",
                "-alias",
                LEAF_ALIAS,
                "-keystore",
                result.keyStore.toString(),
                "-file",
                request.toString(),
                "-keypass:file",
                result.passwordFile.toString());
        result.keytool(
                "-gencert",
                "-rfc",
                "-alias",
                "test-ca",
                "-keystore",
                caStore.toString(),
                "-infile",
                request.toString(),
                "-outfile",
                leafCertificate.toString(),
                "-validity",
                "3",
                "-ext",
                "SAN=dns:localhost",
                "-ext",
                "EKU=serverAuth,clientAuth",
                "-ext",
                "KU=digitalSignature,keyEncipherment",
                "-keypass:file",
                result.passwordFile.toString());
        result.keytool(
                "-importcert",
                "-noprompt",
                "-alias",
                "test-ca",
                "-keystore",
                result.keyStore.toString(),
                "-file",
                caCertificate.toString());
        result.keytool(
                "-importcert",
                "-noprompt",
                "-alias",
                LEAF_ALIAS,
                "-keystore",
                result.keyStore.toString(),
                "-file",
                leafCertificate.toString(),
                "-keypass:file",
                result.passwordFile.toString());
        result.keytool(
                "-importcert",
                "-noprompt",
                "-alias",
                "test-ca",
                "-keystore",
                result.trustStore.toString(),
                "-storetype",
                "JKS",
                "-file",
                caCertificate.toString());
        try (var paths = Files.list(work)) {
            for (Path file : paths.toList()) {
                restrictPermissions(file, "rw-------");
            }
        }
        return result;
    }

    public Path keyStore() {
        return keyStore;
    }

    public Path trustStore() {
        return trustStore;
    }

    public Path passwordFile() {
        return passwordFile;
    }

    /** Returns the generated leaf certificate, without exposing its private key. */
    public X509Certificate certificate() throws Exception {
        return (X509Certificate) load(keyStore).getCertificate(LEAF_ALIAS);
    }

    /** Returns a separate, expired client identity for validation failure checks. */
    public Path expiredKeyStore() throws Exception {
        Path expired = keyStore.resolveSibling("expired-client.jks");
        Files.copy(keyStore, expired);
        keytool(
                "-selfcert",
                "-alias",
                LEAF_ALIAS,
                "-keystore",
                expired.toString(),
                "-startdate",
                "-10d",
                "-validity",
                "1",
                "-ext",
                "EKU=clientAuth",
                "-keypass:file",
                passwordFile.toString());
        return expired;
    }

    /**
     * Returns a server context trusting the test CA; callers choose whether clients are required.
     */
    public SSLContext serverContext() throws Exception {
        char[] password = PASSWORD.toCharArray();
        try {
            KeyManagerFactory keys =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(load(keyStore), password);
            TrustManagerFactory trust =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(load(trustStore));
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
            return context;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static KeyStore load(Path file) throws Exception {
        KeyStore store = KeyStore.getInstance("JKS");
        char[] password = PASSWORD.toCharArray();
        try (InputStream input = Files.newInputStream(file)) {
            store.load(input, password);
        } finally {
            Arrays.fill(password, '\0');
        }
        return store;
    }

    private void keytool(String... arguments) throws Exception {
        String executable =
                System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool";
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", executable).toString());
        command.addAll(List.of(arguments));
        command.addAll(List.of("-storepass:file", passwordFile.toString()));
        Process process =
                new ProcessBuilder(command)
                        .redirectErrorStream(true)
                        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                        .start();
        try {
            process.getOutputStream().close();
            if (!process.waitFor(30, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IllegalStateException(
                        "Test keytool operation timed out: " + arguments[0]);
            }
            if (process.exitValue() != 0) {
                throw new IllegalStateException("Test keytool operation failed: " + arguments[0]);
            }
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    private static void restrictPermissions(Path path, String permissions) throws Exception {
        if (Files.getFileAttributeView(path, PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(permissions));
        }
    }
}
