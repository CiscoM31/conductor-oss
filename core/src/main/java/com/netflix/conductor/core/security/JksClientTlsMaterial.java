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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/** Loads startup snapshots; replacing the files requires recreating the owning clients. */
final class JksClientTlsMaterial implements ClientTlsMaterial {

    private static final String CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2";

    private final KeyManagerFactory keyManagers;
    private final TrustManagerFactory trustManagers;
    private final SSLContext context;

    JksClientTlsMaterial(String keyStorePath, String trustStorePath, String passwordFilePath) {
        char[] password = null;
        try {
            password =
                    Files.readString(
                                    requiredFile(passwordFilePath, "tlsPasswordFilePath"),
                                    StandardCharsets.UTF_8)
                            .strip()
                            .toCharArray();
            if (password.length == 0) {
                throw new IOException("tlsPasswordFilePath must contain a password");
            }
            KeyStore keys = loadStore(keyStorePath, "tlsKeyStorePath", password);
            validateClientKeys(keys, password);
            KeyStore trust = loadStore(trustStorePath, "tlsTrustStorePath", password);
            validateTrustStore(trust);

            keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keys, password);
            trustManagers =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trust);
            context = SSLContext.getInstance("TLS");
            context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Unable to initialize private client mTLS material", e);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    @Override
    public SSLSocketFactory getSocketFactory() {
        return context.getSocketFactory();
    }

    @Override
    public SSLParameters getSslParameters() {
        SSLParameters parameters = context.getDefaultSSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        return parameters;
    }

    @Override
    public KeyManagerFactory getKeyManagerFactory() {
        return keyManagers;
    }

    @Override
    public TrustManagerFactory getTrustManagerFactory() {
        return trustManagers;
    }

    private static Path requiredFile(String file, String property) throws IOException {
        if (file == null || file.isBlank()) {
            throw new IOException(property + " must be configured when mTLS is enabled");
        }
        final Path path;
        try {
            path = Path.of(file);
        } catch (InvalidPathException e) {
            throw new IOException(property + " must name a readable absolute file");
        }
        if (!path.isAbsolute() || !Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw new IOException(property + " must name a readable absolute file");
        }
        return path;
    }

    private static KeyStore loadStore(String file, String property, char[] password)
            throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("JKS");
        try (InputStream input = Files.newInputStream(requiredFile(file, property))) {
            store.load(input, password);
        } catch (IOException e) {
            throw new IOException("Unable to load " + property + " JKS store", e);
        }
        return store;
    }

    private static void validateClientKeys(KeyStore keys, char[] password)
            throws GeneralSecurityException {
        boolean foundKey = false;
        Enumeration<String> aliases = keys.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!keys.isKeyEntry(alias)) {
                continue;
            }
            if (!(keys.getKey(alias, password) instanceof PrivateKey)) {
                throw new GeneralSecurityException(
                        "Client TLS key store must contain a private key");
            }
            Certificate[] chain = keys.getCertificateChain(alias);
            if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate leaf)) {
                throw new GeneralSecurityException(
                        "Client TLS private key must have an X.509 chain");
            }
            List<String> eku = leaf.getExtendedKeyUsage();
            if (leaf.getBasicConstraints() >= 0 || eku == null || !eku.contains(CLIENT_AUTH_EKU)) {
                throw new GeneralSecurityException(
                        "Client TLS certificate must be a leaf with explicit clientAuth EKU");
            }
            for (Certificate certificate : chain) {
                if (!(certificate instanceof X509Certificate x509)) {
                    throw new GeneralSecurityException(
                            "Client TLS chain must contain X.509 certificates");
                }
                x509.checkValidity();
            }
            foundKey = true;
        }
        if (!foundKey) {
            throw new GeneralSecurityException("Client TLS key store has no private key");
        }
    }

    private static void validateTrustStore(KeyStore trust) throws GeneralSecurityException {
        if (trust.size() == 0) {
            throw new GeneralSecurityException("Client TLS trust store has no CA certificates");
        }
        Enumeration<String> aliases = trust.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!trust.isCertificateEntry(alias)
                    || !(trust.getCertificate(alias) instanceof X509Certificate ca)
                    || ca.getBasicConstraints() < 0) {
                throw new GeneralSecurityException(
                        "Client TLS trust store must contain only X.509 CA certificates");
            }
            // Retain overlapping issuer roots during CA rotation. The TLS trust manager validates
            // the served chain instead of rejecting an unrelated, unused CA at client startup.
        }
    }
}
