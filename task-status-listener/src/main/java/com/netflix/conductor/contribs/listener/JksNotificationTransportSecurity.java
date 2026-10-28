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
package com.netflix.conductor.contribs.listener;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

/**
 * Uses private JKS stores without changing the JVM's trust or client identity for other traffic.
 */
final class JksNotificationTransportSecurity implements NotificationTransportSecurity {

    private static final String CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2";

    private final URI origin;
    private final SSLConnectionSocketFactory socketFactory;

    JksNotificationTransportSecurity(StatusNotifierNotificationProperties config) {
        try {
            origin = parseHttpsTarget(config.getUrl());
            socketFactory = createSocketFactory(config);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Unable to initialize status-notifier mTLS", e);
        }
    }

    @Override
    public PoolingHttpClientConnectionManager createConnectionManager() {
        // Register the key-bearing factory on the pool itself; HttpClient builder SSL settings
        // do not replace the socket factory of a separately supplied connection manager.
        return new PoolingHttpClientConnectionManager(
                RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("https", socketFactory)
                        .build());
    }

    @Override
    public void validateTarget(String target) throws IOException {
        URI uri = parseHttpsTarget(target);
        if (!origin.getHost().equalsIgnoreCase(uri.getHost()) || port(origin) != port(uri)) {
            throw new IOException("mTLS notification target must use the configured HTTPS origin");
        }
    }

    private static URI parseHttpsTarget(String target) throws IOException {
        if (target == null) {
            throw new IOException("mTLS notification URL must be an absolute HTTPS URL");
        }
        final URI uri;
        try {
            uri = new URI(target);
        } catch (URISyntaxException e) {
            // Do not include an untrusted URL, which could contain credentials, in the exception.
            throw new IOException("mTLS notification URL is invalid");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null
                || uri.getRawUserInfo() != null
                || uri.getRawFragment() != null
                || uri.getPort() == 0
                || uri.getPort() > 65535) {
            throw new IOException(
                    "mTLS notification URL must be an absolute HTTPS URL without user info or a fragment");
        }
        return uri;
    }

    private static int port(URI uri) {
        return uri.getPort() == -1 ? 443 : uri.getPort();
    }

    private static SSLConnectionSocketFactory createSocketFactory(
            StatusNotifierNotificationProperties config)
            throws IOException, GeneralSecurityException {
        Path passwordFile = requiredFile(config.getTlsPasswordFilePath(), "tlsPasswordFilePath");
        char[] password =
                Files.readString(passwordFile, StandardCharsets.UTF_8).strip().toCharArray();
        try {
            if (password.length == 0) {
                throw new IOException(
                        "status-notifier tlsPasswordFilePath must contain a password");
            }
            KeyStore keys = loadStore(config.getTlsKeyStorePath(), "tlsKeyStorePath", password);
            validateClientKeys(keys, password);
            KeyStore trust =
                    loadStore(config.getTlsTrustStorePath(), "tlsTrustStorePath", password);
            validateTrustStore(trust);

            KeyManagerFactory keyManagers =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keys, password);
            TrustManagerFactory trustManagers =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
            return new SSLConnectionSocketFactory(
                    context,
                    new String[] {"TLSv1.3", "TLSv1.2"},
                    null,
                    SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static KeyStore loadStore(String file, String property, char[] password)
            throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("JKS");
        try (InputStream input = Files.newInputStream(requiredFile(file, property))) {
            store.load(input, password);
        } catch (IOException e) {
            throw new IOException("Unable to read status-notifier " + property + " JKS store", e);
        }
        return store;
    }

    private static Path requiredFile(String file, String property) throws IOException {
        if (file == null || file.isBlank()) {
            throw new IOException(
                    "status-notifier " + property + " must be configured when mTLS is enabled");
        }
        Path path = Path.of(file);
        if (!path.isAbsolute() || !Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw new IOException(
                    "status-notifier " + property + " must name a readable absolute file");
        }
        return path;
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
                        "status-notifier TLS key store must contain a private key");
            }
            Certificate[] chain = keys.getCertificateChain(alias);
            if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate leaf)) {
                throw new GeneralSecurityException(
                        "status-notifier TLS private key must have an X.509 certificate chain");
            }
            List<String> eku = leaf.getExtendedKeyUsage();
            if (leaf.getBasicConstraints() >= 0 || eku == null || !eku.contains(CLIENT_AUTH_EKU)) {
                throw new GeneralSecurityException(
                        "status-notifier TLS client certificate must be a leaf with explicit clientAuth EKU");
            }
            for (Certificate certificate : chain) {
                if (!(certificate instanceof X509Certificate x509)) {
                    throw new GeneralSecurityException(
                            "status-notifier TLS client chain must contain X.509 certificates");
                }
                x509.checkValidity();
            }
            foundKey = true;
        }
        if (!foundKey) {
            throw new GeneralSecurityException(
                    "status-notifier TLS key store has no client private key");
        }
    }

    private static void validateTrustStore(KeyStore trust) throws GeneralSecurityException {
        if (trust.size() == 0) {
            throw new GeneralSecurityException(
                    "status-notifier TLS trust store has no CA certificates");
        }
        Enumeration<String> aliases = trust.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!trust.isCertificateEntry(alias)
                    || !(trust.getCertificate(alias) instanceof X509Certificate ca)
                    || ca.getBasicConstraints() < 0) {
                throw new GeneralSecurityException(
                        "status-notifier TLS trust store must contain only X.509 CA certificates");
            }
        }
    }
}
