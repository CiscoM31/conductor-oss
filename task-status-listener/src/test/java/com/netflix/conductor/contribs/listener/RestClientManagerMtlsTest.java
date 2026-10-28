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
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.apache.http.client.ClientProtocolException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.netflix.conductor.common.utils.TestTlsCertificates;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import static org.junit.jupiter.api.Assertions.*;

class RestClientManagerMtlsTest {

    @TempDir static Path directory;

    private static TestTlsCertificates certificates;
    private static TestTlsCertificates unrelatedCertificates;

    @BeforeAll
    static void createCertificates() throws Exception {
        certificates = TestTlsCertificates.create(directory.resolve("trusted"));
        unrelatedCertificates = TestTlsCertificates.create(directory.resolve("unrelated"));
    }

    @Test
    void sendsTaskAndWorkflowNotificationsWithTheConfiguredClientCertificate() throws Exception {
        List<ReceivedRequest> received = new CopyOnWriteArrayList<>();
        SSLContext originalDefault = SSLContext.getDefault();
        try (LocalServer server =
                        LocalServer.https(
                                certificates.serverContext(),
                                exchange -> {
                                    X509Certificate peer =
                                            (X509Certificate)
                                                    ((HttpsExchange) exchange)
                                                            .getSSLSession()
                                                            .getPeerCertificates()[0];
                                    received.add(
                                            new ReceivedRequest(
                                                    exchange.getRequestMethod(),
                                                    exchange.getRequestURI().getPath(),
                                                    exchange.getRequestHeaders()
                                                            .getFirst("X-Domain-Group"),
                                                    exchange.getRequestHeaders()
                                                            .getFirst("X-Account"),
                                                    new String(
                                                            exchange.getRequestBody()
                                                                    .readAllBytes(),
                                                            StandardCharsets.UTF_8),
                                                    peer));
                                    exchange.sendResponseHeaders(202, -1);
                                });
                RestClientManager client = new RestClientManager(mtlsProperties(server.url()))) {
            post(client, RestClientManager.NotificationType.TASK, null);
            post(client, RestClientManager.NotificationType.WORKFLOW, null);

            assertEquals(
                    List.of("/tasks", "/workflows"),
                    received.stream().map(ReceivedRequest::path).toList());
            for (ReceivedRequest request : received) {
                assertEquals("POST", request.method());
                assertEquals("domain-group", request.domainGroup());
                assertEquals("account", request.account());
                assertEquals("{\"status\":\"COMPLETED\"}", request.body());
                assertArrayEquals(
                        certificates.certificate().getEncoded(), request.peer().getEncoded());
            }
            assertSame(originalDefault, SSLContext.getDefault());
        }
    }

    @Test
    void rejectsHttpAndOtherOriginsBeforeSendingNotifications() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        HttpHandler handler =
                exchange -> {
                    requests.incrementAndGet();
                    exchange.sendResponseHeaders(200, -1);
                };
        try (LocalServer origin = LocalServer.https(certificates.serverContext(), handler);
                LocalServer other = LocalServer.https(certificates.serverContext(), handler);
                RestClientManager client = new RestClientManager(mtlsProperties(origin.url()))) {
            for (String target :
                    List.of(
                            origin.url().replace("https:", "http:"),
                            origin.url().replace("localhost", "127.0.0.1"),
                            other.url(),
                            origin.url() + "#fragment",
                            origin.url().replace("https://", "https://user:password@"))) {
                StatusNotifier override = new StatusNotifier();
                override.setUrl(target);
                IOException failure =
                        assertThrows(
                                IOException.class,
                                () ->
                                        post(
                                                client,
                                                RestClientManager.NotificationType.TASK,
                                                override));
                assertTrue(failure.getMessage().contains("mTLS notification"));
            }
            assertEquals(0, requests.get());
        }
    }

    @Test
    void doesNotFollowSeeOtherRedirectsToAnotherOrigin() throws Exception {
        AtomicInteger redirectedRequests = new AtomicInteger();
        AtomicInteger originalRequests = new AtomicInteger();
        try (LocalServer destination =
                        LocalServer.http(
                                exchange -> {
                                    redirectedRequests.incrementAndGet();
                                    exchange.sendResponseHeaders(200, -1);
                                });
                LocalServer origin =
                        LocalServer.https(
                                certificates.serverContext(),
                                exchange -> {
                                    originalRequests.incrementAndGet();
                                    exchange.getRequestBody().readAllBytes();
                                    exchange.getResponseHeaders()
                                            .set("Location", destination.url() + "/redirected");
                                    exchange.sendResponseHeaders(303, -1);
                                });
                RestClientManager client = new RestClientManager(mtlsProperties(origin.url()))) {
            // Unlike several other redirects, 303 would normally turn this POST into a GET.
            ClientProtocolException failure =
                    assertThrows(
                            ClientProtocolException.class,
                            () -> post(client, RestClientManager.NotificationType.TASK, null));
            assertEquals("Unexpected response status: 303", failure.getMessage());
            assertEquals(1, originalRequests.get());
            assertEquals(0, redirectedRequests.get());
        }
    }

    @Test
    void rejectsAServerCertificateWithTheWrongHostname() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        try (LocalServer server =
                        LocalServer.https(
                                certificates.serverContext(),
                                exchange -> {
                                    requests.incrementAndGet();
                                    exchange.sendResponseHeaders(200, -1);
                                });
                RestClientManager client =
                        new RestClientManager(
                                mtlsProperties(server.url().replace("localhost", "127.0.0.1")))) {
            // The certificate covers localhost only; the connection still reaches the same server.
            assertThrows(
                    javax.net.ssl.SSLException.class,
                    () -> post(client, RestClientManager.NotificationType.TASK, null));
            assertEquals(0, requests.get());
        }
    }

    @Test
    void rejectsAServerOutsideTheConfiguredTrustStore() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        try (LocalServer server =
                LocalServer.https(
                        certificates.serverContext(),
                        exchange -> {
                            requests.incrementAndGet();
                            exchange.sendResponseHeaders(200, -1);
                        })) {
            StatusNotifierNotificationProperties config = mtlsProperties(server.url());
            config.setTlsTrustStorePath(unrelatedCertificates.trustStore().toString());
            try (RestClientManager client = new RestClientManager(config)) {
                assertThrows(
                        IOException.class,
                        () -> post(client, RestClientManager.NotificationType.TASK, null));
                assertEquals(0, requests.get());
            }
        }
    }

    @Test
    void keepsPlaintextAsTheDefaultAndClosesTheConnectionPool() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        try (LocalServer server =
                LocalServer.http(
                        exchange -> {
                            requests.incrementAndGet();
                            exchange.getRequestBody().readAllBytes();
                            exchange.sendResponseHeaders(200, -1);
                        })) {
            StatusNotifierNotificationProperties config = properties(server.url());
            assertFalse(config.isMtlsEnabled());
            RestClientManager client = new RestClientManager(config);
            try (client) {
                post(client, RestClientManager.NotificationType.TASK, null);
                assertEquals(1, requests.get());
            }
            assertThrows(
                    IllegalStateException.class,
                    () -> post(client, RestClientManager.NotificationType.TASK, null));
            assertEquals(1, requests.get());
        }
    }

    private static StatusNotifierNotificationProperties mtlsProperties(String url) {
        StatusNotifierNotificationProperties config = properties(url);
        config.setMtlsEnabled(true);
        config.setTlsKeyStorePath(certificates.keyStore().toString());
        config.setTlsTrustStorePath(certificates.trustStore().toString());
        config.setTlsPasswordFilePath(certificates.passwordFile().toString());
        return config;
    }

    private static StatusNotifierNotificationProperties properties(String url) {
        StatusNotifierNotificationProperties config = new StatusNotifierNotificationProperties();
        config.setUrl(url);
        config.setEndpointTask("tasks");
        config.setEndpointWorkflow("workflows");
        config.setHeaderDomainGroup("X-Domain-Group");
        config.setHeaderAccountCookie("X-Account");
        config.setRequestTimeOutMsConnect(5000);
        config.setRequestTimeoutMsread(5000);
        config.setRequestTimeoutMsConnMgr(5000);
        config.setRequestRetryCount(0);
        return config;
    }

    private static void post(
            RestClientManager client,
            RestClientManager.NotificationType type,
            StatusNotifier override)
            throws IOException {
        client.postNotification(
                type,
                "{\"status\":\"COMPLETED\"}",
                "domain-group",
                "account",
                "notification-id",
                override);
    }

    private record ReceivedRequest(
            String method,
            String path,
            String domainGroup,
            String account,
            String body,
            X509Certificate peer) {}

    private static final class LocalServer implements AutoCloseable {
        private final HttpServer server;
        private final String scheme;
        private final ExecutorService executor = Executors.newSingleThreadExecutor();

        private LocalServer(HttpServer server, String scheme, HttpHandler handler) {
            this.server = server;
            this.scheme = scheme;
            server.createContext(
                    "/",
                    exchange -> {
                        try {
                            handler.handle(exchange);
                        } finally {
                            exchange.close();
                        }
                    });
            server.setExecutor(executor);
            server.start();
        }

        static LocalServer http(HttpHandler handler) throws IOException {
            return new LocalServer(
                    HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0), "http", handler);
        }

        static LocalServer https(SSLContext context, HttpHandler handler) throws IOException {
            HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setHttpsConfigurator(
                    new HttpsConfigurator(context) {
                        @Override
                        public void configure(HttpsParameters parameters) {
                            SSLParameters tls = getSSLContext().getDefaultSSLParameters();
                            tls.setNeedClientAuth(true);
                            parameters.setSSLParameters(tls);
                        }
                    });
            return new LocalServer(server, "https", handler);
        }

        String url() {
            return scheme + "://localhost:" + server.getAddress().getPort();
        }

        @Override
        public void close() throws InterruptedException {
            server.stop(0);
            executor.shutdownNow();
            assertTrue(
                    executor.awaitTermination(5, TimeUnit.SECONDS),
                    "HTTP test server executor must terminate");
        }
    }
}
