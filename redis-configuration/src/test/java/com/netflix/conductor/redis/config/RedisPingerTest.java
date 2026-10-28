/*
 * Copyright 2022 Conductor Authors.
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
package com.netflix.conductor.redis.config;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.netflix.conductor.common.utils.TestTlsCertificates;
import com.netflix.conductor.core.config.ConductorProperties;
import com.netflix.dyno.connectionpool.Host;
import com.netflix.dyno.connectionpool.HostBuilder;

import static org.junit.jupiter.api.Assertions.*;

public class RedisPingerTest {

    @TempDir static Path directory;
    private static TestTlsCertificates certificates;

    @BeforeAll
    static void createCertificates() throws Exception {
        certificates = TestTlsCertificates.create(directory);
    }

    @Test
    public void testPingWithRetry() {
        RedisPinger pinger = new RedisPinger();
        long startTime = System.currentTimeMillis();
        Host host = new HostBuilder().setHostname("abcd").setPort(8080).createHost();
        boolean result = pinger.pingWithRetry(host);
        long duration = System.currentTimeMillis() - startTime;
        assertFalse(result);
        assertTrue(duration > 3000);
    }

    @Test
    void pingPresentsClientCertificateAndPreservesAclAuthentication() throws Exception {
        RedisProperties properties = new RedisProperties(new ConductorProperties());
        properties.setMtlsEnabled(true);
        properties.setUser("test-user");
        properties.setTlsKeyStorePath(certificates.keyStore().toString());
        properties.setTlsTrustStorePath(certificates.trustStore().toString());
        properties.setTlsPasswordFilePath(certificates.passwordFile().toString());
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try (SSLServerSocket server =
                (SSLServerSocket)
                        certificates
                                .serverContext()
                                .getServerSocketFactory()
                                .createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            server.setNeedClientAuth(true);
            server.setSoTimeout(10000);
            // A small RESP endpoint verifies the real TLS/authentication exchange without a
            // database.
            Future<List<String>> authentication =
                    executor.submit(
                            () -> {
                                try (SSLSocket connection = (SSLSocket) server.accept()) {
                                    connection.setSoTimeout(10000);
                                    connection.startHandshake();
                                    assertEquals(
                                            certificates.certificate().getSubjectX500Principal(),
                                            connection.getSession().getPeerPrincipal());
                                    BufferedReader reader =
                                            new BufferedReader(
                                                    new InputStreamReader(
                                                            connection.getInputStream(),
                                                            StandardCharsets.UTF_8));
                                    PrintWriter writer =
                                            new PrintWriter(
                                                    new OutputStreamWriter(
                                                            connection.getOutputStream(),
                                                            StandardCharsets.UTF_8));
                                    List<String> auth = null;
                                    String line;
                                    while ((line = reader.readLine()) != null) {
                                        assertTrue(line.startsWith("*"));
                                        int count = Integer.parseInt(line.substring(1));
                                        List<String> command = new ArrayList<>();
                                        for (int index = 0; index < count; index++) {
                                            assertTrue(reader.readLine().startsWith("$"));
                                            command.add(reader.readLine());
                                        }
                                        if ("AUTH".equalsIgnoreCase(command.getFirst())) {
                                            auth = command;
                                        }
                                        boolean ping = "PING".equalsIgnoreCase(command.getFirst());
                                        writer.print(ping ? "+PONG\r\n" : "+OK\r\n");
                                        writer.flush();
                                        if (ping) {
                                            return auth;
                                        }
                                    }
                                    throw new AssertionError("Connection closed before PING");
                                }
                            });
            Host host =
                    new HostBuilder()
                            .setHostname("localhost")
                            .setPort(server.getLocalPort())
                            .setPassword("test-password")
                            .createHost();

            assertTrue(new RedisPinger(properties).ping(host));
            assertEquals(
                    List.of("AUTH", "test-user", "test-password"),
                    authentication.get(10, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }
}
