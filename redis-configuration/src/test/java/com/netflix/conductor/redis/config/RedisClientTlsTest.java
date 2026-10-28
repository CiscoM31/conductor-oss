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
package com.netflix.conductor.redis.config;

import java.nio.file.Path;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.netflix.conductor.common.utils.TestTlsCertificates;
import com.netflix.conductor.core.config.ConductorProperties;
import com.netflix.conductor.core.security.ClientTlsMaterial;

import redis.clients.jedis.DefaultJedisClientConfig;

import static org.junit.jupiter.api.Assertions.*;

class RedisClientTlsTest {

    @TempDir static Path directory;
    private static TestTlsCertificates certificates;

    @BeforeAll
    static void createCertificates() throws Exception {
        certificates = TestTlsCertificates.create(directory);
    }

    @Test
    void disabledMtlsDoesNotReadStoresOrChangePlaintextConfiguration() {
        RedisProperties properties = new RedisProperties(new ConductorProperties());
        properties.setTlsKeyStorePath("/missing/client.jks");
        DefaultJedisClientConfig.Builder builder = DefaultJedisClientConfig.builder();

        assertNull(RedisClientTls.load(properties));
        RedisClientTls.apply(builder, null);
        assertFalse(builder.build().isSsl());
    }

    @Test
    void mtlsEnablesTlsAndHostnameVerificationWithoutChangingAuthentication() {
        RedisProperties properties = new RedisProperties(new ConductorProperties());
        properties.setMtlsEnabled(true);
        properties.setTlsKeyStorePath(certificates.keyStore().toString());
        properties.setTlsTrustStorePath(certificates.trustStore().toString());
        properties.setTlsPasswordFilePath(certificates.passwordFile().toString());
        ClientTlsMaterial material = RedisClientTls.load(properties);
        DefaultJedisClientConfig.Builder builder =
                DefaultJedisClientConfig.builder().user("test-user").password("test-password");

        RedisClientTls.apply(builder, material);
        DefaultJedisClientConfig config = builder.build();

        assertTrue(config.isSsl());
        assertNotNull(config.getSslSocketFactory());
        assertEquals("HTTPS", config.getSslParameters().getEndpointIdentificationAlgorithm());
        assertArrayEquals(
                new String[] {"TLSv1.3", "TLSv1.2"}, config.getSslParameters().getProtocols());
        assertEquals("test-user", config.getUser());
        assertEquals("test-password", config.getPassword());
    }

    @Test
    void mtlsRejectsDisabledCertificateVerification() {
        RedisProperties properties = new RedisProperties(new ConductorProperties());
        properties.setMtlsEnabled(true);
        properties.setIgnoreSsl(true);

        IllegalStateException error =
                assertThrows(IllegalStateException.class, () -> RedisClientTls.load(properties));
        assertTrue(error.getMessage().contains("ignoreSsl=false"));
    }
}
