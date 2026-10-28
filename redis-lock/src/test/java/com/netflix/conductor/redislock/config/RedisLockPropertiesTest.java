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
package com.netflix.conductor.redislock.config;

import org.junit.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class RedisLockPropertiesTest {

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner().withUserConfiguration(PropertiesConfiguration.class);

    @Test
    public void defaultsPreservePlaintextConnections() {
        contextRunner.run(
                context -> {
                    RedisLockProperties properties = context.getBean(RedisLockProperties.class);
                    assertFalse(properties.isMtlsEnabled());
                    assertEquals("redis://127.0.0.1:6379", properties.getServerAddress());
                    assertEquals(
                            RedisLockProperties.REDIS_SERVER_TYPE.SINGLE,
                            properties.getServerType());
                    assertNull(properties.getTlsKeyStorePath());
                    assertNull(properties.getTlsTrustStorePath());
                    assertNull(properties.getTlsPasswordFilePath());
                });
    }

    @Test
    public void bindsDedicatedMtlsAndAuthenticationProperties() {
        contextRunner
                .withPropertyValues(
                        "conductor.redis-lock.mtls-enabled=true",
                        "conductor.redis-lock.server-address=rediss://localhost:6380",
                        "conductor.redis-lock.server-username=lock-user",
                        "conductor.redis-lock.server-password=test-password",
                        "conductor.redis-lock.tls-key-store-path=/tmp/test-client.jks",
                        "conductor.redis-lock.tls-trust-store-path=/tmp/test-trust.jks",
                        "conductor.redis-lock.tls-password-file-path=/tmp/test-store-password")
                .run(
                        context -> {
                            RedisLockProperties properties =
                                    context.getBean(RedisLockProperties.class);
                            assertTrue(properties.isMtlsEnabled());
                            assertEquals("rediss://localhost:6380", properties.getServerAddress());
                            assertEquals("lock-user", properties.getServerUsername());
                            assertEquals("test-password", properties.getServerPassword());
                            assertEquals("/tmp/test-client.jks", properties.getTlsKeyStorePath());
                            assertEquals("/tmp/test-trust.jks", properties.getTlsTrustStorePath());
                            assertEquals(
                                    "/tmp/test-store-password",
                                    properties.getTlsPasswordFilePath());
                        });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(RedisLockProperties.class)
    static class PropertiesConfiguration {}
}
