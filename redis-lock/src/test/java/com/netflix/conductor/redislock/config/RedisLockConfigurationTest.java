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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import com.netflix.conductor.redislock.config.RedisLockProperties.REDIS_SERVER_TYPE;

import static org.junit.jupiter.api.Assertions.*;

class RedisLockConfigurationTest {

    @ParameterizedTest
    @EnumSource(REDIS_SERVER_TYPE.class)
    void mtlsRejectsPlaintextBeforeCreatingConnections(REDIS_SERVER_TYPE serverType) {
        RedisLockProperties properties = new RedisLockProperties();
        properties.setMtlsEnabled(true);
        properties.setServerType(serverType);
        properties.setServerAddress("redis://localhost:6379");

        IllegalStateException error =
                assertThrows(
                        IllegalStateException.class,
                        () -> new RedisLockConfiguration().getRedisson(properties));
        assertTrue(error.getMessage().contains("requires rediss://"));
    }

    @ParameterizedTest
    @EnumSource(
            value = REDIS_SERVER_TYPE.class,
            names = {"CLUSTER", "SENTINEL"})
    void mtlsRejectsMixedAddressLists(REDIS_SERVER_TYPE serverType) {
        RedisLockProperties properties = new RedisLockProperties();
        properties.setMtlsEnabled(true);
        properties.setServerType(serverType);
        String delimiter = serverType == REDIS_SERVER_TYPE.SENTINEL ? ";" : ",";
        properties.setServerAddress(
                "rediss://localhost:6380" + delimiter + "redis://localhost:6379");

        IllegalStateException error =
                assertThrows(
                        IllegalStateException.class,
                        () -> new RedisLockConfiguration().getRedisson(properties));
        assertTrue(error.getMessage().contains("requires rediss://"));
    }

    @Test
    void mtlsRequiresClientMaterialEvenWithASecureAddress() {
        RedisLockProperties properties = new RedisLockProperties();
        properties.setMtlsEnabled(true);
        properties.setServerAddress("rediss://localhost:6380");

        IllegalStateException error =
                assertThrows(
                        IllegalStateException.class,
                        () -> new RedisLockConfiguration().getRedisson(properties));
        assertEquals("Unable to initialize private client mTLS material", error.getMessage());
    }
}
