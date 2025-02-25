/*
 * Copyright 2020 Conductor Authors.
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

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.netflix.conductor.core.config.ConductorProperties;
import com.netflix.conductor.core.dal.ExecutionDAOFacade;
import com.netflix.conductor.core.sync.Lock;
import com.netflix.conductor.redislock.lock.SimpleRedisLock;

@Configuration
@ConditionalOnProperty(
        name = "conductor.workflow-execution-lock.type",
        havingValue = "simple_redis")
public class SimpleRedisLockConfiguration {

    @Bean
    public Lock provideLock(ExecutionDAOFacade facade, ConductorProperties conductorProperties) {
        return new SimpleRedisLock(facade, conductorProperties);
    }
}
