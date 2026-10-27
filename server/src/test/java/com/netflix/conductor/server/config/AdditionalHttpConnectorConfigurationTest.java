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
package com.netflix.conductor.server.config;

import org.apache.catalina.connector.Connector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;

import static org.junit.jupiter.api.Assertions.*;

class AdditionalHttpConnectorConfigurationTest {

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner()
                    .withUserConfiguration(AdditionalHttpConnectorConfiguration.class);

    @Test
    void additionalListenerRequiresBothSslAndAnExplicitPort() {
        contextRunner
                .withPropertyValues("conductor.server.additional-http-port=8080")
                .run(
                        context ->
                                assertFalse(
                                        context.containsBean("additionalHttpConnectorCustomizer")));
        contextRunner
                .withPropertyValues("server.ssl.enabled=true")
                .run(
                        context ->
                                assertFalse(
                                        context.containsBean("additionalHttpConnectorCustomizer")));
    }

    @Test
    void addsPlaintextConnectorWithoutChangingThePrimaryPort() {
        contextRunner
                .withPropertyValues(
                        "server.ssl.enabled=true",
                        "server.port=8443",
                        "conductor.server.additional-http-port=8080")
                .run(
                        context -> {
                            TomcatServletWebServerFactory factory =
                                    new TomcatServletWebServerFactory(8443);
                            @SuppressWarnings("unchecked")
                            WebServerFactoryCustomizer<TomcatServletWebServerFactory> customizer =
                                    context.getBean(
                                            "additionalHttpConnectorCustomizer",
                                            WebServerFactoryCustomizer.class);
                            customizer.customize(factory);

                            assertEquals(8443, factory.getPort());
                            assertEquals(1, factory.getAdditionalTomcatConnectors().size());
                            Connector connector = factory.getAdditionalTomcatConnectors().get(0);
                            assertEquals(8080, connector.getPort());
                            assertEquals("http", connector.getScheme());
                            assertFalse(connector.getSecure());
                        });
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 65536, 8443})
    void rejectsInvalidOrDuplicatePorts(int port) {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new AdditionalHttpConnectorConfiguration()
                                .additionalHttpConnectorCustomizer(port, 8443));
    }
}
