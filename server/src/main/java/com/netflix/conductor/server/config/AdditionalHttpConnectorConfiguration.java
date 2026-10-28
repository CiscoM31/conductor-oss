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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Adds an optional HTTP listener alongside the primary HTTPS listener. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "server.ssl.enabled", havingValue = "true")
public class AdditionalHttpConnectorConfiguration {

    @Bean
    @ConditionalOnProperty(name = "conductor.server.additional-http-port")
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory>
            additionalHttpConnectorCustomizer(
                    @Value("${conductor.server.additional-http-port}") int httpPort,
                    @Value("${server.port:8080}") int serverPort) {
        if (httpPort < 1 || httpPort > 65535 || httpPort == serverPort) {
            throw new IllegalArgumentException(
                    "conductor.server.additional-http-port must be between 1 and 65535 and differ from server.port");
        }
        return factory -> {
            Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
            connector.setScheme("http");
            connector.setPort(httpPort);
            connector.setSecure(false);
            factory.addAdditionalTomcatConnectors(connector);
        };
    }
}
