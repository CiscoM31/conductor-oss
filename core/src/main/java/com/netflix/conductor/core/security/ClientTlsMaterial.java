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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/** A private client identity and trust snapshot, independent of JVM-wide TLS settings. */
public interface ClientTlsMaterial {

    /** Loads JKS client keys and CA trust using a password read from an absolute file path. */
    static ClientTlsMaterial loadJks(
            String keyStorePath, String trustStorePath, String passwordFilePath) {
        return new JksClientTlsMaterial(keyStorePath, trustStorePath, passwordFilePath);
    }

    /** Returns the socket factory that presents this client's certificate chain. */
    SSLSocketFactory getSocketFactory();

    /** Returns fresh TLS 1.2/1.3 parameters with HTTPS-style hostname verification enabled. */
    SSLParameters getSslParameters();

    /** Returns the explicit identity factory for transports that build their own TLS context. */
    KeyManagerFactory getKeyManagerFactory();

    /** Returns the explicit CA trust factory for transports that build their own TLS context. */
    TrustManagerFactory getTrustManagerFactory();
}
