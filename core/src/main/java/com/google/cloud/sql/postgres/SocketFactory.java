/*
 * Copyright 2016 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.cloud.sql.postgres;

import com.google.cloud.sql.core.CoreSocketFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * A Postgres {@link SocketFactory} that establishes a secure connection to a Cloud SQL instance
 * using ephemeral certificates.
 *
 * <p>The heavy lifting is done by the singleton {@link CoreSocketFactory} class.
 */
public class SocketFactory extends javax.net.SocketFactory {

  private static final Logger logger = Logger.getLogger(SocketFactory.class.getName());

  private static final String DEPRECATED_SOCKET_ARG = "SocketFactoryArg";
  private static final String POSTGRES_SUFFIX = "/.s.PGSQL.5432";

  private Properties props;

  static {
    CoreSocketFactory.addArtifactId("com.google.cloud.sql.postgres-socket-factory");
  }

  /**
   * Implements the {@link SocketFactory} constructor, which can be used to create authenticated
   * connections to a Cloud SQL instance.
   */
  public SocketFactory(Properties info) {
    String oldInstanceKey = info.getProperty(DEPRECATED_SOCKET_ARG);
    if (oldInstanceKey != null) {
      logger.warning(
          String.format(
              "The '%s' property has been deprecated. Please update your com.google.cloud.sql.postgres driver and use"
                  + "the  '%s' property in your JDBC url instead.",
              DEPRECATED_SOCKET_ARG, CoreSocketFactory.CLOUD_SQL_INSTANCE_PROPERTY));
      info.setProperty(CoreSocketFactory.CLOUD_SQL_INSTANCE_PROPERTY, oldInstanceKey);
    }
    this.props = info;
  }

  @Deprecated
  public SocketFactory(String instanceName) {
    // Deprecated constructor for converting 'SocketFactoryArg' to 'CloudSqlInstance'
    this(createDefaultProperties(instanceName));
  }

  private static Properties createDefaultProperties(String instanceName) {
    Properties info = new Properties();
    info.setProperty(DEPRECATED_SOCKET_ARG, instanceName);
    return info;
  }

  @Override
  public Socket createSocket() throws IOException {
    return CoreSocketFactory.connect(props, POSTGRES_SUFFIX);
  }

  @Override
  public Socket createSocket(String host, int port) throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
      throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Socket createSocket(InetAddress host, int port) throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
      throws IOException {
    throw new UnsupportedOperationException();
  }
}
