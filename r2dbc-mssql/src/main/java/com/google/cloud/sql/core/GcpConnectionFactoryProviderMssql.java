/*
 * Copyright 2020 Google Inc. All Rights Reserved.
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

package com.google.cloud.sql.core;

import java.util.function.Function;

import io.netty.handler.ssl.SslContextBuilder;
import io.r2dbc.mssql.MssqlConnectionFactoryProvider;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryOptions;
import io.r2dbc.spi.ConnectionFactoryProvider;

import static io.r2dbc.spi.ConnectionFactoryOptions.Builder;
import static io.r2dbc.spi.ConnectionFactoryOptions.DRIVER;

/**
 * {@link ConnectionFactoryProvider} for proxied access to GCP MsSQL instances.
 */
public class GcpConnectionFactoryProviderMssql extends GcpConnectionFactoryProvider {

  static {
    CoreSocketFactory.addArtifactId("cloud-sql-connector-r2dbc-mssql");
  }

  /**
   * MsSQL driver option value.
   */
  private static final String MSSQL_DRIVER = "mssql";

  @Override
  boolean supportedProtocol(String protocol) {
    return protocol.equals(MSSQL_DRIVER);
  }

  @Override
  ConnectionFactory tcpConnectonFactory(
      Builder optionBuilder,
      Function<SslContextBuilder, SslContextBuilder> customizer,
      String csqlHostName) {
    optionBuilder
        .option(MssqlConnectionFactoryProvider.SSL_TUNNEL, customizer);

    return new CloudSqlConnectionFactory(
        (ConnectionFactoryOptions options) -> new MssqlConnectionFactoryProvider().create(options),
        optionBuilder,
        csqlHostName);
  }

  @Override
  ConnectionFactory socketConnectionFactory(Builder optionBuilder, String socket) {
    //optionBuilder.option(MssqlConnectionFactoryProvider.UNIX_SOCKET, socket).build();
    return new MssqlConnectionFactoryProvider().create(optionBuilder.build());
  }

  @Override
  Builder createBuilder(ConnectionFactoryOptions connectionFactoryOptions) {
    return connectionFactoryOptions.mutate().option(DRIVER, MSSQL_DRIVER);
  }
}
