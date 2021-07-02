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

package com.google.cloud.sql.core;

import static com.google.common.base.Preconditions.checkArgument;

import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.services.sqladmin.SQLAdmin;
import com.google.api.services.sqladmin.model.DatabaseInstance;
import com.google.api.services.sqladmin.model.IpMapping;
import com.google.api.services.sqladmin.model.SslCert;
import com.google.api.services.sqladmin.model.SslCertsCreateEphemeralRequest;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.OAuth2Credentials;
import com.google.cloud.sql.CredentialFactory;
import com.google.common.base.Throwables;
import com.google.common.io.BaseEncoding;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningScheduledExecutorService;
import com.google.common.util.concurrent.RateLimiter;
import com.google.common.util.concurrent.SettableFuture;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.errorprone.annotations.concurrent.GuardedBy;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.checkerframework.checker.nullness.compatqual.NullableDecl;

/**
 * This class manages information on and creates connections to a Cloud SQL instance using the Cloud
 * SQL Admin API. The operations to retrieve information with the API are largely done
 * asynchronously, and this class should be considered threadsafe.
 */
class CloudSqlInstance {

  private static final Logger logger = Logger.getLogger(CloudSqlInstance.class.getName());

  // Unique identifier for each Cloud SQL instance in the format "PROJECT:REGION:INSTANCE"
  // Some legacy project ids are domain-scoped (e.g. "example.com:PROJECT:REGION:INSTANCE")
  private static final Pattern CONNECTION_NAME =
      Pattern.compile("([^:]+(:[^:]+)?):([^:]+):([^:]+)");
  // defaultRefreshBuffer is the minimum amount of time for which a
  // certificate must be valid to ensure the next refresh attempt has adequate
  // time to complete.
  private static final Duration DEFAULT_REFRESH_BUFFER = Duration.ofMinutes(5);
  // iamAuthRefreshBuffer is the minimum amount of time for which a
  // certificate holding an Access Token must be valid. Because some token
  // sources are refreshed with only ~60 seconds before expiration, this value
  // must be smaller than the defaultRefreshBuffer.
  private static final Duration IAM_AUTH_REFRESH_BUFFER = Duration.ofSeconds(55);
  private final ListeningScheduledExecutorService executor;
  private final SQLAdmin apiClient;
  private final boolean enableIamAuth;
  private final Optional<OAuth2Credentials> credentials;
  private final String connectionName;
  private final String projectId;
  private final String regionId;
  private final String instanceId;
  private final String regionalizedInstanceId;
  private final ListenableFuture<KeyPair> keyPair;
  private final Object instanceDataGuard = new Object();

  @GuardedBy("instanceDataGuard")
  private ListenableFuture<InstanceData> currentInstanceData;

  @GuardedBy("instanceDataGuard")
  private ListenableFuture<ListenableFuture<InstanceData>> nextInstanceData;

  // Limit forced refreshes to 1 every minute.
  private final RateLimiter forcedRenewRateLimiter = RateLimiter.create(1.0 / 60.0);

  /**
   * Initializes a new Cloud SQL instance based on the given connection name.
   *
   * @param connectionName instance connection name in the format "PROJECT_ID:REGION_ID:INSTANCE_ID"
   * @param apiClient      Cloud SQL Admin API client for interacting with the Cloud SQL instance
   * @param executor       executor used to schedule asynchronous tasks
   * @param keyPair        public/private key pair used to authenticate connections
   */
  CloudSqlInstance(
      String connectionName,
      SQLAdmin apiClient,
      boolean enableIamAuth,
      CredentialFactory tokenSourceFactory,
      ListeningScheduledExecutorService executor,
      ListenableFuture<KeyPair> keyPair) {

    this.connectionName = connectionName;
    Matcher matcher = CONNECTION_NAME.matcher(connectionName);
    checkArgument(
        matcher.matches(),
        "[%s] Cloud SQL connection name is invalid, expected string in the form of"
            + " \"<PROJECT_ID>:<REGION_ID>:<INSTANCE_ID>\".");
    this.projectId = matcher.group(1);
    this.regionId = matcher.group(3);
    this.instanceId = matcher.group(4);
    this.regionalizedInstanceId = String.format("%s~%s", this.regionId, this.instanceId);

    this.apiClient = apiClient;
    this.enableIamAuth = enableIamAuth;
    this.executor = executor;
    this.keyPair = keyPair;

    if (enableIamAuth) {
      HttpCredentialsAdapter credentialsAdapter = (HttpCredentialsAdapter) tokenSourceFactory
          .create();
      this.credentials = Optional.of((OAuth2Credentials) credentialsAdapter.getCredentials());
    } else {
      this.credentials = Optional.empty();
    }

    // Kick off initial async jobs
    synchronized (instanceDataGuard) {
      this.currentInstanceData = performRefresh();
      this.nextInstanceData = Futures.immediateFuture(currentInstanceData);
    }
  }

  /**
   * Generates public key certificate for which the instance has the matching private key.
   *
   * @return PEM encoded public key certificate
   */
  private static String generatePublicKeyCert(KeyPair keyPair) {
    // Format the public key into a PEM encoded Certificate.
    return "-----BEGIN RSA PUBLIC KEY-----\n"
        + BaseEncoding.base64().withSeparator("\n", 64).encode(keyPair.getPublic().getEncoded())
        + "\n"
        + "-----END RSA PUBLIC KEY-----\n";
  }

  // Schedules task to be executed once the provided futures are complete.
  private static <T> ListenableFuture<T> whenAllSucceed(
      Callable<T> task,
      ListeningScheduledExecutorService executor,
      ListenableFuture<?>... futures) {
    SettableFuture<T> taskFuture = SettableFuture.create();

    // Create a countDown for all Futures to complete.
    AtomicInteger countDown = new AtomicInteger(futures.length);

    // Trigger the task when all futures are complete.
    FutureCallback<Object> runWhenInputAreComplete =
        new FutureCallback<Object>() {
          @Override
          public void onSuccess(@NullableDecl Object o) {
            if (countDown.decrementAndGet() == 0) {
              taskFuture.setFuture(executor.submit(task));
            }
          }

          @Override
          public void onFailure(Throwable throwable) {
            if (!taskFuture.setException(throwable)) {
              String msg = "Got more than one input failure. Logging failures after the first";
              logger.log(Level.SEVERE, msg, throwable);
            }
          }
        };
    for (ListenableFuture<?> future : futures) {
      Futures.addCallback(future, runWhenInputAreComplete, executor);
    }

    return taskFuture;
  }

  /**
   * Returns a future that blocks until the result of a nested future is complete.
   */
  private static <T> ListenableFuture<T> blockOnNestedFuture(
      ListenableFuture<ListenableFuture<T>> nestedFuture, ScheduledExecutorService executor) {
    SettableFuture<T> blockedFuture = SettableFuture.create();
    // Once the nested future is complete, update the blocked future to match
    Futures.addCallback(
        nestedFuture,
        new FutureCallback<ListenableFuture<T>>() {
          @Override
          public void onSuccess(ListenableFuture<T> result) {
            blockedFuture.setFuture(result);
          }

          @Override
          public void onFailure(Throwable throwable) {
            blockedFuture.setException(throwable);
          }
        },
        executor);
    return blockedFuture;
  }

  // Creates a Certificate object from a provided string.
  private static Certificate createCertificate(String cert) throws CertificateException {
    byte[] certBytes = cert.getBytes(StandardCharsets.UTF_8);
    ByteArrayInputStream certStream = new ByteArrayInputStream(certBytes);
    return CertificateFactory.getInstance("X.509").generateCertificate(certStream);
  }

  /**
   * Returns the current data related to the instance from {@link #performRefresh()}. May block if
   * no valid data is currently available.
   */
  private InstanceData getInstanceData() {
    ListenableFuture<InstanceData> instanceData;
    synchronized (instanceDataGuard) {
      instanceData = currentInstanceData;
    }
    try {
      // TODO(kvg): Let exceptions up to here before adding context
      return Uninterruptibles.getUninterruptibly(instanceData);
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      Throwables.throwIfUnchecked(cause);
      throw new RuntimeException(cause);
    }
  }

  /**
   * Returns an unconnected {@link SSLSocket} using the SSLContext associated with the instance. May
   * block until required instance data is available.
   */
  SSLSocket createSslSocket() throws IOException {
    return (SSLSocket) getInstanceData().getSslContext().getSocketFactory().createSocket();
  }

  /**
   * Returns the first IP address for the instance, in order of the preference supplied by
   * preferredTypes.
   *
   * @param preferredTypes Preferred instance IP types to use. Valid IP types include "Public" and
   *                       "Private".
   * @return returns a string representing the IP address for the instance
   * @throws IllegalArgumentException If the instance has no IP addresses matching the provided
   *                                  preferences.
   */
  String getPreferredIp(List<String> preferredTypes) {
    Map<String, String> ipAddrs = getInstanceData().getIpAddrs();
    for (String ipType : preferredTypes) {
      String preferredIp = ipAddrs.get(ipType);
      if (preferredIp != null) {
        return preferredIp;
      }
    }
    throw new IllegalArgumentException(
        String.format(
            "[%s] Cloud SQL instance  does not have any IP addresses matching preferences (%s)",
            connectionName, String.join(", ", preferredTypes)));
  }

  /**
   * Attempts to force a new refresh of the instance data. May fail if called too frequently or if a
   * new refresh is already in progress. If successful, other methods will block until refresh has
   * been completed.
   *
   * @return {@code true} if successfully scheduled, or {@code false} otherwise.
   */
  boolean forceRefresh() {
    if (!forcedRenewRateLimiter.tryAcquire()) {
      return false;
    }
    synchronized (instanceDataGuard) {
      // If a scheduled refresh hasn't started, perform one immediately
      if (nextInstanceData.cancel(false)) {
        currentInstanceData = performRefresh();
        nextInstanceData = Futures.immediateFuture(currentInstanceData);
      } else {
        // Otherwise it's already running, so just block on the results
        currentInstanceData = blockOnNestedFuture(nextInstanceData, executor);
      }
      return true;
    }
  }

  /**
   * Triggers an update of internal information obtained from the Cloud SQL Admin API. Replaces the
   * value of currentInstanceData and schedules the next refresh shortly before the information
   * would expire.
   */
  private ListenableFuture<InstanceData> performRefresh() {
    // Use the Cloud SQL Admin API to return the Metadata and Certificate
    ListenableFuture<Metadata> metadataFuture = executor.submit(this::fetchMetadata);
    ListenableFuture<Certificate> ephemeralCertificateFuture =
        whenAllSucceed(
            () -> fetchEphemeralCertificate(Futures.getDone(keyPair)), executor, keyPair);
    // Once the API calls are complete, construct the SSLContext for the sockets
    ListenableFuture<SslData> sslContextFuture =
        whenAllSucceed(
            () ->
                createSslData(
                    Futures.getDone(keyPair),
                    Futures.getDone(metadataFuture),
                    Futures.getDone(ephemeralCertificateFuture)),
            executor,
            keyPair,
            metadataFuture,
            ephemeralCertificateFuture);
    // Once both the SSLContext and Metadata are complete, return the results
    ListenableFuture<InstanceData> refreshFuture =
        whenAllSucceed(
            () -> {

              // Get expiration value for new cert
              Certificate ephemeralCertificate = Futures.getDone(ephemeralCertificateFuture);
              X509Certificate x509Certificate = (X509Certificate) ephemeralCertificate;
              Date expiration = x509Certificate.getNotAfter();

              if (enableIamAuth) {
                Date tokenExpiration = getTokenExpirationTime();
                if (expiration.after(tokenExpiration)) {
                  expiration = tokenExpiration;
                }
              }

              return new InstanceData(
                  Futures.getDone(metadataFuture), Futures.getDone(sslContextFuture),
                  expiration);
            },
            executor,
            metadataFuture,
            sslContextFuture);
    refreshFuture.addListener(
        () -> {
          synchronized (instanceDataGuard) {
            // update currentInstanceData with the most recent results
            currentInstanceData = refreshFuture;
            // schedule a replacement before the SSLContext expires;
            nextInstanceData = executor
                .schedule(this::performRefresh, secondsUntilRefresh(),
                    TimeUnit.SECONDS);
          }
        },
        executor);
    return refreshFuture;
  }

  /**
   * Creates a new SslData based on the provided parameters. It contains a SSLContext that will be
   * used to provide new SSLSockets authorized to connect to a Cloud SQL instance. It also contains
   * a KeyManagerFactory and a TrustManagerFactory that can be used by drivers to establish an SSL
   * tunnel.
   */
  private SslData createSslData(
      KeyPair keyPair, Metadata metadata, Certificate ephemeralCertificate) {
    try {
      KeyStore authKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      authKeyStore.load(null, null);
      KeyStore.PrivateKeyEntry privateKey =
          new PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{ephemeralCertificate});
      authKeyStore.setEntry("ephemeral", privateKey, new PasswordProtection(new char[0]));
      KeyManagerFactory kmf =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(authKeyStore, new char[0]);

      KeyStore trustedKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      trustedKeyStore.load(null, null);
      trustedKeyStore.setCertificateEntry("instance", metadata.getInstanceCaCertificate());
      TrustManagerFactory tmf = TrustManagerFactory.getInstance("X.509");
      tmf.init(trustedKeyStore);
      SSLContext sslContext;
      if (enableIamAuth) {
        try {
          sslContext = SSLContext.getInstance("TLSv1.3");
        } catch (NoSuchAlgorithmException ex) {
          throw new RuntimeException(
              String.format(
                  "[%s] Unable to create a SSLContext for the Cloud SQL instance.", connectionName)
                  + " TLSv1.3 is not supported for your Java version and is required to connect"
                  + " using IAM authentication",
              ex);
        }
      } else {
        sslContext = SSLContext.getInstance("TLSv1.2");
      }

      sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

      return new SslData(sslContext, kmf, tmf);
    } catch (GeneralSecurityException | IOException ex) {
      throw new RuntimeException(
          String.format(
              "[%s] Unable to create a SSLContext for the Cloud SQL instance.", connectionName),
          ex);
    }
  }

  /**
   * Fetches the latest version of the instance's metadata using the Cloud SQL Admin API.
   */
  private Metadata fetchMetadata() {
    try {
      DatabaseInstance instanceMetadata =
          apiClient.instances().get(projectId, regionalizedInstanceId).execute();

      // Validate the instance will support the authenticated connection.
      if (!instanceMetadata.getRegion().equals(regionId)) {
        throw new IllegalArgumentException(
            String.format(
                "[%s] The region specified for the Cloud SQL instance is"
                    + " incorrect. Please verify the instance connection name.",
                connectionName));
      }
      if (!instanceMetadata.getBackendType().equals("SECOND_GEN")) {
        throw new IllegalArgumentException(
            String.format(
                "[%s] Connections to Cloud SQL instance not supported - not a Second Generation "
                    + "instance.",
                connectionName));
      }

      // Verify the instance has at least one IP type assigned that can be used to connect.
      if (instanceMetadata.getIpAddresses().isEmpty()) {
        throw new IllegalStateException(
            String.format(
                "[%s] Unable to connect to Cloud SQL instance: instance does not have an assigned "
                    + "IP address.",
                connectionName));
      }
      // Update the IP addresses and types need to connect with the instance.
      Map<String, String> ipAddrs = new HashMap<>();
      for (IpMapping addr : instanceMetadata.getIpAddresses()) {
        ipAddrs.put(addr.getType(), addr.getIpAddress());
      }

      // Update the Server CA certificate used to create the SSL connection with the instance.
      try {
        Certificate instanceCaCertificate =
            createCertificate(instanceMetadata.getServerCaCert().getCert());
        return new Metadata(ipAddrs, instanceCaCertificate);
      } catch (CertificateException ex) {
        throw new RuntimeException(
            String.format(
                "[%s] Unable to parse the server CA certificate for the Cloud SQL instance.",
                connectionName),
            ex);
      }
    } catch (IOException ex) {
      throw addExceptionContext(
          ex,
          String.format("[%s] Failed to update metadata for Cloud SQL instance.", connectionName));
    }
  }

  /**
   * Uses the Cloud SQL Admin API to create an ephemeral SSL certificate that is authenticated to
   * connect the Cloud SQL instance for up to 60 minutes.
   */
  private Certificate fetchEphemeralCertificate(KeyPair keyPair) {

    // Use the SQL Admin API to create a new ephemeral certificate.
    SslCertsCreateEphemeralRequest request =
        new SslCertsCreateEphemeralRequest().setPublicKey(generatePublicKeyCert(keyPair));

    if (enableIamAuth) {
      try {
        credentials.get().refresh();
        String token = credentials.get().getAccessToken().getTokenValue();
        request.setAccessToken(token);
      } catch (IOException ex) {
        throw addExceptionContext(
            ex,
            "An exception occurred while fetching IAM auth token:");
      }
    }
    SslCert response;
    try {
      response = apiClient.sslCerts().createEphemeral(projectId, regionalizedInstanceId, request)
          .execute();
    } catch (IOException ex) {
      throw addExceptionContext(
          ex,
          String.format(
              "[%s] Failed to create ephemeral certificate for the Cloud SQL instance.",
              connectionName));
    }

    // Parse the certificate from the response.
    Certificate ephemeralCertificate;
    try {
      ephemeralCertificate = createCertificate(response.getCert());
    } catch (CertificateException ex) {
      throw new RuntimeException(
          String.format(
              "[%s] Unable to parse the ephemeral certificate for the Cloud SQL instance.",
              connectionName),
          ex);
    }

    return ephemeralCertificate;
  }

  private Date getTokenExpirationTime() {
    return credentials.get().getAccessToken().getExpirationTime();
  }

  private long secondsUntilRefresh() {
    // 55 minutes
    Duration refreshBuffer = enableIamAuth ? IAM_AUTH_REFRESH_BUFFER : DEFAULT_REFRESH_BUFFER;

    Date expiration = getInstanceData().getExpiration();

    Duration timeUntilRefresh = Duration.between(Instant.now(), expiration.toInstant())
        .minus(refreshBuffer);

    if (timeUntilRefresh.isNegative()) {
      // If the time until the certificate expires is less than the buffer, schedule the refresh
      // closer to the expiration time
      timeUntilRefresh = Duration.between(Instant.now(), expiration.toInstant())
          .minus(Duration.ofSeconds(5));
    }
    return timeUntilRefresh.getSeconds();
  }

  /**
   * Checks for common errors that can occur when interacting with the Cloud SQL Admin API, and adds
   * additional context to help the user troubleshoot them.
   *
   * @param ex           exception thrown by the Admin API request
   * @param fallbackDesc generic description used as a fallback if no additional information can be
   *                     provided to the user
   */
  private RuntimeException addExceptionContext(IOException ex, String fallbackDesc) {
    // Verify we are able to extract a reason from an exception, or fallback to a generic desc
    GoogleJsonResponseException gjrEx =
        ex instanceof GoogleJsonResponseException ? (GoogleJsonResponseException) ex : null;
    if (gjrEx == null
        || gjrEx.getDetails() == null
        || gjrEx.getDetails().getErrors() == null
        || gjrEx.getDetails().getErrors().isEmpty()) {
      return new RuntimeException(fallbackDesc, ex);
    }
    // Check for commonly occurring user errors and add additional context
    String reason = gjrEx.getDetails().getErrors().get(0).getReason();
    if ("accessNotConfigured".equals(reason)) {
      // This error occurs when the project doesn't have the "Cloud SQL Admin API" enabled
      String apiLink =
          "https://console.cloud.google.com/apis/api/sqladmin/overview?project=" + projectId;
      return new RuntimeException(
          String.format(
              "[%s] The Google Cloud SQL Admin API is not enabled for the project \"%s\". Please "
                  + "use the Google Developers Console to enable it: %s",
              connectionName, projectId, apiLink),
          ex);
    } else if ("notAuthorized".equals(reason)) {
      // This error occurs if the instance doesn't exist or the account isn't authorized
      // TODO(kvg): Add credential account name to error string.
      return new RuntimeException(
          String.format(
              "[%s] The Cloud SQL Instance does not exist or your account is not authorized to "
                  + "access it. Please verify the instance connection name and check the IAM "
                  + "permissions for project \"%s\" ",
              connectionName, projectId),
          ex);
    }
    // Fallback to the generic description
    return new RuntimeException(fallbackDesc, ex);
  }

  SslData getSslData() {
    return getInstanceData().getSslData();
  }

  /**
   * Represents the results of {@link #performRefresh()}.
   */
  private static class InstanceData {

    private final Metadata metadata;
    private final SSLContext sslContext;
    private final SslData sslData;
    private final Date expiration;

    InstanceData(Metadata metadata, SslData sslData, Date expiration) {
      this.metadata = metadata;
      this.sslData = sslData;
      this.sslContext = sslData.getSslContext();
      this.expiration = expiration;
    }

    Date getExpiration() {
      return expiration;
    }

    SSLContext getSslContext() {
      return sslContext;
    }

    Map<String, String> getIpAddrs() {
      return metadata.getIpAddrs();
    }

    SslData getSslData() {
      return sslData;
    }
  }

  /**
   * Represents the results of @link #fetchMetadata().
   */
  private static class Metadata {

    private final Map<String, String> ipAddrs;
    private final Certificate instanceCaCertificate;

    Metadata(Map<String, String> ipAddrs, Certificate instanceCaCertificate) {
      this.ipAddrs = ipAddrs;
      this.instanceCaCertificate = instanceCaCertificate;
    }

    Map<String, String> getIpAddrs() {
      return ipAddrs;
    }

    Certificate getInstanceCaCertificate() {
      return instanceCaCertificate;
    }
  }
}
