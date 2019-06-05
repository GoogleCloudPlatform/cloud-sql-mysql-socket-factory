package com.google.cloud.sql.core;

import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.util.Throwables;
import com.google.api.services.sqladmin.SQLAdmin;
import com.google.api.services.sqladmin.model.DatabaseInstance;
import com.google.api.services.sqladmin.model.IpMapping;
import com.google.api.services.sqladmin.model.SslCert;
import com.google.api.services.sqladmin.model.SslCertsCreateEphemeralRequest;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningScheduledExecutorService;
import com.google.common.util.concurrent.RateLimiter;
import com.google.common.util.concurrent.SettableFuture;
import com.google.common.util.concurrent.Uninterruptibles;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * This class manages information on and creates connections to a Cloud SQL instance using the Cloud
 * SQL Admin API. The operations to retrieve information with the API are largely done
 * asynchronously, and this class should be considered threadsafe.
 */
class CloudSqlInstance {
  private final ListeningScheduledExecutorService executor;
  private final SQLAdmin apiClient;

  private final String connectionName;
  private final String projectId;
  private final String regionId;
  private final String instanceId;
  private final KeyPair keyPair;

  private final Object instanceDataGuard = new Object();
  private ListenableFuture<InstanceData> currentInstanceData;
  private ListenableFuture<ListenableFuture<InstanceData>> nextInstanceData;
  private RateLimiter forcedRenewRateLimiter = RateLimiter.create(1.0 / 60.0);

  /**
   * Initializes a new Cloud SQL instance based on the given connection name.
   *
   * @param connectionName instance connection name in the format "PROJECT_ID:REGION_ID:INSTANCE_ID"
   * @param apiClient Cloud SQL Admin API client for interacting with the Cloud SQL instance
   * @param executor executor used to schedule asynchronous tasks
   * @param keyPair public/private key pair used to authenticate connections
   */
  CloudSqlInstance(
      String connectionName,
      SQLAdmin apiClient,
      ListeningScheduledExecutorService executor,
      KeyPair keyPair) {
    String[] connFields = connectionName.split(":");
    if (connFields.length != 3) {
      throw new IllegalArgumentException(
          "[%s] Cloud SQL connection name is invalid, expected string in the form of "
              + "\"<PROJECT_ID>:<REGION_ID>:<INSTANCE_ID>\".");
    }
    this.connectionName = connectionName;
    this.projectId = connFields[0];
    this.regionId = connFields[1];
    this.instanceId = connFields[2];

    this.apiClient = apiClient;
    this.executor = executor;
    this.keyPair = keyPair;

    // Kick off initial async jobs
    synchronized (instanceDataGuard) {
      this.scheduleRefresh(0, TimeUnit.MINUTES);
      this.blockInstanceDataOnNext();
    }
  }

  // Update currentInstanceData to block until the final result of the nextInstanceData.
  private void blockInstanceDataOnNext() {
    synchronized (instanceDataGuard) {
      SettableFuture blockingCurrent = new SettableFuture<>();
      nextInstanceData.addListener(
          () -> {
            ListenableFuture<InstanceData> scheduledRefresh = extractNestedFuture(nextInstanceData);
            blockingCurrent.setFuture(scheduledRefresh);
          },
          executor);
    }
  }

  /**
   * Returns the current data related to the instance from {@link this.performRefresh}. May block if
   * no valid data is currently available.
   */
  private InstanceData getInstanceData() {
    try {
      return Uninterruptibles.getUninterruptibly(this.currentInstanceData);
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      Throwables.propagateIfPossible(cause);
      throw Throwables.propagate(cause);
    }
  }

  /**
   * Returns an unconnected {@link SSLSocket} using the SSLContext associated with the instance. May
   * block until required instance data is available.
   */
  SSLSocket createSslSocket() throws IOException {
    return (SSLSocket) this.getInstanceData().getSslContext().getSocketFactory().createSocket();
  }

  /**
   * Returns the first IP address for the instance, in order of the preference supplied by
   * preferredTypes.
   *
   * @param preferredTypes Preferred instance IP types to use. Valid IP types include "Public" and
   *     "Private".
   * @return returns a string representing the IP address for the instance
   * @throws IllegalArgumentException If the instance has no IP addresses matching the provided
   *     preferences.
   */
  String getPreferredIp(List<String> preferredTypes) {
    String preferredIp = null;
    Map<String, String> ipAddrs = this.getInstanceData().getIpAddrs();
    for (String ipType : preferredTypes) {
      preferredIp = ipAddrs.get(ipType);
      if (preferredIp != null) {
        break;
      }
    }
    if (preferredIp == null) {
      throw new IllegalArgumentException(
          String.format(
              "[%s] Cloud SQL instance  does not have any IP addresses matching preferences (%s)",
              connectionName, String.join(", ", preferredTypes)));
    }
    return preferredIp;
  }

  /**
   * Attempts to force a new refresh of the instance data. May fail if called too frequently or if a
   * new refresh is already in progress. If successful, other methods may block until refresh has
   * been completed.
   *
   * @return {@code true} if successfully scheduled, or {@code false} if it is called too
   *     frequently.
   */
  boolean forceRefresh() {
    if (!forcedRenewRateLimiter.tryAcquire()) {
      return false; // Forced refreshing too often
    }
    synchronized (instanceDataGuard) {
      // If a scheduled Refresh already exists, cancel if if not immediately imminent
      if (nextInstanceData == null || nextInstanceData.cancel(false)) {
        // If canceled successfully, schedule a replacement immediately
        nextInstanceData = null;
        this.scheduleRefresh(0, TimeUnit.MINUTES);
      }
      // Force currentInstanceData to block until the next refresh is complete
      this.blockInstanceDataOnNext();
      return true;
    }
  }

  /**
   * Schedules an asynchronous refresh of instance data unless one is already in progress.
   *
   * @return a future that completes when the scheduled refresh begins, and returns the actual
   *     refresh operation
   */
  private ListenableFuture<ListenableFuture<InstanceData>> scheduleRefresh(
      long delay, TimeUnit timeUnit) {
    synchronized (instanceDataGuard) {
      if (this.nextInstanceData == null) { // If no refresh is already scheduled
        ListenableFuture<ListenableFuture<InstanceData>> scheduledRefresh =
            executor.schedule(this::performRefresh, delay, timeUnit);
        // Once the next refresh has been scheduled, add a listener to the result.
        scheduledRefresh.addListener(
            () -> {
              ListenableFuture<InstanceData> refresh = extractNestedFuture(scheduledRefresh);
              refresh.addListener(
                  () -> {
                    // Once complete, replace current and schedule another before the cert expires.
                    synchronized (instanceDataGuard) {
                      this.currentInstanceData = refresh;
                      this.nextInstanceData = null;
                      this.scheduleRefresh(55, TimeUnit.MINUTES);
                    }
                  },
                  executor);
            },
            executor);
        this.nextInstanceData = scheduledRefresh;
      }
      return this.nextInstanceData;
    }
  }

  /**
   * Performs an update for the instance's internal state using the Cloud SQL Admin API. This
   * refreshes information about the Cloud SQL instance, as well as the SSLContext used to
   * authenticate connections.
   */
  private ListenableFuture<InstanceData> performRefresh() {
    ListenableFuture<Metadata> metadataFuture = executor.submit(this::fetchMetadata);
    ListenableFuture<Certificate> ephemeralCertificateFuture =
        executor.submit(this::fetchEphemeralCertificate);

    ListenableFuture<SSLContext> sslContextFuture =
        whenComplete(
            () ->
                createSslContext(
                    Futures.getDone(metadataFuture), Futures.getDone(ephemeralCertificateFuture)),
            metadataFuture,
            ephemeralCertificateFuture);

    ListenableFuture<InstanceData> refreshFuture =
        whenComplete(
            () ->
                new InstanceData(
                    Futures.getDone(metadataFuture), Futures.getDone(sslContextFuture)),
            metadataFuture,
            sslContextFuture);

    return refreshFuture;
  }

  /**
   * Creates a new SSLContext based on the provided parameters. This SSLContext will be used to
   * provide new SSLSockets that are authorized to connect to a Cloud SQL instance.
   */
  private SSLContext createSslContext(Metadata metadata, Certificate ephemeralCertificate) {
    SSLContext sslContext;
    try {
      KeyStore authKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      authKeyStore.load(null, null);
      KeyStore.PrivateKeyEntry privateKey =
          new PrivateKeyEntry(keyPair.getPrivate(), new Certificate[] {ephemeralCertificate});
      authKeyStore.setEntry("ephemeral", privateKey, null);
      KeyManagerFactory kmf =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(authKeyStore, null);

      KeyStore trustedKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      trustedKeyStore.load(null, null);
      trustedKeyStore.setCertificateEntry("instance", metadata.getInstanceCaCertificate());
      TrustManagerFactory tmf = TrustManagerFactory.getInstance("X.509");
      tmf.init(trustedKeyStore);

      sslContext = SSLContext.getInstance("TLSv1.2");
      sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

    } catch (GeneralSecurityException | IOException ex) {
      // TODO(kvg): Verify this should be unchecked
      throw new RuntimeException(
          String.format(
              "[%s] Unable to create a SSLContext for the Cloud SQL instance.", connectionName),
          ex);
    }
    return sslContext;
  }

  /** Fetches the latest version of the instance's metadata using the Cloud SQL Admin API. */
  private Metadata fetchMetadata() {
    DatabaseInstance instanceMetadata;
    try {
      instanceMetadata = apiClient.instances().get(projectId, instanceId).execute();
    } catch (IOException ex) {
      throw addExceptionContext(
          ex,
          String.format("[%s] Failed to update metadata for Cloud SQL instance.", connectionName));
    }

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

    // Update the IP addresses and types need to connect with the instance.
    Map<String, String> ipAddrs = new HashMap<>();
    for (IpMapping addr : instanceMetadata.getIpAddresses()) {
      ipAddrs.put(addr.getType(), addr.getIpAddress());
    }
    if (ipAddrs.isEmpty()) {
      throw new IllegalStateException(
          String.format(
              "[%s] Unable to connect to Cloud SQL instance: instance does not have an assigned "
                  + "IP address.",
              connectionName));
    }

    // Update the Server CA certificate used to create the SSL connection with the instance.
    Certificate instanceCaCertificate;
    try {
      byte[] certBytes =
          instanceMetadata.getServerCaCert().getCert().getBytes(StandardCharsets.UTF_8);
      instanceCaCertificate =
          CertificateFactory.getInstance("X.509")
              .generateCertificate(new ByteArrayInputStream(certBytes));
    } catch (CertificateException ex) {
      throw new RuntimeException(
          String.format(
              "[%s] Unable to parse the server CA certificate for the Cloud SQL instance.",
              connectionName),
          ex);
    }

    return new Metadata(ipAddrs, instanceCaCertificate);
  }

  /**
   * Uses the Cloud SQL Admin API to create an ephemeral SSL certificate that is authenticated to
   * connect the Cloud SQL instance for up to 60 minutes.
   */
  private Certificate fetchEphemeralCertificate() {
    // Format the public key into a PEM encoded Certificate.
    StringBuilder publicKeyPemBuilder = new StringBuilder();
    publicKeyPemBuilder.append("-----BEGIN RSA PUBLIC KEY-----\n");
    publicKeyPemBuilder.append(
        Base64.getEncoder()
            .encodeToString(keyPair.getPublic().getEncoded())
            .replaceAll("(.{64})", "$1\n"));
    publicKeyPemBuilder.append("\n");
    publicKeyPemBuilder.append("-----END RSA PUBLIC KEY-----\n");

    // Use the SQL Admin API to create a new ephemeral certificate.
    SslCertsCreateEphemeralRequest request =
        new SslCertsCreateEphemeralRequest().setPublicKey(publicKeyPemBuilder.toString());
    SslCert response;
    try {
      response = apiClient.sslCerts().createEphemeral(projectId, instanceId, request).execute();
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
      byte[] certBytes = response.getCert().getBytes(StandardCharsets.UTF_8);
      ephemeralCertificate =
          CertificateFactory.getInstance("X.509")
              .generateCertificate(new ByteArrayInputStream(certBytes));
    } catch (CertificateException ex) {
      throw new RuntimeException(
          String.format(
              "[%s] Unable to parse the ephemeral certificate for the Cloud SQL instance.",
              connectionName),
          ex);
    }
    return ephemeralCertificate;
  }

  // Schedules task to be executed once the provided futures are complete.
  private <T> ListenableFuture<T> whenComplete(Callable<T> task, ListenableFuture<?>... futures) {
    SettableFuture<T> taskFuture = SettableFuture.create();

    // Create a countDown for all Futures to complete.
    AtomicInteger countDown = new AtomicInteger(futures.length);

    // Trigger the task when all futures are complete.
    Runnable runOutput =
        () -> {
          if (countDown.decrementAndGet() == 0) {
            taskFuture.setFuture(executor.submit(task));
          }
        };
    for (ListenableFuture<?> future : futures) {
      future.addListener(runOutput, executor);
    }

    return taskFuture;
  }

  // Returns the inner future from a nested future, or else the exception it encountered.
  private <T> ListenableFuture<T> extractNestedFuture(
      ListenableFuture<ListenableFuture<T>> future) {
    try {
      return Futures.getDone(future);
    } catch (ExecutionException ex) {
      return Futures.immediateFailedFuture(ex.getCause());
    }
  }

  /**
   * Checks for common errors that can occur when interacting with the Cloud SQL Admin API, and adds
   * additional context to help the user troubleshoot them.
   *
   * @param ex exception thrown by the Admin API request
   * @param fallbackDesc generic description used as a fallback if no additional information can be
   *     provided to the user
   */
  // TODO(kvg) Throw checked exceptions for recoverable states?
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
              connectionName, projectId, apiLink));
    } else if ("notAuthorized".equals(reason)) {
      // This error occurs if the instance doesn't exist or the account isn't authorized
      // TODO(kvg): Add credential account name to error string.
      return new RuntimeException(
          String.format(
              "[%s] The Cloud SQL Instance does not exist or your account is not authorized to "
                  + "access it. Please verify the instance connection name and check the IAM "
                  + "permissions for project \"%s\" ",
              connectionName, projectId));
    }
    // Fallback to the generic description
    return new RuntimeException(fallbackDesc, ex);
  }

  /** Represents the results of {@link #performRefresh()}. */
  private class InstanceData {
    private Metadata metadata;
    private SSLContext sslContext;

    InstanceData(Metadata metadata, SSLContext sslContext) {
      this.metadata = metadata;
      this.sslContext = sslContext;
    }

    SSLContext getSslContext() {
      return sslContext;
    }

    Map<String, String> getIpAddrs() {
      return metadata.getIpAddrs();
    }
  }

  /** Represents the results of @link #this.fetchMetadata(). */
  private class Metadata {
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
