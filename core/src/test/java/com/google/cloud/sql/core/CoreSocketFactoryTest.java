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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.json.GoogleJsonError;
import com.google.api.client.googleapis.json.GoogleJsonError.ErrorInfo;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.HttpBackOffIOExceptionHandler;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.Json;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.testing.http.HttpTesting;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.api.client.util.ExponentialBackOff;
import com.google.api.services.sqladmin.SQLAdmin;
import com.google.api.services.sqladmin.model.DatabaseInstance;
import com.google.api.services.sqladmin.model.IpMapping;
import com.google.api.services.sqladmin.model.SslCert;
import com.google.api.services.sqladmin.model.SslCertsCreateEphemeralRequest;
import com.google.cloud.sql.CredentialFactory;
import com.google.common.collect.ImmutableList;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningScheduledExecutorService;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

// TODO(berezv): add multithreaded test
@RunWith(JUnit4.class)
public class CoreSocketFactoryTest {

  private static final String SERVER_MESSAGE = "HELLO";

  private static final String PUBLIC_IP = "127.0.0.1";
  private static final String PRIVATE_IP = "127.0.1.1";

  // TODO(kvg): Remove this when updating tests to use single CoreSocketFactory
  private ListeningScheduledExecutorService defaultExecutor;
  @Mock
  private CredentialFactory credentialFactory;
  @Mock
  private GoogleCredential credential;
  @Mock
  private HttpRequest httpRequest;
  @Mock
  private HttpResponse httpResponse;
  @Mock
  private SQLAdmin adminApi;
  @Mock
  private SQLAdmin.Instances adminApiInstances;
  @Mock
  private SQLAdmin.Instances.Get adminApiInstancesGet;
  @Mock
  private SQLAdmin.SslCerts adminApiSslCerts;
  @Mock
  private SQLAdmin.SslCerts.CreateEphemeral adminApiSslCertsCreateEphemeral;

  private ListenableFuture<KeyPair> clientKeyPair;

  // Creates a fake "accessNotConfigured" exception that can be used for testing.
  private static GoogleJsonResponseException fakeNotConfiguredException() throws IOException {
    return fakeGoogleJsonResponseException(
        HttpStatusCodes.STATUS_CODE_FORBIDDEN,
        "accessNotConfigured",
        "Cloud SQL Admin API has not been used in project 12345 before or it is disabled. Enable"
            + " it by visiting "
            + " https://console.developers.google.com/apis/api/sqladmin.googleapis.com/overview?project=12345"
            + " then retry. If you enabled this API recently, wait a few minutes for the action to"
            + " propagate to our systems and retry.");
  }

  // Creates a fake "notAuthorized" exception that can be used for testing.
  private static GoogleJsonResponseException fakeNotAuthorizedException() throws IOException {
    return fakeGoogleJsonResponseException(
        HttpStatusCodes.STATUS_CODE_FORBIDDEN,
        "notAuthorized",
        "The client is not authorized to make this request");
  }

  // Builds a fake GoogleJsonResponseException for testing API error handling.
  private static GoogleJsonResponseException fakeGoogleJsonResponseException(
      int httpStatus, String reason, String message) throws IOException {
    ErrorInfo errorInfo = new ErrorInfo();
    errorInfo.setReason(reason);
    errorInfo.setMessage(message);
    return fakeGoogleJsonResponseException(httpStatus, errorInfo, message);
  }

  private static GoogleJsonResponseException fakeGoogleJsonResponseException(
      int status, ErrorInfo errorInfo, String message) throws IOException {
    final JsonFactory jsonFactory = new JacksonFactory();
    HttpTransport transport =
        new MockHttpTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            errorInfo.setFactory(jsonFactory);
            GoogleJsonError jsonError = new GoogleJsonError();
            jsonError.setCode(status);
            jsonError.setErrors(Collections.singletonList(errorInfo));
            jsonError.setMessage(message);
            jsonError.setFactory(jsonFactory);
            GenericJson errorResponse = new GenericJson();
            errorResponse.set("error", jsonError);
            errorResponse.setFactory(jsonFactory);
            return new MockLowLevelHttpRequest()
                .setResponse(
                    new MockLowLevelHttpResponse()
                        .setContent(errorResponse.toPrettyString())
                        .setContentType(Json.MEDIA_TYPE)
                        .setStatusCode(status));
          }
        };
    HttpRequest request =
        transport.createRequestFactory().buildGetRequest(HttpTesting.SIMPLE_GENERIC_URL);
    request.setThrowExceptionOnExecuteError(false);
    HttpResponse response = request.execute();
    return GoogleJsonResponseException.from(jsonFactory, response);
  }

  private static byte[] decodeBase64StripWhitespace(String b64) {
    return Base64.getDecoder().decode(b64.replaceAll("\\s", ""));
  }

  @Before
  public void setup() throws IOException, GeneralSecurityException, ExecutionException {
    MockitoAnnotations.openMocks(this);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec privateKeySpec =
        new PKCS8EncodedKeySpec(decodeBase64StripWhitespace(TestKeys.CLIENT_PRIVATE_KEY));
    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

    X509EncodedKeySpec publicKeySpec =
        new X509EncodedKeySpec(decodeBase64StripWhitespace(TestKeys.CLIENT_PUBLIC_KEY));
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

    clientKeyPair = Futures.immediateFuture(new KeyPair(publicKey, privateKey));

    defaultExecutor = CoreSocketFactory.getDefaultExecutor();

    // Stub the API client for testing
    when(adminApi.instances()).thenReturn(adminApiInstances);

    // Stub when generic cases for project/instance
    when(adminApiInstances.get(anyString(), anyString())).thenThrow(fakeNotConfiguredException());
    // Stub when correct project, but generic instance
    when(adminApiInstances.get(eq("myProject"), anyString()))
        .thenThrow(fakeNotAuthorizedException());

    // Stub when correct instance
    when(adminApiInstances.get(eq("myProject"), eq("myInstance"))).thenReturn(adminApiInstancesGet);
    when(adminApiInstances.get(eq("example.com:myProject"), eq("myInstance")))
        .thenReturn(adminApiInstancesGet);

    // Prefixing the region to the instance name is considered valid
    when(adminApiInstances.get(eq("myProject"), eq("myRegion~myInstance")))
        .thenReturn(adminApiInstancesGet);
    when(adminApiInstances.get(eq("myProject"), eq("notMyRegion~myInstance")))
        .thenReturn(adminApiInstancesGet);
    when(adminApiInstances.get(eq("example.com:myProject"), eq("myRegion~myInstance")))
        .thenReturn(adminApiInstancesGet);

    when(adminApiInstancesGet.buildHttpRequest()).thenReturn(httpRequest);
    when(httpRequest
        .setIOExceptionHandler(new HttpBackOffIOExceptionHandler(new ExponentialBackOff())))
        .thenReturn(httpRequest);

    when(adminApi.sslCerts()).thenReturn(adminApiSslCerts);
    when(adminApiSslCerts.createEphemeral(
        anyString(), anyString(), isA(SslCertsCreateEphemeralRequest.class)))
        .thenReturn(adminApiSslCertsCreateEphemeral);

    when(adminApiInstancesGet.buildHttpRequest()).thenReturn(httpRequest);
    when(adminApiSslCertsCreateEphemeral.buildHttpRequest()).thenReturn(httpRequest);
    when(httpRequest
        .setIOExceptionHandler(new HttpBackOffIOExceptionHandler(new ExponentialBackOff())))
        .thenReturn(httpRequest);
    when(adminApiInstancesGet.getResponseClass()).thenReturn(DatabaseInstance.class);
    when(adminApiSslCertsCreateEphemeral.getResponseClass()).thenReturn(SslCert.class);
    when(httpRequest.execute()).thenReturn(httpResponse);
    when(httpResponse.parseAs(adminApiInstancesGet.getResponseClass()))
        .thenReturn(
            new DatabaseInstance()
                .setBackendType("SECOND_GEN")
                .setIpAddresses(
                    ImmutableList.of(
                        new IpMapping().setIpAddress(PUBLIC_IP).setType("PRIMARY"),
                        new IpMapping().setIpAddress(PRIVATE_IP).setType("PRIVATE")))
                .setServerCaCert(new SslCert().setCert(TestKeys.SERVER_CA_CERT))
                .setRegion("myRegion"));
    when(httpResponse.parseAs(adminApiSslCertsCreateEphemeral.getResponseClass()))
        .thenReturn(new SslCert().setCert(createEphemeralCert(Duration.ofSeconds(0))));
  }

  @Test
  public void create_throwsErrorForInvalidInstanceName() throws IOException {
    CoreSocketFactory coreSocketFactory =
        new CoreSocketFactory(clientKeyPair, adminApi, credentialFactory, 3307, defaultExecutor);
    try {
      coreSocketFactory.createSslSocket("myProject", Arrays.asList("PRIMARY"));
      fail();
    } catch (IllegalArgumentException e) {
      assertThat(e).hasMessageThat().contains("Cloud SQL connection name is invalid");
    }

    try {
      coreSocketFactory.createSslSocket("myProject:myRegion", Arrays.asList("PRIMARY"));
      fail();
    } catch (IllegalArgumentException e) {
      assertThat(e).hasMessageThat().contains("Cloud SQL connection name is invalid");
    }
  }

  @Test
  public void create_throwsErrorForInvalidInstanceRegion() throws IOException {
    CoreSocketFactory coreSocketFactory =
        new CoreSocketFactory(clientKeyPair, adminApi, credentialFactory, 3307, defaultExecutor);
    try {
      coreSocketFactory.createSslSocket(
          "myProject:notMyRegion:myInstance", Arrays.asList("PRIMARY"));
      fail();
    } catch (IllegalArgumentException e) {
      assertThat(e)
          .hasMessageThat()
          .contains("The region specified for the Cloud SQL instance is incorrect");
    }
  }

  /**
   * Start an SSL server on the private IP, and verifies that specifying a preference for private IP
   * results in a connection to the private IP.
   */
  @Test
  public void create_successfulPrivateConnection()
      throws IOException, GeneralSecurityException, InterruptedException {
    FakeSslServer sslServer = new FakeSslServer();
    int port = sslServer.start(PRIVATE_IP);

    CoreSocketFactory coreSocketFactory =
        new CoreSocketFactory(clientKeyPair, adminApi, credentialFactory, port, defaultExecutor);
    Socket socket =
        coreSocketFactory.createSslSocket(
            "myProject:myRegion:myInstance", Arrays.asList("PRIVATE"));

    verify(adminApiInstances).get("myProject", "myRegion~myInstance");
    verify(adminApiSslCerts)
        .createEphemeral(
            eq("myProject"), eq("myRegion~myInstance"), isA(SslCertsCreateEphemeralRequest.class));

    BufferedReader bufferedReader =
        new BufferedReader(new InputStreamReader(socket.getInputStream(), UTF_8));
    String line = bufferedReader.readLine();
    assertThat(line).isEqualTo(SERVER_MESSAGE);
  }

  @Test
  public void create_successfulConnection() throws IOException, InterruptedException {
    FakeSslServer sslServer = new FakeSslServer();
    int port = sslServer.start();

    CoreSocketFactory coreSocketFactory =
        new CoreSocketFactory(clientKeyPair, adminApi, credentialFactory, port, defaultExecutor);
    Socket socket =
        coreSocketFactory.createSslSocket(
            "myProject:myRegion:myInstance", Arrays.asList("PRIMARY"));

    verify(adminApiInstances).get("myProject", "myRegion~myInstance");
    verify(adminApiSslCerts)
        .createEphemeral(
            eq("myProject"), eq("myRegion~myInstance"), isA(SslCertsCreateEphemeralRequest.class));

    BufferedReader bufferedReader =
        new BufferedReader(new InputStreamReader(socket.getInputStream(), UTF_8));
    String line = bufferedReader.readLine();
    assertThat(line).isEqualTo(SERVER_MESSAGE);
  }

  @Test
  public void create_successfulDomainScopedConnection() throws IOException, InterruptedException {
    FakeSslServer sslServer = new FakeSslServer();
    int port = sslServer.start();

    CoreSocketFactory coreSocketFactory =
        new CoreSocketFactory(clientKeyPair, adminApi, credentialFactory, port, defaultExecutor);
    Socket socket =
        coreSocketFactory.createSslSocket(
            "example.com:myProject:myRegion:myInstance", Arrays.asList("PRIMARY"));

    verify(adminApiInstances).get("example.com:myProject", "myRegion~myInstance");
    verify(adminApiSslCerts)
        .createEphemeral(
            eq("example.com:myProject"), eq("myRegion~myInstance"),
            isA(SslCertsCreateEphemeralRequest.class));

    BufferedReader bufferedReader =
        new BufferedReader(new InputStreamReader(socket.getInputStream(), UTF_8));
    String line = bufferedReader.readLine();
    assertThat(line).isEqualTo(SERVER_MESSAGE);
  }

  @Test
  @Ignore
  // test disabled because the connection to the test server produces a different error than when
  // connecting to the real thing.
  // TODO(berezv): figure out why the test server produces a different error on an expired
  // certificate
  public void create_expiredCertificateOnFirstConnection_certificateRenewed()
      throws IOException, GeneralSecurityException, ExecutionException, InterruptedException {
    FakeSslServer sslServer = new FakeSslServer();
    int port = sslServer.start();

    // Certificate already expired.
    when(adminApiSslCertsCreateEphemeral.execute())
        .thenReturn(new SslCert().setCert(createEphemeralCert(Duration.ofMinutes(65))));

    CoreSocketFactory coreSocketFactory =
        new CoreSocketFactory(clientKeyPair, adminApi, credentialFactory, port, defaultExecutor);
    Socket socket =
        coreSocketFactory.createSslSocket(
            "myProject:myRegion:myInstance", Arrays.asList("PRIMARY"));

    verify(adminApiInstances, times(2)).get("myProject", "myRegion~myInstance");
    verify(adminApiSslCerts, times(2))
        .createEphemeral(
            eq("myProject"), eq("myRegion~myInstance"), isA(SslCertsCreateEphemeralRequest.class));

    BufferedReader bufferedReader =
        new BufferedReader(new InputStreamReader(socket.getInputStream(), UTF_8));
    String line = bufferedReader.readLine();
    assertThat(line).isEqualTo(SERVER_MESSAGE);
  }

  @Test
  public void create_certificateReusedIfNotExpired() throws IOException, InterruptedException {
    FakeSslServer sslServer = new FakeSslServer();
    int port = sslServer.start();

    CoreSocketFactory coreSocketFactory =
        new CoreSocketFactory(clientKeyPair, adminApi, credentialFactory, port, defaultExecutor);
    coreSocketFactory.createSslSocket("myProject:myRegion:myInstance", Arrays.asList("PRIMARY"));

    verify(adminApiInstances).get("myProject", "myRegion~myInstance");
    verify(adminApiSslCerts)
        .createEphemeral(
            eq("myProject"), eq("myRegion~myInstance"), isA(SslCertsCreateEphemeralRequest.class));

    coreSocketFactory.createSslSocket("myProject:myRegion:myInstance", Arrays.asList("PRIMARY"));

    verifyNoMoreInteractions(adminApiInstances);
    verifyNoMoreInteractions(adminApiSslCerts);
  }

  @Test
  public void create_adminApiNotEnabled() throws IOException {
    CoreSocketFactory coreSocketFactory =
        new CoreSocketFactory(clientKeyPair, adminApi, credentialFactory, 3307, defaultExecutor);
    try {
      // Use a different project to get Api Not Enabled Error.
      coreSocketFactory.createSslSocket(
          "NotMyProject:myRegion:myInstance", Arrays.asList("PRIMARY"));
      fail("Expected RuntimeException");
    } catch (RuntimeException e) {
      // TODO(berezv): should we throw something more specific than RuntimeException?
      assertThat(e)
          .hasMessageThat()
          .contains(
              String.format(
                  "[%s] The Google Cloud SQL Admin API is not enabled for the project",
                  "NotMyProject:myRegion:myInstance"));
    }
  }

  @Test
  public void create_notAuthorized() throws IOException {
    CoreSocketFactory coreSocketFactory =
        new CoreSocketFactory(clientKeyPair, adminApi, credentialFactory, 3307, defaultExecutor);
    try {
      // Use a different instance to simulate incorrect permissions.
      coreSocketFactory.createSslSocket(
          "myProject:myRegion:NotMyInstance", Arrays.asList("PRIMARY"));
      fail();
    } catch (RuntimeException e) {
      assertThat(e)
          .hasMessageThat()
          .contains(
              String.format(
                  "[%s] The Cloud SQL Instance does not exist or your account is not authorized",
                  "myProject:myRegion:NotMyInstance"));
    }
  }

  private String createEphemeralCert(Duration shiftIntoPast)
      throws GeneralSecurityException, ExecutionException, IOException {
    Duration validFor = Duration.ofHours(1);
    ZonedDateTime notBefore = ZonedDateTime.now().minus(shiftIntoPast);
    ZonedDateTime notAfter = notBefore.plus(validFor);

    CertificateValidity interval =
        new CertificateValidity(Date.from(notBefore.toInstant()), Date.from(notAfter.toInstant()));

    X509CertInfo info = new X509CertInfo();
    info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
    info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(1));
    info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get("SHA1withRSA")));
    info.set(X509CertInfo.SUBJECT, new X500Name("C = US, O = Google\\, Inc, CN=temporary-subject"));
    info.set(X509CertInfo.KEY, new CertificateX509Key(Futures.getDone(clientKeyPair).getPublic()));
    info.set(X509CertInfo.VALIDITY, interval);
    info.set(
        X509CertInfo.ISSUER,
        new X500Name("C = US, O = Google\\, Inc, CN=Google Cloud SQL Signing CA foo:baz"));

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec keySpec =
        new PKCS8EncodedKeySpec(decodeBase64StripWhitespace(TestKeys.SIGNING_CA_PRIVATE_KEY));
    PrivateKey signingKey = keyFactory.generatePrivate(keySpec);

    X509CertImpl cert = new X509CertImpl(info);
    cert.sign(signingKey, "SHA1withRSA");

    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN CERTIFICATE-----\n");
    sb.append(Base64.getEncoder().encodeToString(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
    sb.append("\n");
    sb.append("-----END CERTIFICATE-----\n");

    return sb.toString();
  }

  private static class FakeSslServer {

    int start() throws InterruptedException {
      return start(PUBLIC_IP);
    }

    int start(final String ip) throws InterruptedException {
      final CountDownLatch countDownLatch = new CountDownLatch(1);
      final AtomicInteger pickedPort = new AtomicInteger();

      new Thread() {
        @Override
        public void run() {
          try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            KeyStore authKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            authKeyStore.load(null, null);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec =
                new PKCS8EncodedKeySpec(
                    decodeBase64StripWhitespace(TestKeys.SERVER_CERT_PRIVATE_KEY));
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            PrivateKeyEntry serverCert =
                new PrivateKeyEntry(
                    privateKey,
                    new Certificate[]{
                        certFactory.generateCertificate(
                            new ByteArrayInputStream(
                                TestKeys.SERVER_CERT.getBytes(StandardCharsets.UTF_8)))
                    });
            authKeyStore.setEntry("serverCert", serverCert, new PasswordProtection(new char[0]));
            KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(authKeyStore, new char[0]);

            final X509Certificate signingCaCert =
                (X509Certificate)
                    certFactory.generateCertificate(
                        new ByteArrayInputStream(
                            TestKeys.SIGNING_CA_CERT.getBytes(StandardCharsets.UTF_8)));

            KeyStore trustKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustKeyStore.load(null, null);
            trustKeyStore.setCertificateEntry("instance", signingCaCert);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("X.509");
            tmf.init(trustKeyStore);

            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(
                keyManagerFactory.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket sslServerSocket =
                (SSLServerSocket)
                    sslServerSocketFactory.createServerSocket(0, 5, InetAddress.getByName(ip));
            sslServerSocket.setNeedClientAuth(true);

            pickedPort.set(sslServerSocket.getLocalPort());
            countDownLatch.countDown();

            for (; ; ) {
              SSLSocket socket = (SSLSocket) sslServerSocket.accept();
              try {
                socket.startHandshake();
                socket.getOutputStream().write(SERVER_MESSAGE.getBytes(StandardCharsets.UTF_8));
                socket.close();
              } catch (Exception e) {
                e.printStackTrace();
              }
            }
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
        }
      }.start();

      countDownLatch.await();

      return pickedPort.get();
    }
  }
}
