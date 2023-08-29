// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.testing;

import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.integration.awskms.AwsKmsClient;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import io.grpc.ServerBuilder;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

/** Starts a server with Tink testing services. */
public final class TestingServer {

  @Option(name = "--port", usage = "The service port")
  private int port;

  @Option(name = "--gcp_credentials_path", usage = "Google Cloud KMS credentials path")
  private String gcpCredentialsPath;

  @Option(
      name = "--gcp_key_uri",
      usage =
          "Google Cloud KMS key URL of the form:"
              + " gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*.")
  private String gcpKeyUri;

  @Option(name = "--aws_credentials_path", usage = "AWS KMS credentials path")
  private String awsCredentialsPath;

  @Option(
      name = "--aws_key_uri",
      usage =
          "AWS KMS key URL of the form: aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>.")
  private String awsKeyUri;

  private static GcpKmsClient getGcpKmsClient(String uri, String credentialsPath)
      throws GeneralSecurityException {
    GcpKmsClient client = (uri == null) ? new GcpKmsClient() : new GcpKmsClient(uri);
    if (credentialsPath != null) {
      client.withCredentials(credentialsPath);
    } else {
      client.withDefaultCredentials();
    }
    return client;
  }

  private static AwsKmsClient getAwsKmsClient(String uri, String credentialsPath)
      throws GeneralSecurityException {
    AwsKmsClient client = (uri == null) ? new AwsKmsClient() : new AwsKmsClient(uri);
    if (credentialsPath != null) {
      client.withCredentials(credentialsPath);
    } else {
      client.withDefaultCredentials();
    }
    return client;
  }

  public void run() throws InterruptedException, GeneralSecurityException, IOException {
    installConscrypt();
    AeadConfig.register();
    DeterministicAeadConfig.register();
    HybridConfig.register();
    JwtMacConfig.register();
    JwtSignatureConfig.register();
    MacConfig.register();
    PrfConfig.register();
    SignatureConfig.register();
    StreamingAeadConfig.register();

    KmsClients.add(getGcpKmsClient(gcpKeyUri, gcpCredentialsPath));
    KmsClients.add(getAwsKmsClient(awsKeyUri, awsCredentialsPath));

    KmsClients.add(new FakeKmsClient());

    System.out.println("Start server on port " + port);
    ServerBuilder.forPort(port)
        .addService(new MetadataServiceImpl())
        .addService(new KeysetServiceImpl())
        .addService(new AeadServiceImpl())
        .addService(new DeterministicAeadServiceImpl())
        .addService(new StreamingAeadServiceImpl())
        .addService(new HybridServiceImpl())
        .addService(new MacServiceImpl())
        .addService(new PrfSetServiceImpl())
        .addService(new SignatureServiceImpl())
        .addService(new JwtServiceImpl())
        .build()
        .start()
        .awaitTermination();
  }

  public static void main(String[] args)
      throws InterruptedException, GeneralSecurityException, IOException {

    TestingServer server = new TestingServer();
    CmdLineParser parser = new CmdLineParser(server);
    try {
      parser.parseArgument(args);
    } catch (CmdLineException e) {
      System.err.println("TestingServer [options...] arguments...");
      parser.printUsage(System.err);
    }
    server.run();
  }

  private static void installConscrypt() {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      throw new IllegalStateException("Cannot test AesGcmSiv without Conscrypt Provider", cause);
    }
  }
}
