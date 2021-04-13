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

/**
 * Starts a server with Tink testing services.
 */
public final class TestingServer {

  private TestingServer() {
    // no instances
  }

  public static void main(String[] args)
      throws InterruptedException, GeneralSecurityException, IOException {

    if ((args.length != 2) || !args[0].equals("--port")) {
      System.out.println("Usage: TestingServer --port <port>");
      System.exit(1);
    }
    int port = Integer.parseInt(args[1]);

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

    System.out.println("Start server on port " + port);
    KmsClients.add(new FakeKmsClient());
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

  private static void installConscrypt() {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      throw new IllegalStateException("Cannot test AesGcmSiv without Conscrypt Provider", cause);
    }
  }
}
