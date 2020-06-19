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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.proto.testing.AeadDecryptRequest;
import com.google.crypto.tink.proto.testing.AeadDecryptResponse;
import com.google.crypto.tink.proto.testing.AeadEncryptRequest;
import com.google.crypto.tink.proto.testing.AeadEncryptResponse;
import com.google.crypto.tink.proto.testing.AeadGrpc;
import com.google.crypto.tink.proto.testing.KeysetGenerateRequest;
import com.google.crypto.tink.proto.testing.KeysetGenerateResponse;
import com.google.crypto.tink.proto.testing.KeysetGrpc;
import com.google.crypto.tink.proto.testing.MetadataGrpc;
import com.google.crypto.tink.proto.testing.ServerInfoRequest;
import com.google.crypto.tink.proto.testing.ServerInfoResponse;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TestingServicesTest {
  private Server server;
  private ManagedChannel channel;
  KeysetGrpc.KeysetBlockingStub keysetStub;
  AeadGrpc.AeadBlockingStub aeadStub;
  MetadataGrpc.MetadataBlockingStub metadataStub;

  @Before
  public void setUp() throws Exception {
    TinkConfig.register();
    String serverName = InProcessServerBuilder.generateName();
    server = InProcessServerBuilder
        .forName(serverName)
        .directExecutor()
        .addService(new MetadataServiceImpl())
        .addService(new AeadServiceImpl())
        .addService(new KeysetServiceImpl())
        .build()
        .start();
    channel = InProcessChannelBuilder
        .forName(serverName)
        .directExecutor()
        .build();
    keysetStub = KeysetGrpc.newBlockingStub(channel);
    aeadStub = AeadGrpc.newBlockingStub(channel);
    metadataStub = MetadataGrpc.newBlockingStub(channel);
  }

  @After
  public void tearDown() throws Exception {
    assertThat(channel.shutdown().awaitTermination(5, SECONDS)).isTrue();
    assertThat(server.shutdown().awaitTermination(5, SECONDS)).isTrue();
  }

  private static KeysetGenerateResponse generateKeyset(
      KeysetGrpc.KeysetBlockingStub keysetStub, byte[] template) {
    KeysetGenerateRequest genRequest =
        KeysetGenerateRequest.newBuilder().setTemplate(ByteString.copyFrom(template)).build();
    return keysetStub.generate(genRequest);
  }


  private static AeadEncryptResponse aeadEncrypt(
      AeadGrpc.AeadBlockingStub aeadStub, byte[] keyset, byte[] plaintext, byte[] associatedData) {
    AeadEncryptRequest encRequest =
        AeadEncryptRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(keyset))
            .setPlaintext(ByteString.copyFrom(plaintext))
            .setAssociatedData(ByteString.copyFrom(associatedData))
            .build();
    return aeadStub.encrypt(encRequest);

  }

  private static AeadDecryptResponse aeadDecrypt(
      AeadGrpc.AeadBlockingStub aeadStub, byte[] keyset, byte[] ciphertext, byte[] associatedData) {
    AeadDecryptRequest decRequest =
        AeadDecryptRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(keyset))
            .setCiphertext(ByteString.copyFrom(ciphertext))
            .setAssociatedData(ByteString.copyFrom(associatedData))
            .build();
    return aeadStub.decrypt(decRequest);

  }

  @Test
  public void aeadGenerateEncryptDecrypt_success() throws Exception {
    byte[] template = AeadKeyTemplates.AES128_GCM.toByteArray();
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "generate_encrypt_decrypt".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    AeadEncryptResponse encResponse = aeadEncrypt(aeadStub, keyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isEmpty();
    byte[] ciphertext = encResponse.getCiphertext().toByteArray();

    AeadDecryptResponse decResponse = aeadDecrypt(aeadStub, keyset, ciphertext, associatedData);
    assertThat(decResponse.getErr()).isEmpty();
    byte[] output = decResponse.getPlaintext().toByteArray();

    assertThat(output).isEqualTo(plaintext);
  }

  @Test
  public void generateKeyset_failsOnBadTemplate() throws Exception {
    byte[] badTemplate = "bad template".getBytes(UTF_8);
    KeysetGenerateResponse genResponse = generateKeyset(keysetStub, badTemplate);
    assertThat(genResponse.getErr()).isNotEmpty();
  }

  @Test
  public void aeadEncrypt_failsOnBadKeyset() throws Exception {
    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "aead_encrypt_fails_on_bad_keyset".getBytes(UTF_8);
    AeadEncryptResponse encResponse = aeadEncrypt(aeadStub, badKeyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isNotEmpty();
  }

  @Test
  public void aeadDecrypt_failsOnBadCiphertext() throws Exception {
    byte[] template = AeadKeyTemplates.AES128_GCM.toByteArray();
    byte[] badCiphertext = "bad ciphertext".getBytes(UTF_8);
    byte[] associatedData = "aead_decrypt_fails_on_bad_ciphertext".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    AeadDecryptResponse decResponse = aeadDecrypt(aeadStub, keyset, badCiphertext, associatedData);
    assertThat(decResponse.getErr()).isNotEmpty();
  }

  @Test
  public void aeadDecrypt_failsOnBadKeyset() throws Exception {
    byte[] template = AeadKeyTemplates.AES128_GCM.toByteArray();
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "generate_encrypt_decrypt".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    AeadEncryptResponse encResponse = aeadEncrypt(aeadStub, keyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isEmpty();
    byte[] ciphertext = encResponse.getCiphertext().toByteArray();

    byte[] badKeyset = "bad keyset".getBytes(UTF_8);

    AeadDecryptResponse decResponse = aeadDecrypt(aeadStub, badKeyset, ciphertext, associatedData);
    assertThat(decResponse.getErr()).isNotEmpty();
  }

  @Test
  public void getServerInfo_success() throws Exception {
    ServerInfoResponse response =
        metadataStub.getServerInfo(ServerInfoRequest.getDefaultInstance());
    assertThat(response.getLanguage()).isEqualTo("java");
    assertThat(response.getTinkVersion()).isNotEmpty();
  }
}
