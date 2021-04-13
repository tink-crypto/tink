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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.hybrid.EciesAeadHkdfPrivateKeyManager;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.proto.testing.HybridDecryptRequest;
import com.google.crypto.tink.proto.testing.HybridDecryptResponse;
import com.google.crypto.tink.proto.testing.HybridEncryptRequest;
import com.google.crypto.tink.proto.testing.HybridEncryptResponse;
import com.google.crypto.tink.proto.testing.HybridGrpc;
import com.google.crypto.tink.proto.testing.KeysetGenerateRequest;
import com.google.crypto.tink.proto.testing.KeysetGenerateResponse;
import com.google.crypto.tink.proto.testing.KeysetGrpc;
import com.google.crypto.tink.proto.testing.KeysetPublicRequest;
import com.google.crypto.tink.proto.testing.KeysetPublicResponse;
import com.google.crypto.tink.proto.testing.SignatureGrpc;
import com.google.crypto.tink.proto.testing.SignatureSignRequest;
import com.google.crypto.tink.proto.testing.SignatureSignResponse;
import com.google.crypto.tink.proto.testing.SignatureVerifyRequest;
import com.google.crypto.tink.proto.testing.SignatureVerifyResponse;
import com.google.crypto.tink.signature.EcdsaSignKeyManager;
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
public final class AsymmetricTestingServicesTest {
  private Server server;
  private ManagedChannel channel;
  KeysetGrpc.KeysetBlockingStub keysetStub;
  HybridGrpc.HybridBlockingStub hybridStub;
  SignatureGrpc.SignatureBlockingStub signatureStub;


  @Before
  public void setUp() throws Exception {
    TinkConfig.register();
    String serverName = InProcessServerBuilder.generateName();
    server = InProcessServerBuilder
        .forName(serverName)
        .directExecutor()
        .addService(new KeysetServiceImpl())
        .addService(new HybridServiceImpl())
        .addService(new SignatureServiceImpl())
        .build()
        .start();
    channel = InProcessChannelBuilder
        .forName(serverName)
        .directExecutor()
        .build();
    keysetStub = KeysetGrpc.newBlockingStub(channel);
    hybridStub = HybridGrpc.newBlockingStub(channel);
    signatureStub = SignatureGrpc.newBlockingStub(channel);
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

  private static KeysetPublicResponse publicKeyset(
      KeysetGrpc.KeysetBlockingStub keysetStub, byte[] privateKeyset) {
    KeysetPublicRequest request =
        KeysetPublicRequest.newBuilder()
            .setPrivateKeyset(ByteString.copyFrom(privateKeyset))
            .build();
    return keysetStub.public_(request);
  }

  private static HybridEncryptResponse hybridEncrypt(
      HybridGrpc.HybridBlockingStub hybridStub,
      byte[] publicKeyset,
      byte[] plaintext,
      byte[] contextInfo) {
    HybridEncryptRequest encRequest =
        HybridEncryptRequest.newBuilder()
            .setPublicKeyset(ByteString.copyFrom(publicKeyset))
            .setPlaintext(ByteString.copyFrom(plaintext))
            .setContextInfo(ByteString.copyFrom(contextInfo))
            .build();
    return hybridStub.encrypt(encRequest);
  }

  private static HybridDecryptResponse hybridDecrypt(
      HybridGrpc.HybridBlockingStub hybridStub,
      byte[] privateKeyset,
      byte[] ciphertext,
      byte[] contextInfo) {
    HybridDecryptRequest decRequest =
        HybridDecryptRequest.newBuilder()
            .setPrivateKeyset(ByteString.copyFrom(privateKeyset))
            .setCiphertext(ByteString.copyFrom(ciphertext))
            .setContextInfo(ByteString.copyFrom(contextInfo))
            .build();
    return hybridStub.decrypt(decRequest);
  }

  @Test
  public void hybridGenerateEncryptDecrypt_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(
        EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128GcmTemplate());
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "generate_encrypt_decrypt".getBytes(UTF_8);

    KeysetGenerateResponse genResponse = generateKeyset(keysetStub, template);
    assertThat(genResponse.getErr()).isEmpty();
    byte[] privateKeyset = genResponse.getKeyset().toByteArray();

    KeysetPublicResponse pubResponse = publicKeyset(keysetStub, privateKeyset);
    assertThat(pubResponse.getErr()).isEmpty();
    byte[] publicKeyset = pubResponse.getPublicKeyset().toByteArray();

    HybridEncryptResponse encResponse =
        hybridEncrypt(hybridStub, publicKeyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isEmpty();
    byte[] ciphertext = encResponse.getCiphertext().toByteArray();

    HybridDecryptResponse decResponse =
        hybridDecrypt(hybridStub, privateKeyset, ciphertext, associatedData);
    assertThat(decResponse.getErr()).isEmpty();
    byte[] output = decResponse.getPlaintext().toByteArray();

    assertThat(output).isEqualTo(plaintext);
  }

  @Test
  public void publicKeyset_failsOnBadKeyset() throws Exception {
    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    KeysetPublicResponse response = publicKeyset(keysetStub, badKeyset);
    assertThat(response.getErr()).isNotEmpty();
  }

  @Test
  public void hybridEncrypt_failsOnBadKeyset() throws Exception {
    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] contextInfo = "hybrid_encrypt_bad_keyset".getBytes(UTF_8);
    HybridEncryptResponse encResponse =
        hybridEncrypt(hybridStub, badKeyset, plaintext, contextInfo);
    assertThat(encResponse.getErr()).isNotEmpty();
  }

  @Test
  public void hybridDecrypt_failsOnBadCiphertext() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(
        EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128GcmTemplate());
    byte[] badCiphertext = "bad ciphertext".getBytes(UTF_8);
    byte[] contextInfo = "hybrid_decrypt_bad_ciphertext".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] privateKeyset = keysetResponse.getKeyset().toByteArray();

    KeysetPublicResponse pubResponse = publicKeyset(keysetStub, privateKeyset);
    assertThat(pubResponse.getErr()).isEmpty();
    byte[] publicKeyset = pubResponse.getPublicKeyset().toByteArray();

    HybridDecryptResponse decResponse =
        hybridDecrypt(hybridStub, publicKeyset, badCiphertext, contextInfo);
    assertThat(decResponse.getErr()).isNotEmpty();
  }

  @Test
  public void hybridDecrypt_failsOnBadKeyset() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(
        EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128GcmTemplate());
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] contextInfo = "hybrid_decrypt_bad_keyset".getBytes(UTF_8);

    KeysetGenerateResponse privateKeysetResponse = generateKeyset(keysetStub, template);
    assertThat(privateKeysetResponse.getErr()).isEmpty();
    byte[] privateKeyset = privateKeysetResponse.getKeyset().toByteArray();

    KeysetPublicResponse pubResponse = publicKeyset(keysetStub, privateKeyset);
    assertThat(pubResponse.getErr()).isEmpty();
    byte[] publicKeyset = pubResponse.getPublicKeyset().toByteArray();

    HybridEncryptResponse encResponse =
        hybridEncrypt(hybridStub, publicKeyset, plaintext, contextInfo);
    assertThat(encResponse.getErr()).isEmpty();
    byte[] ciphertext = encResponse.getCiphertext().toByteArray();

    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    HybridDecryptResponse decResponse =
        hybridDecrypt(hybridStub, badKeyset, ciphertext, contextInfo);
    assertThat(decResponse.getErr()).isNotEmpty();
  }

  private static SignatureSignResponse signatureSign(
      SignatureGrpc.SignatureBlockingStub signatureStub, byte[] privateKeyset, byte[] data) {
    SignatureSignRequest request =
        SignatureSignRequest.newBuilder()
            .setPrivateKeyset(ByteString.copyFrom(privateKeyset))
            .setData(ByteString.copyFrom(data))
            .build();
    return signatureStub.sign(request);
  }

  private static SignatureVerifyResponse signatureVerify(
      SignatureGrpc.SignatureBlockingStub signatureStub,
      byte[] publicKeyset,
      byte[] signature,
      byte[] data) {
    SignatureVerifyRequest request =
        SignatureVerifyRequest.newBuilder()
            .setPublicKeyset(ByteString.copyFrom(publicKeyset))
            .setSignature(ByteString.copyFrom(signature))
            .setData(ByteString.copyFrom(data))
            .build();
    return signatureStub.verify(request);
  }

  @Test
  public void signatureSignVerify_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(
        EcdsaSignKeyManager.ecdsaP256Template());
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);

    KeysetGenerateResponse genResponse = generateKeyset(keysetStub, template);
    assertThat(genResponse.getErr()).isEmpty();
    byte[] privateKeyset = genResponse.getKeyset().toByteArray();

    KeysetPublicResponse pubResponse = publicKeyset(keysetStub, privateKeyset);
    assertThat(pubResponse.getErr()).isEmpty();
    byte[] publicKeyset = pubResponse.getPublicKeyset().toByteArray();

    SignatureSignResponse signResponse = signatureSign(signatureStub, privateKeyset, data);
    assertThat(signResponse.getErr()).isEmpty();
    byte[] signature = signResponse.getSignature().toByteArray();

    SignatureVerifyResponse verifyResponse =
        signatureVerify(signatureStub, publicKeyset, signature, data);
    assertThat(verifyResponse.getErr()).isEmpty();
  }

  @Test
  public void signatureSign_failsOnBadKeyset() throws Exception {
    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);

    SignatureSignResponse response = signatureSign(signatureStub, badKeyset, data);
    assertThat(response.getErr()).isNotEmpty();
  }

  @Test
  public void signatureVerify_failsOnBadSignature() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(
        EcdsaSignKeyManager.ecdsaP256Template());
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);

    KeysetGenerateResponse genResponse = generateKeyset(keysetStub, template);
    assertThat(genResponse.getErr()).isEmpty();
    byte[] privateKeyset = genResponse.getKeyset().toByteArray();

    KeysetPublicResponse pubResponse = publicKeyset(keysetStub, privateKeyset);
    assertThat(pubResponse.getErr()).isEmpty();
    byte[] publicKeyset = pubResponse.getPublicKeyset().toByteArray();

    SignatureVerifyResponse verifyResponse =
        signatureVerify(signatureStub, publicKeyset, "bad signature".getBytes(UTF_8), data);
    assertThat(verifyResponse.getErr()).isNotEmpty();
  }

  @Test
  public void signatureVerify_failsOnBadKeyset() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(
        EcdsaSignKeyManager.ecdsaP256Template());
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);

    KeysetGenerateResponse genResponse = generateKeyset(keysetStub, template);
    assertThat(genResponse.getErr()).isEmpty();
    byte[] privateKeyset = genResponse.getKeyset().toByteArray();

    SignatureSignResponse signResponse = signatureSign(signatureStub, privateKeyset, data);
    assertThat(signResponse.getErr()).isEmpty();
    byte[] signature = signResponse.getSignature().toByteArray();

    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    SignatureVerifyResponse verifyResponse =
        signatureVerify(signatureStub, badKeyset, signature, data);
    assertThat(verifyResponse.getErr()).isNotEmpty();
  }

}
