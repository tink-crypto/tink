// Copyright 2021 Google LLC
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

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.jwt.JwtHmacKeyManager;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.crypto.tink.testing.proto.JwtClaimValue;
import com.google.crypto.tink.testing.proto.JwtFromJwkSetRequest;
import com.google.crypto.tink.testing.proto.JwtFromJwkSetResponse;
import com.google.crypto.tink.testing.proto.JwtGrpc;
import com.google.crypto.tink.testing.proto.JwtSignRequest;
import com.google.crypto.tink.testing.proto.JwtSignResponse;
import com.google.crypto.tink.testing.proto.JwtToJwkSetRequest;
import com.google.crypto.tink.testing.proto.JwtToJwkSetResponse;
import com.google.crypto.tink.testing.proto.JwtToken;
import com.google.crypto.tink.testing.proto.JwtValidator;
import com.google.crypto.tink.testing.proto.JwtVerifyRequest;
import com.google.crypto.tink.testing.proto.JwtVerifyResponse;
import com.google.crypto.tink.testing.proto.KeysetGenerateRequest;
import com.google.crypto.tink.testing.proto.KeysetGenerateResponse;
import com.google.crypto.tink.testing.proto.KeysetGrpc;
import com.google.crypto.tink.testing.proto.KeysetPublicRequest;
import com.google.crypto.tink.testing.proto.KeysetPublicResponse;
import com.google.crypto.tink.testing.proto.NullValue;
import com.google.protobuf.ByteString;
import com.google.protobuf.StringValue;
import com.google.protobuf.Timestamp;
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
public final class JwtServiceImplTest {
  private Server server;
  private ManagedChannel channel;
  KeysetGrpc.KeysetBlockingStub keysetStub;
  JwtGrpc.JwtBlockingStub jwtStub;

  @Before
  public void setUp() throws Exception {
    JwtMacConfig.register();
    JwtSignatureConfig.register();

    String serverName = InProcessServerBuilder.generateName();
    server = InProcessServerBuilder
        .forName(serverName)
        .directExecutor()
        .addService(new KeysetServiceImpl())
        .addService(new JwtServiceImpl())
        .build()
        .start();
    channel = InProcessChannelBuilder
        .forName(serverName)
        .directExecutor()
        .build();
    keysetStub = KeysetGrpc.newBlockingStub(channel);
    jwtStub = JwtGrpc.newBlockingStub(channel);
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

  private JwtToken generateToken(String audience, long expSeconds, int expNanos) {
    return JwtToken.newBuilder()
        .setTypeHeader(StringValue.newBuilder().setValue("typeHeader"))
        .setIssuer(StringValue.newBuilder().setValue("issuer"))
        .addAudiences(audience)
        .addAudiences(audience + "2")
        .setJwtId(StringValue.newBuilder().setValue("123abc"))
        .putCustomClaims("boolean", JwtClaimValue.newBuilder().setBoolValue(true).build())
        .putCustomClaims(
            "null", JwtClaimValue.newBuilder().setNullValue(NullValue.NULL_VALUE).build())
        .putCustomClaims("number", JwtClaimValue.newBuilder().setNumberValue(123.456).build())
        .putCustomClaims("string", JwtClaimValue.newBuilder().setStringValue("foo").build())
        .putCustomClaims(
            "json_array",
            JwtClaimValue.newBuilder()
                .setJsonArrayValue("[123,\"value\",null,[],{\"a\":42}]")
                .build())
        .putCustomClaims(
            "json_object",
            JwtClaimValue.newBuilder().setJsonObjectValue("{\"a\":[null,{\"b\":42}]}").build())
        .setExpiration(Timestamp.newBuilder().setSeconds(expSeconds).setNanos(expNanos))
        .build();
  }

  @Test
  public void jwtMacCreateKeyset_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("JWT_HS256"));
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    CreationResponse response =
        jwtStub.createJwtMac(
            CreationRequest.newBuilder().setKeyset(keysetResponse.getKeyset()).build());
    assertThat(response.getErr()).isEmpty();
  }

  @Test
  public void jwtMacCreateKeyset_fails() throws Exception {
    CreationResponse response =
        jwtStub.createJwtMac(
            CreationRequest.newBuilder()
                .setKeyset(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                .build());
    assertThat(response.getErr()).isNotEmpty();
  }

  @Test
  public void jwtComputeVerifyMac_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("JWT_HS256"));
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    long expSecs = 1234 + 100;
    int expNanos = 567000000;
    JwtToken token = generateToken("audience", expSecs, expNanos);

    JwtSignRequest signRequest =
        JwtSignRequest.newBuilder().setKeyset(ByteString.copyFrom(keyset)).setRawJwt(token).build();
    JwtSignResponse signResponse = jwtStub.computeMacAndEncode(signRequest);
    assertThat(signResponse.getErr()).isEmpty();

    JwtValidator validator =
        JwtValidator.newBuilder()
            .setExpectedTypeHeader(StringValue.newBuilder().setValue("typeHeader"))
            .setExpectedIssuer(StringValue.newBuilder().setValue("issuer"))
            .setExpectedAudience(StringValue.newBuilder().setValue("audience"))
            .setNow(Timestamp.newBuilder().setSeconds(1234))
            .build();
    JwtVerifyRequest verifyRequest =
        JwtVerifyRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(keyset))
            .setSignedCompactJwt(signResponse.getSignedCompactJwt())
            .setValidator(validator)
            .build();

    JwtToken expectedToken = generateToken("audience", expSecs, 0);
    JwtVerifyResponse verifyResponse = jwtStub.verifyMacAndDecode(verifyRequest);
    assertThat(verifyResponse.getErr()).isEmpty();
    assertThat(verifyResponse.getVerifiedJwt()).isEqualTo(expectedToken);
  }

  @Test
  public void jwtEmptyTokenComputeVerifyMac_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(JwtHmacKeyManager.hs256Template());
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    JwtToken token = JwtToken.getDefaultInstance();

    JwtSignRequest signRequest =
        JwtSignRequest.newBuilder().setKeyset(ByteString.copyFrom(keyset)).setRawJwt(token).build();
    JwtSignResponse signResponse = jwtStub.computeMacAndEncode(signRequest);
    assertThat(signResponse.getErr()).isEmpty();

    JwtValidator validator = JwtValidator.newBuilder().setAllowMissingExpiration(true).build();
    JwtVerifyRequest verifyRequest =
        JwtVerifyRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(keyset))
            .setSignedCompactJwt(signResponse.getSignedCompactJwt())
            .setValidator(validator)
            .build();

    JwtVerifyResponse verifyResponse = jwtStub.verifyMacAndDecode(verifyRequest);
    assertThat(verifyResponse.getErr()).isEmpty();
    assertThat(verifyResponse.getVerifiedJwt()).isEqualTo(token);
  }

  @Test
  public void jwtPublicKeySignCreateKeyset_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("JWT_ES256"));
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    CreationResponse response =
        jwtStub.createJwtPublicKeySign(
            CreationRequest.newBuilder().setKeyset(keysetResponse.getKeyset()).build());
    assertThat(response.getErr()).isEmpty();
  }

  @Test
  public void jwtPublicKeySignCreateKeyset_fails() throws Exception {
    CreationResponse response =
        jwtStub.createJwtPublicKeySign(
            CreationRequest.newBuilder()
                .setKeyset(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                .build());
    assertThat(response.getErr()).isNotEmpty();
  }


  @Test
  public void jwtPublicKeyVerifyCreateKeyset_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("JWT_ES256"));
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] privateKeyset = keysetResponse.getKeyset().toByteArray();

    KeysetPublicResponse pubResponse = publicKeyset(keysetStub, privateKeyset);
    assertThat(pubResponse.getErr()).isEmpty();
    CreationResponse response =
        jwtStub.createJwtPublicKeyVerify(
            CreationRequest.newBuilder().setKeyset(pubResponse.getPublicKeyset()).build());
    assertThat(response.getErr()).isEmpty();
  }

  @Test
  public void jwtPublicKeyVerifyCreateKeyset_fails() throws Exception {
    CreationResponse response =
        jwtStub.createJwtPublicKeyVerify(
            CreationRequest.newBuilder()
                .setKeyset(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                .build());
    assertThat(response.getErr()).isNotEmpty();
  }

  @Test
  public void publicKeySignVerify_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("JWT_ES256"));
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] privateKeyset = keysetResponse.getKeyset().toByteArray();

    KeysetPublicResponse pubResponse = publicKeyset(keysetStub, privateKeyset);
    assertThat(pubResponse.getErr()).isEmpty();
    byte[] publicKeyset = pubResponse.getPublicKeyset().toByteArray();

    long expSecs = 1234 + 100;
    int expNanos = 567000000;
    JwtToken token = generateToken("audience", expSecs, expNanos);

    JwtSignRequest signRequest =
        JwtSignRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(privateKeyset))
            .setRawJwt(token)
            .build();
    JwtSignResponse signResponse = jwtStub.publicKeySignAndEncode(signRequest);
    assertThat(signResponse.getErr()).isEmpty();

    JwtValidator validator =
        JwtValidator.newBuilder()
            .setExpectedTypeHeader(StringValue.newBuilder().setValue("typeHeader"))
            .setExpectedIssuer(StringValue.newBuilder().setValue("issuer"))
            .setExpectedAudience(StringValue.newBuilder().setValue("audience"))
            .setNow(Timestamp.newBuilder().setSeconds(1234))
            .build();
    JwtVerifyRequest verifyRequest =
        JwtVerifyRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(publicKeyset))
            .setSignedCompactJwt(signResponse.getSignedCompactJwt())
            .setValidator(validator)
            .build();

    JwtToken expectedToken = generateToken("audience", expSecs, 0);
    JwtVerifyResponse verifyResponse = jwtStub.publicKeyVerifyAndDecode(verifyRequest);
    assertThat(verifyResponse.getErr()).isEmpty();
    assertThat(verifyResponse.getVerifiedJwt()).isEqualTo(expectedToken);
  }

  @Test
  public void signFailsOnBadKeyset() throws Exception {
    byte[] badKeyset = "bad keyset".getBytes(UTF_8);

    JwtToken token = generateToken("audience", 1234, 0);
    JwtSignRequest signRequest =
        JwtSignRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(badKeyset))
            .setRawJwt(token)
            .build();
    JwtSignResponse signResponse = jwtStub.computeMacAndEncode(signRequest);
    assertThat(signResponse.getErr()).isNotEmpty();
  }

  @Test
  public void verifyFailsWhenExpired() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(JwtHmacKeyManager.hs256Template());
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    JwtToken token = generateToken("audience", 1234 - 10, 0);

    JwtSignRequest signRequest =
        JwtSignRequest.newBuilder().setKeyset(ByteString.copyFrom(keyset)).setRawJwt(token).build();
    JwtSignResponse signResponse = jwtStub.computeMacAndEncode(signRequest);
    assertThat(signResponse.getErr()).isEmpty();

    JwtValidator validator =
        JwtValidator.newBuilder()
            .setExpectedTypeHeader(StringValue.newBuilder().setValue("typeHeader"))
            .setExpectedIssuer(StringValue.newBuilder().setValue("issuer"))
            .setExpectedAudience(StringValue.newBuilder().setValue("audience"))
            .setNow(Timestamp.newBuilder().setSeconds(1234))
            .build();
    JwtVerifyRequest verifyRequest =
        JwtVerifyRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(keyset))
            .setSignedCompactJwt(signResponse.getSignedCompactJwt())
            .setValidator(validator)
            .build();

    JwtVerifyResponse verifyResponse = jwtStub.verifyMacAndDecode(verifyRequest);
    assertThat(verifyResponse.getErr()).isNotEmpty();
  }

  @Test
  public void verifyFailsWithWrongAudience() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(JwtHmacKeyManager.hs256Template());
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    JwtToken token = generateToken("wrong_audience", 1234 + 100, 0);

    JwtSignRequest signRequest =
        JwtSignRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(keyset))
            .setRawJwt(token)
            .build();
    JwtSignResponse signResponse = jwtStub.computeMacAndEncode(signRequest);
    assertThat(signResponse.getErr()).isEmpty();

    JwtValidator validator =
        JwtValidator.newBuilder()
            .setExpectedTypeHeader(StringValue.newBuilder().setValue("typeHeader"))
            .setExpectedIssuer(StringValue.newBuilder().setValue("issuer"))
            .setExpectedAudience(StringValue.newBuilder().setValue("audience"))
            .setNow(Timestamp.newBuilder().setSeconds(1234))
            .build();
    JwtVerifyRequest verifyRequest =
        JwtVerifyRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(keyset))
            .setSignedCompactJwt(signResponse.getSignedCompactJwt())
            .setValidator(validator)
            .build();

    JwtVerifyResponse verifyResponse = jwtStub.verifyMacAndDecode(verifyRequest);
    assertThat(verifyResponse.getErr()).isNotEmpty();
  }

  @Test
  public void verifyFailsWithWrongKey() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(JwtHmacKeyManager.hs256Template());

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    JwtToken token = generateToken("audience", 1234 + 100, 0);

    JwtSignRequest signRequest =
        JwtSignRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(keyset))
            .setRawJwt(token)
            .build();
    JwtSignResponse signResponse = jwtStub.computeMacAndEncode(signRequest);
    assertThat(signResponse.getErr()).isEmpty();

    KeysetGenerateResponse wrongKeysetResponse = generateKeyset(keysetStub, template);
    assertThat(wrongKeysetResponse.getErr()).isEmpty();
    byte[] wrongKeyset = wrongKeysetResponse.getKeyset().toByteArray();

    JwtValidator validator =
        JwtValidator.newBuilder()
            .setExpectedTypeHeader(StringValue.newBuilder().setValue("typeHeader"))
            .setExpectedIssuer(StringValue.newBuilder().setValue("issuer"))
            .setExpectedAudience(StringValue.newBuilder().setValue("audience"))
            .setNow(Timestamp.newBuilder().setSeconds(1234))
            .build();
    JwtVerifyRequest verifyRequest =
        JwtVerifyRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(wrongKeyset))
            .setSignedCompactJwt(signResponse.getSignedCompactJwt())
            .setValidator(validator)
            .build();

    JwtVerifyResponse verifyResponse = jwtStub.verifyMacAndDecode(verifyRequest);
    assertThat(verifyResponse.getErr()).isNotEmpty();
  }

  @Test
  public void jwtToFromJwt_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("JWT_ES256"));
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] privateKeyset = keysetResponse.getKeyset().toByteArray();

    KeysetPublicResponse pubResponse = publicKeyset(keysetStub, privateKeyset);
    assertThat(pubResponse.getErr()).isEmpty();
    byte[] publicKeyset = pubResponse.getPublicKeyset().toByteArray();

    JwtToken token = generateToken("audience", 1245, 0);

    JwtSignRequest signRequest =
        JwtSignRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(privateKeyset))
            .setRawJwt(token)
            .build();
    JwtSignResponse signResponse = jwtStub.publicKeySignAndEncode(signRequest);
    assertThat(signResponse.getErr()).isEmpty();

    // Convert the public keyset to a JWK set
    JwtToJwkSetRequest toRequest =
        JwtToJwkSetRequest.newBuilder().setKeyset(ByteString.copyFrom(publicKeyset)).build();
    JwtToJwkSetResponse toResponse = jwtStub.toJwkSet(toRequest);
    assertThat(toResponse.getErr()).isEmpty();
    assertThat(toResponse.getJwkSet()).contains("{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",");
    // Convert the public keyset to a JWK set
    JwtFromJwkSetRequest fromRequest =
        JwtFromJwkSetRequest.newBuilder().setJwkSet(toResponse.getJwkSet()).build();
    JwtFromJwkSetResponse fromResponse = jwtStub.fromJwkSet(fromRequest);
    assertThat(fromResponse.getErr()).isEmpty();

    // Use that output keyset to verify the token
    JwtValidator validator =
        JwtValidator.newBuilder()
            .setExpectedTypeHeader(StringValue.newBuilder().setValue("typeHeader"))
            .setExpectedIssuer(StringValue.newBuilder().setValue("issuer"))
            .setExpectedAudience(StringValue.newBuilder().setValue("audience"))
            .setNow(Timestamp.newBuilder().setSeconds(1234))
            .build();
    JwtVerifyRequest verifyRequest =
        JwtVerifyRequest.newBuilder()
            .setKeyset(fromResponse.getKeyset())
            .setSignedCompactJwt(signResponse.getSignedCompactJwt())
            .setValidator(validator)
            .build();
    JwtVerifyResponse verifyResponse = jwtStub.publicKeyVerifyAndDecode(verifyRequest);
    assertThat(verifyResponse.getErr()).isEmpty();
  }
}
