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

import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.BinaryKeysetWriter;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.jwt.JwkSetConverter;
import com.google.crypto.tink.jwt.JwtInvalidException;
import com.google.crypto.tink.jwt.JwtMac;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.testing.JwtClaimValue;
import com.google.crypto.tink.proto.testing.JwtFromJwkSetRequest;
import com.google.crypto.tink.proto.testing.JwtFromJwkSetResponse;
import com.google.crypto.tink.proto.testing.JwtGrpc.JwtImplBase;
import com.google.crypto.tink.proto.testing.JwtSignRequest;
import com.google.crypto.tink.proto.testing.JwtSignResponse;
import com.google.crypto.tink.proto.testing.JwtToJwkSetRequest;
import com.google.crypto.tink.proto.testing.JwtToJwkSetResponse;
import com.google.crypto.tink.proto.testing.JwtToken;
import com.google.crypto.tink.proto.testing.JwtVerifyRequest;
import com.google.crypto.tink.proto.testing.JwtVerifyResponse;
import com.google.crypto.tink.proto.testing.NullValue;
import com.google.crypto.tink.proto.testing.StringValue;
import com.google.crypto.tink.proto.testing.Timestamp;
import com.google.crypto.tink.tinkkey.SecretKeyAccess;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

/** Implements a gRPC JWT Testing service. */
public final class JwtServiceImpl extends JwtImplBase {

  public JwtServiceImpl() throws GeneralSecurityException {
    JwtMacConfig.register();
    JwtSignatureConfig.register();
  }

  private Instant timestampToInstant(Timestamp t) {
    return Instant.ofEpochMilli(t.getSeconds() * 1000 + t.getNanos() / 1000000);
  }

  private Timestamp instantToTimestamp(Instant i) {
    long millis = i.toEpochMilli();
    long seconds = millis / 1000;
    int nanos = (int) ((millis - seconds * 1000) * 1000000);
    return Timestamp.newBuilder().setSeconds(seconds).setNanos(nanos).build();
  }

  private RawJwt convertJwtTokenToRawJwt(JwtToken token) throws JwtInvalidException {
    RawJwt.Builder rawJwtBuilder = RawJwt.newBuilder();
    if (token.hasTypeHeader()) {
      rawJwtBuilder.setTypeHeader(token.getTypeHeader().getValue());
    }
    if (token.hasIssuer()) {
      rawJwtBuilder.setIssuer(token.getIssuer().getValue());
    }
    if (token.hasSubject()) {
      rawJwtBuilder.setSubject(token.getSubject().getValue());
    }
    for (String audience : token.getAudiencesList()) {
      rawJwtBuilder.addAudience(audience);
    }
    if (token.hasJwtId()) {
      rawJwtBuilder.setJwtId(token.getJwtId().getValue());
    }
    if (token.hasExpiration()) {
      rawJwtBuilder.setExpiration(timestampToInstant(token.getExpiration()));
    } else {
      rawJwtBuilder.withoutExpiration();
    }
    if (token.hasNotBefore()) {
      rawJwtBuilder.setNotBefore(timestampToInstant(token.getNotBefore()));
    }
    if (token.hasIssuedAt()) {
      rawJwtBuilder.setIssuedAt(timestampToInstant(token.getIssuedAt()));
    }
    for (Map.Entry<String, JwtClaimValue> entry : token.getCustomClaimsMap().entrySet()) {
      String name = entry.getKey();
      JwtClaimValue value = entry.getValue();
      switch (value.getKindCase().getNumber()) {
          case JwtClaimValue.NULL_VALUE_FIELD_NUMBER:
              rawJwtBuilder.addNullClaim(name);
          break;
          case JwtClaimValue.BOOL_VALUE_FIELD_NUMBER:
              rawJwtBuilder.addBooleanClaim(name, value.getBoolValue());
          break;
          case JwtClaimValue.NUMBER_VALUE_FIELD_NUMBER:
              rawJwtBuilder.addNumberClaim(name, value.getNumberValue());
          break;
          case JwtClaimValue.STRING_VALUE_FIELD_NUMBER:
              rawJwtBuilder.addStringClaim(name, value.getStringValue());
          break;
          case JwtClaimValue.JSON_ARRAY_VALUE_FIELD_NUMBER:
              rawJwtBuilder.addJsonArrayClaim(name, value.getJsonArrayValue());
          break;
          case JwtClaimValue.JSON_OBJECT_VALUE_FIELD_NUMBER:
              rawJwtBuilder.addJsonObjectClaim(name, value.getJsonObjectValue());
          break;
        default:
          throw new RuntimeException("Unknown JwtClaimValue kind: " + value.getKindCase());
      }
    }
    return rawJwtBuilder.build();
  }

  /** Creates a signed compact JWT. */
  @Override
  public void computeMacAndEncode(
      JwtSignRequest request, StreamObserver<JwtSignResponse> responseObserver) {
    JwtSignResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      RawJwt rawJwt = convertJwtTokenToRawJwt(request.getRawJwt());
      JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
      String signedCompactJwt = jwtMac.computeMacAndEncode(rawJwt);
      response = JwtSignResponse.newBuilder().setSignedCompactJwt(signedCompactJwt).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = JwtSignResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  /** Creates a signed compact JWT. */
  @Override
  public void publicKeySignAndEncode(
      JwtSignRequest request, StreamObserver<JwtSignResponse> responseObserver) {
    JwtSignResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      RawJwt rawJwt = convertJwtTokenToRawJwt(request.getRawJwt());
      JwtPublicKeySign signer = keysetHandle.getPrimitive(JwtPublicKeySign.class);
      String signedCompactJwt = signer.signAndEncode(rawJwt);
      response = JwtSignResponse.newBuilder().setSignedCompactJwt(signedCompactJwt).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = JwtSignResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  private void addCustomClaimToBuilder(VerifiedJwt token, String name, JwtToken.Builder builder)
      throws JwtInvalidException {
    // We do not know the type, so we just try them one by one.
    if (token.isNullClaim(name)) {
      builder.putCustomClaims(
          name, JwtClaimValue.newBuilder().setNullValue(NullValue.NULL_VALUE).build());
      return;
    }
    if (token.hasStringClaim(name)) {
      String value = token.getStringClaim(name);
      builder.putCustomClaims(name, JwtClaimValue.newBuilder().setStringValue(value).build());
      return;
    }
    if (token.hasNumberClaim(name)) {
      Double value = token.getNumberClaim(name);
      builder.putCustomClaims(name, JwtClaimValue.newBuilder().setNumberValue(value).build());
      return;
    }
    if (token.hasBooleanClaim(name)) {
      Boolean value = token.getBooleanClaim(name);
      builder.putCustomClaims(name, JwtClaimValue.newBuilder().setBoolValue(value).build());
      return;
    }
    if (token.hasJsonArrayClaim(name)) {
      String value = token.getJsonArrayClaim(name);
      builder.putCustomClaims(name, JwtClaimValue.newBuilder().setJsonArrayValue(value).build());
      return;
    }
    if (token.hasJsonObjectClaim(name)) {
      String value = token.getJsonObjectClaim(name);
      builder.putCustomClaims(name, JwtClaimValue.newBuilder().setJsonObjectValue(value).build());
      return;
    }
    throw new RuntimeException("unable to add claim " + name);
  }

  private JwtToken convertVerifiedJwtToJwtToken(VerifiedJwt verifiedJwt)
      throws JwtInvalidException {
    JwtToken.Builder builder = JwtToken.newBuilder();
    if (verifiedJwt.hasTypeHeader()) {
      builder.setTypeHeader(StringValue.newBuilder().setValue(verifiedJwt.getTypeHeader()));
    }
    if (verifiedJwt.hasIssuer()) {
        builder.setIssuer(StringValue.newBuilder().setValue(verifiedJwt.getIssuer()));
    }
    if (verifiedJwt.hasSubject()) {
        builder.setSubject(StringValue.newBuilder().setValue(verifiedJwt.getSubject()));
    }
    if (verifiedJwt.hasAudiences()) {
      for (String audience : verifiedJwt.getAudiences()) {
        builder.addAudiences(audience);
      }
    }
    if (verifiedJwt.hasJwtId()) {
        builder.setJwtId(StringValue.newBuilder().setValue(verifiedJwt.getJwtId()));
    }
    if (verifiedJwt.hasExpiration()) {
      builder.setExpiration(instantToTimestamp(verifiedJwt.getExpiration()));
    }
    if (verifiedJwt.hasNotBefore()) {
      builder.setNotBefore(instantToTimestamp(verifiedJwt.getNotBefore()));
    }
    if (verifiedJwt.hasIssuedAt()) {
      builder.setIssuedAt(instantToTimestamp(verifiedJwt.getIssuedAt()));
    }
    for (String claimName : verifiedJwt.customClaimNames()) {
      addCustomClaimToBuilder(verifiedJwt, claimName, builder);
    }
    return builder.build();
  }

  private JwtValidator convertProtoValidatorToValidator(
      com.google.crypto.tink.proto.testing.JwtValidator validator) throws JwtInvalidException {
    JwtValidator.Builder validatorBuilder = JwtValidator.newBuilder();
    if (validator.hasExpectedTypeHeader()) {
      validatorBuilder.expectTypeHeader(validator.getExpectedTypeHeader().getValue());
    }
    if (validator.hasExpectedIssuer()) {
      validatorBuilder.expectIssuer(validator.getExpectedIssuer().getValue());
    }
    if (validator.hasExpectedAudience()) {
      validatorBuilder.expectAudience(validator.getExpectedAudience().getValue());
    }
    if (validator.getIgnoreTypeHeader()) {
      validatorBuilder.ignoreTypeHeader();
    }
    if (validator.getIgnoreIssuer()) {
      validatorBuilder.ignoreIssuer();
    }
    if (validator.getIgnoreAudience()) {
      validatorBuilder.ignoreAudiences();
    }
    if (validator.getAllowMissingExpiration()) {
      validatorBuilder.allowMissingExpiration();
    }
    if (validator.getExpectIssuedInThePast()) {
      validatorBuilder.expectIssuedInThePast();
    }
    if (validator.hasNow()) {
      Instant now = timestampToInstant(validator.getNow());
      validatorBuilder.setClock(Clock.fixed(now, ZoneOffset.UTC));
    }
    if (validator.hasClockSkew()) {
      validatorBuilder.setClockSkew(Duration.ofSeconds(validator.getClockSkew().getSeconds()));
    }
    return validatorBuilder.build();
  }

  /** Decodes and verifies a signed, compact JWT. */
  @Override
  public void verifyMacAndDecode(
      JwtVerifyRequest request,
      StreamObserver<JwtVerifyResponse> responseObserver) {
    JwtVerifyResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      JwtValidator validator = convertProtoValidatorToValidator(request.getValidator());
      JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
      VerifiedJwt verifiedJwt = jwtMac.verifyMacAndDecode(request.getSignedCompactJwt(), validator);
      JwtToken token = convertVerifiedJwtToJwtToken(verifiedJwt);
      response = JwtVerifyResponse.newBuilder().setVerifiedJwt(token).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = JwtVerifyResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  /** Decodes and verifies a signed, compact JWT. */
  @Override
  public void publicKeyVerifyAndDecode(
      JwtVerifyRequest request,
      StreamObserver<JwtVerifyResponse> responseObserver) {
    JwtVerifyResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      JwtValidator validator = convertProtoValidatorToValidator(request.getValidator());
      JwtPublicKeyVerify verifier = keysetHandle.getPrimitive(JwtPublicKeyVerify.class);
      VerifiedJwt verifiedJwt = verifier.verifyAndDecode(request.getSignedCompactJwt(), validator);
      JwtToken token = convertVerifiedJwtToJwtToken(verifiedJwt);
      response = JwtVerifyResponse.newBuilder().setVerifiedJwt(token).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = JwtVerifyResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  /** Converts a Tink JWT Keyset to a JWK set. */
  @Override
  public void toJwkSet(
      JwtToJwkSetRequest request, StreamObserver<JwtToJwkSetResponse> responseObserver) {
    JwtToJwkSetResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      String jwkSet =
          JwkSetConverter.fromKeysetHandle(keysetHandle, SecretKeyAccess.insecureSecretAccess());
      response = JwtToJwkSetResponse.newBuilder().setJwkSet(jwkSet).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = JwtToJwkSetResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  /** Converts a JWK set to a Tink JWT Keyset. */
  @Override
  public void fromJwkSet(
      JwtFromJwkSetRequest request, StreamObserver<JwtFromJwkSetResponse> responseObserver) {
    JwtFromJwkSetResponse response;
    try {
      KeysetHandle keysetHandle =
          JwkSetConverter.toKeysetHandle(
              request.getJwkSet(), SecretKeyAccess.insecureSecretAccess());

      Keyset keyset = CleartextKeysetHandle.getKeyset(keysetHandle);
      ByteArrayOutputStream keysetStream = new ByteArrayOutputStream();
      BinaryKeysetWriter.withOutputStream(keysetStream).write(keyset);
      keysetStream.close();
      response =
          JwtFromJwkSetResponse.newBuilder()
              .setKeyset(ByteString.copyFrom(keysetStream.toByteArray()))
              .build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = JwtFromJwkSetResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
