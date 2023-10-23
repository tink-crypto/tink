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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.internal.JsonParser;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.errorprone.annotations.InlineMe;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * Provides functions to import and export public Json Web Key (JWK) sets.
 *
 * <p>The currently supported algorithms are ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384
 * and PS512.
 */
public final class JwkSetConverter {

  /**
   * Converts a Tink KeysetHandle with JWT public keys into a Json Web Key (JWK) set.
   *
   * <p>The currently supported algorithms are ES256, ES384, ES512, RS256, RS384, RS512, PS256,
   * PS384 and PS512. JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.txt.
   */
  public static String fromPublicKeysetHandle(KeysetHandle handle)
      throws IOException, GeneralSecurityException {
    // Check validity of the keyset handle before calling "getAt".
    // See comments in {@link KeysetHandle#Entry#getAt}.
    handle = KeysetHandle.newBuilder(handle).build();
    // We never throw a IOException anymore, but keep it in the interface for compatibility.
    JsonArray keys = new JsonArray();
    for (int i = 0; i < handle.size(); i++) {
      KeysetHandle.Entry entry = handle.getAt(i);
      if (entry.getStatus() != KeyStatus.ENABLED) {
        continue;
      }
      ProtoKeySerialization protoKeySerialization =
          MutableSerializationRegistry.globalInstance()
              .serializeKey(entry.getKey(), ProtoKeySerialization.class, /* access= */ null);

      if ((protoKeySerialization.getOutputPrefixType() != OutputPrefixType.RAW)
          && (protoKeySerialization.getOutputPrefixType() != OutputPrefixType.TINK)) {
        throw new GeneralSecurityException("only OutputPrefixType RAW and TINK are supported");
      }
      if (protoKeySerialization.getKeyMaterialType() != KeyMaterialType.ASYMMETRIC_PUBLIC) {
        throw new GeneralSecurityException("only public keys can be converted");
      }
      switch (protoKeySerialization.getTypeUrl()) {
        case JWT_ECDSA_PUBLIC_KEY_URL:
          keys.add(convertJwtEcdsaKey(protoKeySerialization));
          break;
        case JWT_RSA_SSA_PKCS1_PUBLIC_KEY_URL:
          keys.add(convertJwtRsaSsaPkcs1(protoKeySerialization));
          break;
        case JWT_RSA_SSA_PSS_PUBLIC_KEY_URL:
          keys.add(convertJwtRsaSsaPss(protoKeySerialization));
          break;
        default:
          throw new GeneralSecurityException(
              String.format("key type %s is not supported", protoKeySerialization.getTypeUrl()));
      }
    }
    JsonObject jwkSet = new JsonObject();
    jwkSet.add("keys", keys);
    return jwkSet.toString();
  }

  /**
   * Converts a Json Web Key (JWK) set with public keys into a Tink KeysetHandle.
   *
   * <p>It requires that all keys in the set have the "alg" field set. The currently supported
   * algorithms are ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384 and PS512. JWK is defined
   * in https://www.rfc-editor.org/rfc/rfc7517.txt.
   */
  public static KeysetHandle toPublicKeysetHandle(String jwkSet)
      throws IOException, GeneralSecurityException {
    // We never throw a IOException anymore, but keep it in the interface for compatibility.
    JsonObject jsonKeyset;
    try {
      jsonKeyset = JsonParser.parse(jwkSet).getAsJsonObject();
    } catch (IllegalStateException | IOException ex) {
      throw new GeneralSecurityException("JWK set is invalid JSON", ex);
    }
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    JsonArray jsonKeys = jsonKeyset.get("keys").getAsJsonArray();
    for (JsonElement element : jsonKeys) {
      JsonObject jsonKey = element.getAsJsonObject();
      String algPrefix = getStringItem(jsonKey, "alg").substring(0, 2);
      switch (algPrefix) {
        case "RS":
          builder.addEntry(KeysetHandle.importKey(convertToRsaSsaPkcs1Key(jsonKey)).withRandomId());
          break;
        case "PS":
          builder.addEntry(KeysetHandle.importKey(convertToRsaSsaPssKey(jsonKey)).withRandomId());
          break;
        case "ES":
          builder.addEntry(KeysetHandle.importKey(convertToEcdsaKey(jsonKey)).withRandomId());
          break;
        default:
          throw new GeneralSecurityException(
              "unexpected alg value: " + getStringItem(jsonKey, "alg"));
      }
    }
    if (builder.size() <= 0) {
      throw new GeneralSecurityException("empty keyset");
    }
    builder.getAt(0).makePrimary();
    return builder.build();
  }

  private static final String JWT_ECDSA_PUBLIC_KEY_URL =
      "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
  private static final String JWT_RSA_SSA_PKCS1_PUBLIC_KEY_URL =
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey";
  private static final String JWT_RSA_SSA_PSS_PUBLIC_KEY_URL =
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey";

  private static Optional<String> getKid(@Nullable Integer idRequirement) {
    if (idRequirement == null) {
      return Optional.empty();
    }
    byte[] bigEndianKeyId = ByteBuffer.allocate(4).putInt(idRequirement).array();
    return Optional.of(Base64.urlSafeEncode(bigEndianKeyId));
  }

  private static JsonObject convertJwtEcdsaKey(ProtoKeySerialization protoKeySerialization)
      throws GeneralSecurityException {
    com.google.crypto.tink.proto.JwtEcdsaPublicKey jwtEcdsaPublicKey;
    try {
      jwtEcdsaPublicKey =
          com.google.crypto.tink.proto.JwtEcdsaPublicKey.parseFrom(
              protoKeySerialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("failed to parse value as JwtEcdsaPublicKey proto", e);
    }
    String alg;
    String crv;
    int encLength;
    switch (jwtEcdsaPublicKey.getAlgorithm()) {
      case ES256:
        alg = "ES256";
        crv = "P-256";
        encLength = 32;
        break;
      case ES384:
        alg = "ES384";
        crv = "P-384";
        encLength = 48;
        break;
      case ES512:
        alg = "ES512";
        crv = "P-521";
        encLength = 66;
        break;
      default:
        throw new GeneralSecurityException("unknown algorithm");
    }
    JsonObject jsonKey = new JsonObject();
    jsonKey.addProperty("kty", "EC");
    jsonKey.addProperty("crv", crv);
    BigInteger x =
        BigIntegerEncoding.fromUnsignedBigEndianBytes(jwtEcdsaPublicKey.getX().toByteArray());
    BigInteger y =
        BigIntegerEncoding.fromUnsignedBigEndianBytes(jwtEcdsaPublicKey.getY().toByteArray());
    jsonKey.addProperty(
        "x", Base64.urlSafeEncode(BigIntegerEncoding.toBigEndianBytesOfFixedLength(x, encLength)));
    jsonKey.addProperty(
        "y", Base64.urlSafeEncode(BigIntegerEncoding.toBigEndianBytesOfFixedLength(y, encLength)));
    jsonKey.addProperty("use", "sig");
    jsonKey.addProperty("alg", alg);
    JsonArray keyOps = new JsonArray();
    keyOps.add("verify");
    jsonKey.add("key_ops", keyOps);
    Optional<String> kid = getKid(protoKeySerialization.getIdRequirementOrNull());
    if (kid.isPresent()) {
      jsonKey.addProperty("kid", kid.get());
    } else if (jwtEcdsaPublicKey.hasCustomKid()) {
      jsonKey.addProperty("kid", jwtEcdsaPublicKey.getCustomKid().getValue());
    }
    return jsonKey;
  }

  private static JsonObject convertJwtRsaSsaPkcs1(ProtoKeySerialization protoKeySerialization)
      throws GeneralSecurityException {
    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1PublicKey;
    try {
      jwtRsaSsaPkcs1PublicKey =
          com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.parseFrom(
              protoKeySerialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(
          "failed to parse value as JwtRsaSsaPkcs1PublicKey proto", e);
    }
    String alg;
    switch (jwtRsaSsaPkcs1PublicKey.getAlgorithm()) {
      case RS256:
        alg = "RS256";
        break;
      case RS384:
        alg = "RS384";
        break;
      case RS512:
        alg = "RS512";
        break;
      default:
        throw new GeneralSecurityException("unknown algorithm");
    }
    JsonObject jsonKey = new JsonObject();
    jsonKey.addProperty("kty", "RSA");
    jsonKey.addProperty("n", Base64.urlSafeEncode(jwtRsaSsaPkcs1PublicKey.getN().toByteArray()));
    jsonKey.addProperty("e", Base64.urlSafeEncode(jwtRsaSsaPkcs1PublicKey.getE().toByteArray()));
    jsonKey.addProperty("use", "sig");
    jsonKey.addProperty("alg", alg);
    JsonArray keyOps = new JsonArray();
    keyOps.add("verify");
    jsonKey.add("key_ops", keyOps);
    Optional<String> kid = getKid(protoKeySerialization.getIdRequirementOrNull());
    if (kid.isPresent()) {
      jsonKey.addProperty("kid", kid.get());
    } else if (jwtRsaSsaPkcs1PublicKey.hasCustomKid()) {
      jsonKey.addProperty("kid", jwtRsaSsaPkcs1PublicKey.getCustomKid().getValue());
    }
    return jsonKey;
  }

  private static JsonObject convertJwtRsaSsaPss(ProtoKeySerialization protoKeySerialization)
      throws GeneralSecurityException {
    com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey jwtRsaSsaPssPublicKey;
    try {
      jwtRsaSsaPssPublicKey =
          com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.parseFrom(
              protoKeySerialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("failed to parse value as JwtRsaSsaPssPublicKey proto", e);
    }
    String alg;
    switch (jwtRsaSsaPssPublicKey.getAlgorithm()) {
      case PS256:
        alg = "PS256";
        break;
      case PS384:
        alg = "PS384";
        break;
      case PS512:
        alg = "PS512";
        break;
      default:
        throw new GeneralSecurityException("unknown algorithm");
    }
    JsonObject jsonKey = new JsonObject();
    jsonKey.addProperty("kty", "RSA");
    jsonKey.addProperty("n", Base64.urlSafeEncode(jwtRsaSsaPssPublicKey.getN().toByteArray()));
    jsonKey.addProperty("e", Base64.urlSafeEncode(jwtRsaSsaPssPublicKey.getE().toByteArray()));
    jsonKey.addProperty("use", "sig");
    jsonKey.addProperty("alg", alg);
    JsonArray keyOps = new JsonArray();
    keyOps.add("verify");
    jsonKey.add("key_ops", keyOps);
    Optional<String> kid = getKid(protoKeySerialization.getIdRequirementOrNull());
    if (kid.isPresent()) {
      jsonKey.addProperty("kid", kid.get());
    } else if (jwtRsaSsaPssPublicKey.hasCustomKid()) {
      jsonKey.addProperty("kid", jwtRsaSsaPssPublicKey.getCustomKid().getValue());
    }
    return jsonKey;
  }

  private static String getStringItem(JsonObject obj, String name) throws GeneralSecurityException {
    if (!obj.has(name)) {
      throw new GeneralSecurityException(name + " not found");
    }
    if (!obj.get(name).isJsonPrimitive() || !obj.get(name).getAsJsonPrimitive().isString()) {
      throw new GeneralSecurityException(name + " is not a string");
    }
    return obj.get(name).getAsString();
  }

  private static void expectStringItem(JsonObject obj, String name, String expectedValue)
      throws GeneralSecurityException {
    String value = getStringItem(obj, name);
    if (!value.equals(expectedValue)) {
      throw new GeneralSecurityException("unexpected " + name + " value: " + value);
    }
  }

  private static void validateUseIsSig(JsonObject jsonKey) throws GeneralSecurityException {
    if (!jsonKey.has("use")) {
      return;
    }
    expectStringItem(jsonKey, "use", "sig");
  }

  private static void validateKeyOpsIsVerify(JsonObject jsonKey) throws GeneralSecurityException {
    if (!jsonKey.has("key_ops")) {
      return;
    }
    if (!jsonKey.get("key_ops").isJsonArray()) {
      throw new GeneralSecurityException("key_ops is not an array");
    }
    JsonArray keyOps = jsonKey.get("key_ops").getAsJsonArray();
    if (keyOps.size() != 1) {
      throw new GeneralSecurityException("key_ops must contain exactly one element");
    }
    if (!keyOps.get(0).isJsonPrimitive() || !keyOps.get(0).getAsJsonPrimitive().isString()) {
      throw new GeneralSecurityException("key_ops is not a string");
    }
    if (!keyOps.get(0).getAsString().equals("verify")) {
      throw new GeneralSecurityException("unexpected keyOps value: " + keyOps.get(0).getAsString());
    }
  }

  @AccessesPartialKey
  private static JwtRsaSsaPkcs1PublicKey convertToRsaSsaPkcs1Key(JsonObject jsonKey)
      throws GeneralSecurityException {
    JwtRsaSsaPkcs1Parameters.Algorithm algorithm;
    switch (getStringItem(jsonKey, "alg")) {
      case "RS256":
        algorithm = JwtRsaSsaPkcs1Parameters.Algorithm.RS256;
        break;
      case "RS384":
        algorithm = JwtRsaSsaPkcs1Parameters.Algorithm.RS384;
        break;
      case "RS512":
        algorithm = JwtRsaSsaPkcs1Parameters.Algorithm.RS512;
        break;
      default:
        throw new GeneralSecurityException(
            "Unknown Rsa Algorithm: " + getStringItem(jsonKey, "alg"));
    }
    if (jsonKey.has("p")
        || jsonKey.has("q")
        || jsonKey.has("dp")
        || jsonKey.has("dq")
        || jsonKey.has("d")
        || jsonKey.has("qi")) {
      throw new UnsupportedOperationException("importing RSA private keys is not implemented");
    }
    expectStringItem(jsonKey, "kty", "RSA");
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);

    BigInteger publicExponent =
        new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "e")));
    BigInteger modulus = new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "n")));

    if (jsonKey.has("kid")) {
      return JwtRsaSsaPkcs1PublicKey.builder()
          .setParameters(
              JwtRsaSsaPkcs1Parameters.builder()
                  .setModulusSizeBits(modulus.bitLength())
                  .setPublicExponent(publicExponent)
                  .setAlgorithm(algorithm)
                  .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
                  .build())
          .setModulus(modulus)
          .setCustomKid(getStringItem(jsonKey, "kid"))
          .build();
    } else {
      return JwtRsaSsaPkcs1PublicKey.builder()
          .setParameters(
              JwtRsaSsaPkcs1Parameters.builder()
                  .setModulusSizeBits(modulus.bitLength())
                  .setPublicExponent(publicExponent)
                  .setAlgorithm(algorithm)
                  .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                  .build())
          .setModulus(modulus)
          .build();
    }
  }

  @AccessesPartialKey
  private static JwtRsaSsaPssPublicKey convertToRsaSsaPssKey(JsonObject jsonKey)
      throws GeneralSecurityException {
    JwtRsaSsaPssParameters.Algorithm algorithm;
    switch (getStringItem(jsonKey, "alg")) {
      case "PS256":
        algorithm = JwtRsaSsaPssParameters.Algorithm.PS256;
        break;
      case "PS384":
        algorithm = JwtRsaSsaPssParameters.Algorithm.PS384;
        break;
      case "PS512":
        algorithm = JwtRsaSsaPssParameters.Algorithm.PS512;
        break;
      default:
        throw new GeneralSecurityException(
            "Unknown Rsa Algorithm: " + getStringItem(jsonKey, "alg"));
    }
    if (jsonKey.has("p")
        || jsonKey.has("q")
        || jsonKey.has("dq")
        || jsonKey.has("dq")
        || jsonKey.has("d")
        || jsonKey.has("qi")) {
      throw new UnsupportedOperationException("importing RSA private keys is not implemented");
    }
    expectStringItem(jsonKey, "kty", "RSA");
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);

    BigInteger publicExponent =
        new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "e")));
    BigInteger modulus = new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "n")));

    if (jsonKey.has("kid")) {
      return JwtRsaSsaPssPublicKey.builder()
          .setParameters(
              JwtRsaSsaPssParameters.builder()
                  .setModulusSizeBits(modulus.bitLength())
                  .setPublicExponent(publicExponent)
                  .setAlgorithm(algorithm)
                  .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
                  .build())
          .setModulus(modulus)
          .setCustomKid(getStringItem(jsonKey, "kid"))
          .build();
    } else {
      return JwtRsaSsaPssPublicKey.builder()
          .setParameters(
              JwtRsaSsaPssParameters.builder()
                  .setModulusSizeBits(modulus.bitLength())
                  .setPublicExponent(publicExponent)
                  .setAlgorithm(algorithm)
                  .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                  .build())
          .setModulus(modulus)
          .build();
    }
  }

  @AccessesPartialKey
  private static JwtEcdsaPublicKey convertToEcdsaKey(JsonObject jsonKey)
      throws GeneralSecurityException {
    JwtEcdsaParameters.Algorithm algorithm;
    switch (getStringItem(jsonKey, "alg")) {
      case "ES256":
        expectStringItem(jsonKey, "crv", "P-256");
        algorithm = JwtEcdsaParameters.Algorithm.ES256;
        break;
      case "ES384":
        expectStringItem(jsonKey, "crv", "P-384");
        algorithm = JwtEcdsaParameters.Algorithm.ES384;
        break;
      case "ES512":
        expectStringItem(jsonKey, "crv", "P-521");
        algorithm = JwtEcdsaParameters.Algorithm.ES512;
        break;
      default:
        throw new GeneralSecurityException(
            "Unknown Ecdsa Algorithm: " + getStringItem(jsonKey, "alg"));
    }
    if (jsonKey.has("d")) {
      throw new UnsupportedOperationException("importing ECDSA private keys is not implemented");
    }
    expectStringItem(jsonKey, "kty", "EC");
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);

    BigInteger x = new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "x")));
    BigInteger y = new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "y")));
    ECPoint publicPoint = new ECPoint(x, y);

    if (jsonKey.has("kid")) {
      return JwtEcdsaPublicKey.builder()
          .setParameters(
              JwtEcdsaParameters.builder()
                  .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
                  .setAlgorithm(algorithm)
                  .build())
          .setPublicPoint(publicPoint)
          .setCustomKid(getStringItem(jsonKey, "kid"))
          .build();
    } else {
      return JwtEcdsaPublicKey.builder()
          .setParameters(
              JwtEcdsaParameters.builder()
                  .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                  .setAlgorithm(algorithm)
                  .build())
          .setPublicPoint(publicPoint)
          .build();
    }
  }

  /**
   * @deprecated Use JwkSetConverter.fromPublicKeysetHandle(handle) instead.
   */
  @InlineMe(
      replacement = "JwkSetConverter.fromPublicKeysetHandle(handle)",
      imports = "com.google.crypto.tink.jwt.JwkSetConverter")
  @Deprecated
  public static String fromKeysetHandle(KeysetHandle handle, KeyAccess keyAccess)
      throws IOException, GeneralSecurityException {
    return fromPublicKeysetHandle(handle);
  }

  /**
   * @deprecated Use JwkSetConverter.toPublicKeysetHandle(jwkSet) instead.
   */
  @InlineMe(
      replacement = "JwkSetConverter.toPublicKeysetHandle(jwkSet)",
      imports = "com.google.crypto.tink.jwt.JwkSetConverter")
  @Deprecated
  public static KeysetHandle toKeysetHandle(String jwkSet, KeyAccess keyAccess)
      throws IOException, GeneralSecurityException {
    return toPublicKeysetHandle(jwkSet);
  }

  private JwkSetConverter() {}
}
