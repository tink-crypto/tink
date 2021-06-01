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
package com.google.crypto.tink.jwt;

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.PrivateKeyTypeManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.JwtEcdsaAlgorithm;
import com.google.crypto.tink.proto.JwtEcdsaKeyFormat;
import com.google.crypto.tink.proto.JwtEcdsaPrivateKey;
import com.google.crypto.tink.proto.JwtEcdsaPublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.SelfKeyTestValidators;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This key manager generates new {@code JwtEcdsaSignKey} keys and produces new instances of {@code
 * JwtPublicKeySign}.
 */
public final class JwtEcdsaSignKeyManager
    extends PrivateKeyTypeManager<JwtEcdsaPrivateKey, JwtEcdsaPublicKey> {

  private static class JwtPublicKeySignFactory
      extends KeyTypeManager.PrimitiveFactory<JwtPublicKeySignInternal, JwtEcdsaPrivateKey> {
    public JwtPublicKeySignFactory() {
      super(JwtPublicKeySignInternal.class);
    }

    private static final void selfTestKey(ECPrivateKey privateKey, JwtEcdsaPrivateKey keyProto)
        throws GeneralSecurityException {

      Enums.HashType hash =
          JwtEcdsaVerifyKeyManager.hashForEcdsaAlgorithm(keyProto.getPublicKey().getAlgorithm());
      ECPublicKey publicKey =
          EllipticCurves.getEcPublicKey(
              JwtEcdsaVerifyKeyManager.getCurve(keyProto.getPublicKey().getAlgorithm()),
              keyProto.getPublicKey().getX().toByteArray(),
              keyProto.getPublicKey().getY().toByteArray());

      SelfKeyTestValidators.validateEcdsa(
          privateKey, publicKey, hash, EllipticCurves.EcdsaEncoding.IEEE_P1363);
    }

    @Override
    public JwtPublicKeySignInternal getPrimitive(JwtEcdsaPrivateKey keyProto)
        throws GeneralSecurityException {
      ECPrivateKey privateKey =
          EllipticCurves.getEcPrivateKey(
              JwtEcdsaVerifyKeyManager.getCurve(keyProto.getPublicKey().getAlgorithm()),
              keyProto.getKeyValue().toByteArray());

      // Note: this will throw an exception if algorithm is invalid
      selfTestKey(privateKey, keyProto);
      JwtEcdsaAlgorithm algorithm = keyProto.getPublicKey().getAlgorithm();
      Enums.HashType hash = JwtEcdsaVerifyKeyManager.hashForEcdsaAlgorithm(algorithm);
      final EcdsaSignJce signer = new EcdsaSignJce(privateKey, hash, EcdsaEncoding.IEEE_P1363);
      final String algorithmName = algorithm.name();

      return new JwtPublicKeySignInternal() {
        @Override
        public String signAndEncodeWithKid(RawJwt rawJwt, Optional<String> kid)
            throws GeneralSecurityException {
          String unsignedCompact = JwtFormat.createUnsignedCompact(algorithmName, kid, rawJwt);
          return JwtFormat.createSignedCompact(
              unsignedCompact, signer.sign(unsignedCompact.getBytes(US_ASCII)));
        }
      };
    }
  }

  JwtEcdsaSignKeyManager() {
    super(JwtEcdsaPrivateKey.class, JwtEcdsaPublicKey.class, new JwtPublicKeySignFactory());
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public JwtEcdsaPublicKey getPublicKey(JwtEcdsaPrivateKey key) {
    return key.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public JwtEcdsaPrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return JwtEcdsaPrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(JwtEcdsaPrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), getVersion());
    JwtEcdsaVerifyKeyManager.validateEcdsaAlgorithm(privKey.getPublicKey().getAlgorithm());
  }

  @Override
  public KeyFactory<JwtEcdsaKeyFormat, JwtEcdsaPrivateKey> keyFactory() {
    return new KeyFactory<JwtEcdsaKeyFormat, JwtEcdsaPrivateKey>(JwtEcdsaKeyFormat.class) {
      @Override
      public void validateKeyFormat(JwtEcdsaKeyFormat format) throws GeneralSecurityException {
        JwtEcdsaVerifyKeyManager.validateEcdsaAlgorithm(format.getAlgorithm());
      }

      @Override
      public JwtEcdsaKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return JwtEcdsaKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public JwtEcdsaPrivateKey deriveKey(JwtEcdsaKeyFormat format, InputStream inputStream) {
        throw new UnsupportedOperationException();
      }

      @Override
      public JwtEcdsaPrivateKey createKey(JwtEcdsaKeyFormat format)
          throws GeneralSecurityException {
        JwtEcdsaAlgorithm ecdsaAlgorithm = format.getAlgorithm();
        KeyPair keyPair =
            EllipticCurves.generateKeyPair(
                JwtEcdsaVerifyKeyManager.getCurve(format.getAlgorithm()));
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
        ECPoint w = pubKey.getW();
        // Creates JwtEcdsaPublicKey.
        JwtEcdsaPublicKey ecdsaPubKey =
            JwtEcdsaPublicKey.newBuilder()
                .setVersion(getVersion())
                .setAlgorithm(ecdsaAlgorithm)
                .setX(ByteString.copyFrom(w.getAffineX().toByteArray()))
                .setY(ByteString.copyFrom(w.getAffineY().toByteArray()))
                .build();
        // Creates JwtEcdsaPrivateKey.
        return JwtEcdsaPrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(ecdsaPubKey)
            .setKeyValue(ByteString.copyFrom(privKey.getS().toByteArray()))
            .build();
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<JwtEcdsaKeyFormat>> keyFormats() {
        Map<String, KeyFactory.KeyFormat<JwtEcdsaKeyFormat>> result = new HashMap<>();
        result.put(
            "JWT_ES256_RAW",
            createKeyFormat(JwtEcdsaAlgorithm.ES256, KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_ES256",
            createKeyFormat(JwtEcdsaAlgorithm.ES256, KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "JWT_ES384_RAW",
            createKeyFormat(JwtEcdsaAlgorithm.ES384, KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_ES384",
            createKeyFormat(JwtEcdsaAlgorithm.ES384, KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "JWT_ES512_RAW",
            createKeyFormat(JwtEcdsaAlgorithm.ES512, KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_ES512",
            createKeyFormat(JwtEcdsaAlgorithm.ES512, KeyTemplate.OutputPrefixType.TINK));
        return Collections.unmodifiableMap(result);
      }
    };
  }
  /**
   * Registers the {@link EcdsaSignKeyManager} and the {@link EcdsaVerifyKeyManager} with the
   * registry, so that the the Ecdsa-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new JwtEcdsaSignKeyManager(), new JwtEcdsaVerifyKeyManager(), newKeyAllowed);
  }
  /**
   * Returns a {@link KeyTemplate} that generates new instances of ECDSA keys with ES256:
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>Curve: NIST P-256
   *   <li>Signature encoding: IEEE P1363.
   *   <li>Prefix type: RAW (no prefix).
   * </ul>
   *
   * Keys generated from this template create raw signatures of exactly 64 bytes. It is compatible
   * with JWS and most other libraries.
   */
  public static final KeyTemplate jwtES256Template() {
    return createKeyTemplate(JwtEcdsaAlgorithm.ES256);
  }
  /**
   * Returns a {@link KeyTemplate} that generates new instances of ECDSA keys with the ES256:
   *
   * <ul>
   *   <li>Hash function: SHA384
   *   <li>Curve: NIST P-384
   *   <li>Signature encoding: IEEE P1363.
   *   <li>Prefix type: RAW (no prefix).
   * </ul>
   *
   * Keys generated from this template create raw signatures of exactly 64 bytes. It is compatible
   * with JWS and most other libraries.
   */
  public static final KeyTemplate jwtES384Template() {
    return createKeyTemplate(JwtEcdsaAlgorithm.ES384);
  }
  /**
   * Returns a {@link KeyTemplate} that generates new instances of ECDSA keys with ES512:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>Curve: NIST P-512
   *   <li>Signature encoding: IEEE P1363.
   *   <li>Prefix type: RAW (no prefix).
   * </ul>
   *
   * Keys generated from this template create raw signatures of exactly 64 bytes. It is compatible
   * with JWS and most other libraries.
   */
  public static final KeyTemplate jwtES512Template() {
    return createKeyTemplate(JwtEcdsaAlgorithm.ES512);
  }

  /**
   * Returns a {@link KeyTemplate} containing a {@link JwtEcdsaKeyFormat} with some specified
   * parameters.
   */
  private static KeyTemplate createKeyTemplate(JwtEcdsaAlgorithm algorithm) {
    JwtEcdsaKeyFormat format = JwtEcdsaKeyFormat.newBuilder().setAlgorithm(algorithm).build();
    return KeyTemplate.create(
        new JwtEcdsaSignKeyManager().getKeyType(),
        format.toByteArray(),
        KeyTemplate.OutputPrefixType.RAW);
  }

  private static KeyFactory.KeyFormat<JwtEcdsaKeyFormat> createKeyFormat(
      JwtEcdsaAlgorithm algorithm, KeyTemplate.OutputPrefixType prefixType) {
    JwtEcdsaKeyFormat format = JwtEcdsaKeyFormat.newBuilder().setAlgorithm(algorithm).build();
    return new KeyFactory.KeyFormat<>(format, prefixType);
  }
}
