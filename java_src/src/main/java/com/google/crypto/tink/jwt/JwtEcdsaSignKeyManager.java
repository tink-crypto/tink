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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.SecretBigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code JwtEcdsaSignKey} keys and produces new instances of {@code
 * JwtPublicKeySign}.
 */
public final class JwtEcdsaSignKeyManager {
  private static final PrimitiveConstructor<JwtEcdsaPrivateKey, JwtPublicKeySignInternal>
      PRIVATE_KEY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtEcdsaSignKeyManager::getPrimitive,
              JwtEcdsaPrivateKey.class,
              JwtPublicKeySignInternal.class);

  private static final PrimitiveConstructor<JwtEcdsaPublicKey, JwtPublicKeyVerifyInternal>
      PUBLIC_KEY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtEcdsaVerifyKeyManager::getPrimitive,
              JwtEcdsaPublicKey.class,
              JwtPublicKeyVerifyInternal.class);

  private static final PrivateKeyManager<JwtPublicKeySignInternal> legacyPrivateKeyManager =
      LegacyKeyManagerImpl.createPrivateKeyManager(
          getKeyType(),
          JwtPublicKeySignInternal.class,
          com.google.crypto.tink.proto.JwtEcdsaPrivateKey.parser());

  private static final KeyManager<JwtPublicKeyVerifyInternal> legacyPublicKeyManager =
      LegacyKeyManagerImpl.create(
          JwtEcdsaVerifyKeyManager.getKeyType(),
          JwtPublicKeyVerifyInternal.class,
          KeyMaterialType.ASYMMETRIC_PUBLIC,
          com.google.crypto.tink.proto.JwtEcdsaPublicKey.parser());

  @AccessesPartialKey
  private static final EcdsaPrivateKey toEcdsaPrivateKey(JwtEcdsaPrivateKey privateKey)
      throws GeneralSecurityException {
    EcdsaPublicKey ecdsaPublicKey =
        JwtEcdsaVerifyKeyManager.toEcdsaPublicKey(privateKey.getPublicKey());
    return EcdsaPrivateKey.builder()
        .setPublicKey(ecdsaPublicKey)
        .setPrivateValue(privateKey.getPrivateValue())
        .build();
  }

  @SuppressWarnings("Immutable") // The signer created by EcdsaSignJce.create is immutable
  private static JwtPublicKeySignInternal getPrimitive(JwtEcdsaPrivateKey key)
      throws GeneralSecurityException {
    final PublicKeySign signer = EcdsaSignJce.create(toEcdsaPrivateKey(key));
    final String algorithmName = key.getParameters().getAlgorithm().toString();

    return new JwtPublicKeySignInternal() {
      @Override
      public String signAndEncodeWithKid(RawJwt rawJwt, Optional<String> kid)
          throws GeneralSecurityException {
        if (key.getKid().isPresent()) {
          if (kid.isPresent()) {
            throw new JwtInvalidException("custom_kid can only be set for RAW keys.");
          }
          kid = key.getKid();
        }
        String unsignedCompact = JwtFormat.createUnsignedCompact(algorithmName, kid, rawJwt);
        return JwtFormat.createSignedCompact(
            unsignedCompact, signer.sign(unsignedCompact.getBytes(US_ASCII)));
      }
    };
  }

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey";
  }

  @AccessesPartialKey
  private static JwtEcdsaPrivateKey createKey(
      JwtEcdsaParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    KeyPair keyPair =
        EllipticCurves.generateKeyPair(parameters.getAlgorithm().getECParameterSpec());
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(pubKey.getW()).build();

    return JwtEcdsaPrivateKey.create(
        publicKey, SecretBigInteger.fromBigInteger(privKey.getS(), InsecureSecretKeyAccess.get()));
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<JwtEcdsaParameters> KEY_CREATOR =
      JwtEcdsaSignKeyManager::createKey;

  /**
   * List of default templates to generate tokens with algorithms "ES256", "ES384" or "ES512". Use
   * the template with the "_RAW" suffix if you want to generate tokens without a "kid" header.
   */
  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put(
            "JWT_ES256_RAW",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_ES256",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
        result.put(
            "JWT_ES384_RAW",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_ES384",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
        result.put(
            "JWT_ES512_RAW",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_ES512",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
    return Collections.unmodifiableMap(result);
  }

  /**
   * Registers the {@link EcdsaSignKeyManager} and the {@link EcdsaVerifyKeyManager} with the
   * registry, so that the the Ecdsa-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    JwtEcdsaProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PRIVATE_KEY_PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PUBLIC_KEY_PRIMITIVE_CONSTRUCTOR);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, JwtEcdsaParameters.class);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(
            legacyPrivateKeyManager,
            TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO,
            newKeyAllowed);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(
            legacyPublicKeyManager,
            TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO,
            false);
  }

  private JwtEcdsaSignKeyManager() {}
}
