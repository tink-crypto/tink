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
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code JwtRsaSsaPssPrivateKey} keys and produces new instances of
 * {@code JwtPublicKeySign}.
 */
public final class JwtRsaSsaPssSignKeyManager {
  private static final PrivateKeyManager<Void> legacyPrivateKeyManager =
      LegacyKeyManagerImpl.createPrivateKeyManager(
          getKeyType(), Void.class, com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey.parser());

  private static final KeyManager<Void> legacyPublicKeyManager =
      LegacyKeyManagerImpl.create(
          JwtRsaSsaPssVerifyKeyManager.getKeyType(),
          Void.class,
          KeyMaterialType.ASYMMETRIC_PUBLIC,
          com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.parser());

  @AccessesPartialKey
  private static JwtRsaSsaPssPrivateKey createKey(
      JwtRsaSsaPssParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    KeyPairGenerator keyGen = EngineFactory.KEY_PAIR_GENERATOR.getInstance("RSA");
    RSAKeyGenParameterSpec spec =
        new RSAKeyGenParameterSpec(
            parameters.getModulusSizeBits(),
            new BigInteger(1, parameters.getPublicExponent().toByteArray()));
    keyGen.initialize(spec);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    // Creates JwtRsaSsaPssPublicKey.
    JwtRsaSsaPssPublicKey.Builder jwtRsaSsaPssPublicKeyBuilder =
        JwtRsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(pubKey.getModulus());
    if (idRequirement != null) {
      jwtRsaSsaPssPublicKeyBuilder.setIdRequirement(idRequirement);
    }
    JwtRsaSsaPssPublicKey jwtRsaSsaPssPublicKey = jwtRsaSsaPssPublicKeyBuilder.build();

    // Creates RsaSsaPssPrivateKey.
    return JwtRsaSsaPssPrivateKey.builder()
        .setPublicKey(jwtRsaSsaPssPublicKey)
        .setPrimes(
            SecretBigInteger.fromBigInteger(privKey.getPrimeP(), InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(privKey.getPrimeQ(), InsecureSecretKeyAccess.get()))
        .setPrivateExponent(
            SecretBigInteger.fromBigInteger(
                privKey.getPrivateExponent(), InsecureSecretKeyAccess.get()))
        .setPrimeExponents(
            SecretBigInteger.fromBigInteger(
                privKey.getPrimeExponentP(), InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(
                privKey.getPrimeExponentQ(), InsecureSecretKeyAccess.get()))
        .setCrtCoefficient(
            SecretBigInteger.fromBigInteger(
                privKey.getCrtCoefficient(), InsecureSecretKeyAccess.get()))
        .build();
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<JwtRsaSsaPssParameters> KEY_CREATOR =
      JwtRsaSsaPssSignKeyManager::createKey;

  @AccessesPartialKey
  private static RsaSsaPssPrivateKey toRsaSsaPssPrivateKey(
      com.google.crypto.tink.jwt.JwtRsaSsaPssPrivateKey privateKey)
      throws GeneralSecurityException {
    return RsaSsaPssPrivateKey.builder()
        .setPublicKey(JwtRsaSsaPssVerifyKeyManager.toRsaSsaPssPublicKey(privateKey.getPublicKey()))
        .setPrimes(privateKey.getPrimeP(), privateKey.getPrimeQ())
        .setPrivateExponent(privateKey.getPrivateExponent())
        .setPrimeExponents(privateKey.getPrimeExponentP(), privateKey.getPrimeExponentQ())
        .setCrtCoefficient(privateKey.getCrtCoefficient())
        .build();
  }

  @SuppressWarnings("Immutable") // RsaSsaPssVerifyJce.create returns an immutable verifier.
  static JwtPublicKeySign createFullPrimitive(
      com.google.crypto.tink.jwt.JwtRsaSsaPssPrivateKey privateKey)
      throws GeneralSecurityException {
    RsaSsaPssPrivateKey rsaSsaPssPrivateKey = toRsaSsaPssPrivateKey(privateKey);
    final PublicKeySign signer = RsaSsaPssSignJce.create(rsaSsaPssPrivateKey);
    String algorithm = privateKey.getParameters().getAlgorithm().getStandardName();
    return new JwtPublicKeySign() {
      @Override
      public String signAndEncode(RawJwt rawJwt) throws GeneralSecurityException {
        String unsignedCompact =
            JwtFormat.createUnsignedCompact(algorithm, privateKey.getPublicKey().getKid(), rawJwt);
        return JwtFormat.createSignedCompact(
            unsignedCompact, signer.sign(unsignedCompact.getBytes(US_ASCII)));
      }
    };
  }

  private static final PrimitiveConstructor<
          com.google.crypto.tink.jwt.JwtRsaSsaPssPrivateKey, JwtPublicKeySign>
      PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtRsaSsaPssSignKeyManager::createFullPrimitive,
              com.google.crypto.tink.jwt.JwtRsaSsaPssPrivateKey.class,
              JwtPublicKeySign.class);

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey";
  }

  /**
   * List of default templates to generate tokens with algorithms "PS256", "PS384" or "PS512". Use
   * the template with the "_RAW" suffix if you want to generate tokens without a "kid" header.
   */
  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put(
            "JWT_PS256_2048_F4_RAW",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_PS256_2048_F4",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
        result.put(
            "JWT_PS256_3072_F4_RAW",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_PS256_3072_F4",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
        result.put(
            "JWT_PS384_3072_F4_RAW",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_PS384_3072_F4",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
        result.put(
            "JWT_PS512_4096_F4_RAW",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_PS512_4096_F4",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
        return Collections.unmodifiableMap(result);
  }

  /**
   * Registers the {@link RsaSsaPssSignKeyManager} and the {@link RsaSsaPssVerifyKeyManager} with
   * the registry, so that the the RsaSsaPss-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    JwtRsaSsaPssProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(JwtRsaSsaPssVerifyKeyManager.PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveConstructor(PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, JwtRsaSsaPssParameters.class);
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyPrivateKeyManager, newKeyAllowed);
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyPublicKeyManager, false);
  }

  private JwtRsaSsaPssSignKeyManager() {}
}
