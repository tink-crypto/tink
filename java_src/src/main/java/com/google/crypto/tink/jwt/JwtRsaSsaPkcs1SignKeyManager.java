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
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
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
 * This key manager generates new {@code JwtRsaSsaPkcs1PrivateKey} keys and produces new instances
 * of {@code JwtPublicKeySign}.
 */
public final class JwtRsaSsaPkcs1SignKeyManager {
  private static final PrivateKeyManager<Void> legacyPrivateKeyManager =
      LegacyKeyManagerImpl.createPrivateKeyManager(
          getKeyType(), Void.class, com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey.parser());

  private static final KeyManager<Void> legacyPublicKeyManager =
      LegacyKeyManagerImpl.create(
          JwtRsaSsaPkcs1VerifyKeyManager.getKeyType(),
          Void.class,
          KeyMaterialType.ASYMMETRIC_PUBLIC,
          com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.parser());

  @AccessesPartialKey
  static RsaSsaPkcs1PrivateKey toRsaSsaPkcs1PrivateKey(JwtRsaSsaPkcs1PrivateKey privateKey)
      throws GeneralSecurityException {
    RsaSsaPkcs1PublicKey publicKey =
        JwtRsaSsaPkcs1VerifyKeyManager.toRsaSsaPkcs1PublicKey(privateKey.getPublicKey());
    return RsaSsaPkcs1PrivateKey.builder()
        .setPublicKey(publicKey)
        .setPrimes(privateKey.getPrimeP(), privateKey.getPrimeQ())
        .setPrivateExponent(privateKey.getPrivateExponent())
        .setPrimeExponents(privateKey.getPrimeExponentP(), privateKey.getPrimeExponentQ())
        .setCrtCoefficient(privateKey.getCrtCoefficient())
        .build();
  }

  @SuppressWarnings("Immutable") // RsaSsaPkcs1SignJce.create returns an immutable signer.
  static JwtPublicKeySign createFullPrimitive(
      com.google.crypto.tink.jwt.JwtRsaSsaPkcs1PrivateKey privateKey)
      throws GeneralSecurityException {
    RsaSsaPkcs1PrivateKey rsaSsaPkcs1PrivateKey = toRsaSsaPkcs1PrivateKey(privateKey);
    final PublicKeySign signer = RsaSsaPkcs1SignJce.create(rsaSsaPkcs1PrivateKey);
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
          com.google.crypto.tink.jwt.JwtRsaSsaPkcs1PrivateKey, JwtPublicKeySign>
      PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtRsaSsaPkcs1SignKeyManager::createFullPrimitive,
              com.google.crypto.tink.jwt.JwtRsaSsaPkcs1PrivateKey.class,
              JwtPublicKeySign.class);

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey";
  }

  @AccessesPartialKey
  private static JwtRsaSsaPkcs1PrivateKey createKey(
      JwtRsaSsaPkcs1Parameters parameters, @Nullable Integer idRequirement)
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

    // Creates JwtRsaSsaPkcs1PublicKey.
    JwtRsaSsaPkcs1PublicKey.Builder jwtRsaSsaPkcs1PublicKeyBuilder =
        JwtRsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(pubKey.getModulus());
    if (idRequirement != null) {
      jwtRsaSsaPkcs1PublicKeyBuilder.setIdRequirement(idRequirement);
    }
    JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1PublicKey = jwtRsaSsaPkcs1PublicKeyBuilder.build();

    // Creates RsaSsaPkcs1PrivateKey.
    return JwtRsaSsaPkcs1PrivateKey.builder()
        .setPublicKey(jwtRsaSsaPkcs1PublicKey)
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
  private static final MutableKeyCreationRegistry.KeyCreator<JwtRsaSsaPkcs1Parameters> KEY_CREATOR =
      JwtRsaSsaPkcs1SignKeyManager::createKey;

  /**
   * List of default templates to generate tokens with algorithms "RS256", "RS384" or "RS512". Use
   * the template with the "_RAW" suffix if you want to generate tokens without a "kid" header.
   */
  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();
    result.put(
        "JWT_RS256_2048_F4_RAW",
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .build());
    result.put(
        "JWT_RS256_2048_F4",
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build());
    result.put(
        "JWT_RS256_3072_F4_RAW",
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .build());
    result.put(
        "JWT_RS256_3072_F4",
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build());
    result.put(
        "JWT_RS384_3072_F4_RAW",
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .build());
    result.put(
        "JWT_RS384_3072_F4",
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build());
    result.put(
        "JWT_RS512_4096_F4_RAW",
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .build());
    result.put(
        "JWT_RS512_4096_F4",
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build());
    return Collections.unmodifiableMap(result);
  }

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  /**
   * Registers the {@link RsaSsapkcs1SignKeyManager} and the {@link RsaSsapkcs1VerifyKeyManager}
   * with the registry, so that the the RsaSsapkcs1-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use RSA SSA PKCS1 in FIPS-mode, as BoringCrypto module is not available.");
    }
    JwtRsaSsaPkcs1ProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(JwtRsaSsaPkcs1VerifyKeyManager.PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveConstructor(PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, JwtRsaSsaPkcs1Parameters.class);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyPrivateKeyManager, FIPS, newKeyAllowed);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyPublicKeyManager, FIPS, false);
  }

  private JwtRsaSsaPkcs1SignKeyManager() {}
}
